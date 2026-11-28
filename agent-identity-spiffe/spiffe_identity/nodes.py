"""Device (node) attestation: enrolled device keys, one-time challenges, and workload evidence.

See ATTESTATION-MACOS.md for the design and the wire protocol (section 11).

Trust model, briefly
--------------------
* A device ("node") enrolls by submitting a P-256 public key. On a Mac the
  private key lives in the Secure Enclave and was created behind a Touch ID
  prompt. The server can't verify either fact (no Apple attestation without
  MDM), so every node starts **pending** and only a person can approve it.
* An approved node asks for a single-use nonce, then sends a request signed
  with its device key: the nonce, the workload evidence its agent collected
  (code signature facts read from the kernel and macOS), the SPIFFE ID wanted
  and a CSR. The server checks the signature, the nonce, and that a
  registration entry's selectors are all present in the evidence.
* Confidence comes from the *method* (what was proven), looked up in the
  rubric in the locked tool policy. Unlisted methods are Low.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class NodeError(ValueError):
    """A request about a node is invalid. The message is safe to return to the caller."""


STATUSES = ("pending", "approved", "blocked", "revoked")
NONCE_TTL_SECONDS = 60

# ---- canonical signing --------------------------------------------------------------

def canonical_json(obj) -> bytes:
    """The exact bytes that get signed: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def short_code(node_id: str) -> str:
    """What a person compares between the Mac and the portal, e.g. '3F9A-21C7'."""
    return f"{node_id[:4]}-{node_id[4:8]}".upper()


def load_public_key(pem: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError) as e:
        raise NodeError(f"public_key must be a PEM SubjectPublicKeyInfo: {e}") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise NodeError("public_key must be an EC P-256 key (what the Secure Enclave produces)")
    return key


def verify_signature(public_key: ec.EllipticCurvePublicKey, payload: dict, signature_b64: str) -> None:
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as e:
        raise NodeError("signature must be base64 (DER-encoded ECDSA)") from e
    try:
        public_key.verify(sig, canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise NodeError("signature does not verify against the enrolled device key") from e


# ---- workload evidence --------------------------------------------------------------

_SIGNING_ID = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
_TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
_CDHASH = re.compile(r"^[0-9a-f]{40}$")
_FACT_KEYS = {"hostname", "macos_version", "model", "touch_id_confirmed", "software_key_test_only"}


def _code_identity(d, where: str, require_cdhash: bool) -> dict:
    if not isinstance(d, dict):
        raise NodeError(f"{where} must be an object")
    out = {}
    sid = d.get("signing_id")
    if not isinstance(sid, str) or not _SIGNING_ID.match(sid):
        raise NodeError(f"{where}.signing_id is required (letters, digits, . _ -)")
    out["signing_id"] = sid
    team = d.get("team_id")
    if team is not None:
        if not isinstance(team, str) or not _TEAM_ID.match(team):
            raise NodeError(f"{where}.team_id must be a 10-character Apple Team ID or null")
        out["team_id"] = team
    cd = d.get("cdhash")
    if cd is not None or require_cdhash:
        if not isinstance(cd, str) or not _CDHASH.match(cd):
            raise NodeError(f"{where}.cdhash must be 40 lowercase hex characters")
        out["cdhash"] = cd
    return out


def validate_evidence(ev) -> dict:
    """Validate workload evidence from the node agent. Unknown fields are rejected."""
    if not isinstance(ev, dict):
        raise NodeError("workload must be an object")
    unknown = set(ev) - {"signing_id", "team_id", "cdhash", "hardened_runtime", "path", "parent"}
    if unknown:
        raise NodeError(f"workload has unknown field(s): {sorted(unknown)}")
    out = _code_identity(ev, "workload", require_cdhash=True)
    hr = ev.get("hardened_runtime")
    if not isinstance(hr, bool):
        raise NodeError("workload.hardened_runtime must be true or false")
    out["hardened_runtime"] = hr
    path = ev.get("path")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
        raise NodeError("workload.path must be an absolute path")
    out["path"] = path
    if ev.get("parent") is not None:
        out["parent"] = _code_identity(ev["parent"], "workload.parent", require_cdhash=False)
    return out


def evidence_selectors(node_id: str, ev: dict) -> list[str]:
    """Selectors the server derives itself from verified evidence (never taken from the caller)."""
    sel = [f"node:id:{node_id}", f"macos:signing_id:{ev['signing_id']}", f"macos:cdhash:{ev['cdhash']}",
           f"macos:hardened_runtime:{'true' if ev['hardened_runtime'] else 'false'}"]
    if "team_id" in ev:
        sel.append(f"macos:team_id:{ev['team_id']}")
    p = ev.get("parent")
    if p:
        sel.append(f"macos:parent_signing_id:{p['signing_id']}")
        if "team_id" in p:
            sel.append(f"macos:parent_team_id:{p['team_id']}")
        if "cdhash" in p:
            sel.append(f"macos:parent_cdhash:{p['cdhash']}")
    return sorted(sel)


# ---- method and confidence ----------------------------------------------------------

# Strongest first. The method describes what the selectors require to be proven.
METHODS = (
    "macos-se-node+codesign",   # enrolled device key + this program's code signature (own client via agent)
    "macos-codesign-parent",    # enrolled device + our process, launched by a vendor-signed app seen from outside
    "macos-se-node",            # enrolled device key only; program not pinned
    "k8s-api",                  # namespace / service account from the Kubernetes API
    "docker-image",             # image content hash from the local Docker daemon
    "process-path",             # user id + executable path from the OS
    "process-name",             # process name only
    "a2a-card",                 # self-described agent card
    "mcp-config",               # self-described MCP config entry
    "network-addr",             # IP:port
    "unknown",
)
CONFIDENCE_LEVELS = ("high", "medium", "low")


def attestation_method(selectors: list[str]) -> str:
    s = set(selectors)
    has = lambda prefix: any(x.startswith(prefix) for x in s)  # noqa: E731
    if has("node:id:"):
        if has("macos:parent_signing_id:") or has("macos:parent_team_id:"):
            return "macos-codesign-parent"
        if has("macos:cdhash:") and "macos:hardened_runtime:true" in s:
            return "macos-se-node+codesign"
        return "macos-se-node"
    # An interpreter's path (python, node, ...) identifies the interpreter, not the app it runs.
    paths = [x.split(":", 2)[2] for x in s if x.startswith("unix:path:")]
    if paths and all(_is_interpreter(pth) for pth in paths):
        s = {x for x in s if not x.startswith("unix:path:")}
    for prefix, method in (("k8s:sa:", "k8s-api"), ("docker:image_id:", "docker-image"),
                           ("unix:path:", "process-path"), ("unix:comm:", "process-name"),
                           ("ai:a2a-card:", "a2a-card"), ("ai:mcp-config:", "mcp-config"),
                           ("net:addr:", "network-addr")):
        if has(prefix):
            return method
    return "unknown"


_INTERPRETERS = re.compile(r"^(python[0-9.]*|Python|node|nodejs|deno|bun|ruby|perl[0-9.]*|php[0-9.]*|java|bash|zsh|sh|osascript)$")


def _is_interpreter(path: str) -> bool:
    return bool(_INTERPRETERS.match(os.path.basename(path)))


def confidence(method: str, rubric: dict[str, str]) -> str:
    """Look the method up in the policy's rubric. Anything not listed is low."""
    return rubric.get(method, "low")


# ---- registry -----------------------------------------------------------------------

@dataclass
class Node:
    id: str
    public_key_pem: str
    status: str
    short_code: str
    facts: dict                  # reported by the device, not proven
    enrolled_at: str
    decided_by: str = ""
    decided_at: str = ""


@dataclass
class PendingBuild:
    """A new build of an already-approved program asked for an identity (decision D4)."""
    id: str
    node_id: str
    spiffe_id: str
    signing_id: str
    old_cdhash: str
    new_cdhash: str
    base_entry_id: str
    first_seen: str
    status: str = "pending"       # pending | approved | rejected
    decided_by: str = ""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class NodeRegistry:
    """Enrolled devices, pending builds and live nonces. JSON-file backed (``path=None`` = memory)."""

    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.nodes: dict[str, Node] = {}
        self.builds: dict[str, PendingBuild] = {}
        self._nonces: dict[str, tuple[str, float]] = {}   # nonce -> (node_id, expiry)
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text())
            self.nodes = {n["id"]: Node(**n) for n in data.get("nodes", [])}
            self.builds = {b["id"]: PendingBuild(**b) for b in data.get("builds", [])}

    # -- enrollment and decisions

    def enroll(self, public_key_pem: str, facts, max_pending: int) -> tuple[Node, bool]:
        key = load_public_key(public_key_pem)
        if not isinstance(facts, dict):
            raise NodeError("facts must be an object")
        unknown = set(facts) - _FACT_KEYS
        if unknown:
            raise NodeError(f"facts has unknown field(s): {sorted(unknown)}; allowed: {sorted(_FACT_KEYS)}")
        clean = {}
        for k, v in facts.items():
            if k in ("touch_id_confirmed", "software_key_test_only"):
                if not isinstance(v, bool):
                    raise NodeError(f"facts.{k} must be true or false")
            elif not isinstance(v, str) or len(v) > 200:
                raise NodeError(f"facts.{k} must be a short string")
            clean[k] = v
        nid = fingerprint(key)
        with self._lock:
            if nid in self.nodes:
                return self.nodes[nid], False
            if sum(1 for n in self.nodes.values() if n.status == "pending") >= max_pending:
                raise NodeError(f"too many pending enrollments (max {max_pending}); approve or block some first")
            pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            node = Node(id=nid, public_key_pem=pem, status="pending", short_code=short_code(nid),
                        facts=clean, enrolled_at=_now())
            self.nodes[nid] = node
            self._save()
        return node, True

    def decide(self, node_id: str, action: str, who: str) -> Node:
        transitions = {"approve": ("pending", "approved"), "block": ("pending", "blocked"),
                       "revoke": ("approved", "revoked")}
        if action not in transitions:
            raise NodeError(f"unknown action {action!r}")
        if not who:
            raise NodeError("decided_by is required")
        frm, to = transitions[action]
        with self._lock:
            node = self.nodes.get(node_id)
            if node is None:
                raise NodeError("unknown node")
            if node.status != frm:
                raise NodeError(f"can't {action} a node that is {node.status}")
            node.status, node.decided_by, node.decided_at = to, who, _now()
            if to == "revoked":
                self._nonces = {k: v for k, v in self._nonces.items() if v[0] != node_id}
            self._save()
        return node

    def list(self) -> list[Node]:
        with self._lock:
            return sorted(self.nodes.values(), key=lambda n: n.enrolled_at)

    def approved_key(self, node_id: str) -> ec.EllipticCurvePublicKey:
        with self._lock:
            node = self.nodes.get(node_id)
        if node is None:
            raise NodeError("unknown node")
        if node.status != "approved":
            raise NodeError(f"node is {node.status}, not approved")
        return load_public_key(node.public_key_pem)

    # -- nonces

    def challenge(self, node_id: str) -> tuple[str, float]:
        self.approved_key(node_id)
        nonce = secrets.token_urlsafe(32)
        expiry = time.time() + NONCE_TTL_SECONDS
        with self._lock:
            now = time.time()
            self._nonces = {k: v for k, v in self._nonces.items() if v[1] > now}
            self._nonces[nonce] = (node_id, expiry)
        return nonce, expiry

    def consume_nonce(self, nonce: str, node_id: str) -> None:
        with self._lock:
            entry = self._nonces.pop(nonce, None)   # single use: gone even if the rest fails
        if entry is None:
            raise NodeError("unknown or already-used nonce")
        if entry[0] != node_id:
            raise NodeError("nonce was issued to a different node")
        if entry[1] < time.time():
            raise NodeError("nonce expired")

    # -- pending builds (D4)

    def record_build(self, node_id: str, spiffe_id: str, signing_id: str, old_cdhash: str,
                     new_cdhash: str, base_entry_id: str) -> PendingBuild:
        with self._lock:
            for b in self.builds.values():
                if (b.node_id, b.spiffe_id, b.new_cdhash) == (node_id, spiffe_id, new_cdhash) and b.status == "pending":
                    return b
            b = PendingBuild(id=secrets.token_hex(8), node_id=node_id, spiffe_id=spiffe_id, signing_id=signing_id,
                             old_cdhash=old_cdhash, new_cdhash=new_cdhash, base_entry_id=base_entry_id,
                             first_seen=_now())
            self.builds[b.id] = b
            self._save()
        return b

    def decide_build(self, build_id: str, action: str, who: str) -> PendingBuild:
        if action not in ("approve", "reject"):
            raise NodeError(f"unknown action {action!r}")
        if not who:
            raise NodeError("decided_by is required")
        with self._lock:
            b = self.builds.get(build_id)
            if b is None:
                raise NodeError("unknown build")
            if b.status != "pending":
                raise NodeError(f"build is already {b.status}")
            b.status = "approved" if action == "approve" else "rejected"
            b.decided_by = who
            self._save()
        return b

    def pending_builds(self) -> list[PendingBuild]:
        with self._lock:
            return [b for b in self.builds.values() if b.status == "pending"]

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        data = {"nodes": [asdict(n) for n in self.nodes.values()], "builds": [asdict(b) for b in self.builds.values()]}
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
