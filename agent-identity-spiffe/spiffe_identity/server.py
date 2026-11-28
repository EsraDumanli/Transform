"""The learning SPIFFE server: a CA plus a small HTTPS admin API.

Endpoints
---------
Public (no token):
  GET  /healthz
  GET  /v1/bundle          X.509 trust bundle (PEM)
  GET  /v1/bundle/jwks     JWT trust bundle (JWKS)
Admin (``Authorization: Bearer <token>``):
  GET    /v1/entries
  POST   /v1/entries               {spiffe_id, selectors, source, assigned_by, approved_by, rationale}
  DELETE /v1/entries/<id>
  POST   /v1/svid/x509             {spiffe_id, csr}       -> {svid, bundle}
  POST   /v1/svid/jwt              {spiffe_id, audience}  -> {token}

Important difference from SPIRE: there is no workload attestation. SPIRE's
agent proves *which process* is asking before it hands over an SVID. Here the
holder of the admin token can mint an SVID for any *registered* ID. That makes
the token the root of trust, so keep it secret and keep the server on a
network you control. See README "What this is not".

Run:  SPIFFE_ADMIN_TOKEN=... python -m spiffe_identity.server --config config.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
import logging
import os
import ssl
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import config as config_mod
from . import spiffeid
from .ca import CAError, CertificateAuthority
from .nodes import (NodeError, NodeRegistry, attestation_method, confidence, evidence_selectors, short_code,
                    validate_evidence, verify_signature)
from .registry import Entry, Registry, RegistryError
from .toolpolicy import ToolDenied, ToolGate, ToolPolicyError, gate_from_config
from .trace import TraceError

log = logging.getLogger("spiffe-server")
MAX_BODY = 64 * 1024
MIN_TOKEN_LEN = 32


class App:
    """Request handling logic, independent of the HTTP plumbing (easy to test)."""

    def __init__(self, ca: CertificateAuthority, registry: Registry, admin_token: str,
                 x509_ttl: dt.timedelta, jwt_ttl: dt.timedelta, gate: ToolGate,
                 nodes: NodeRegistry | None = None, attested_ttl: dt.timedelta | None = None):
        if len(admin_token) < MIN_TOKEN_LEN:
            raise ValueError(f"admin token must be at least {MIN_TOKEN_LEN} characters")
        self.ca, self.registry, self.token = ca, registry, admin_token
        self.x509_ttl, self.jwt_ttl = x509_ttl, jwt_ttl
        self.gate = gate
        self.nodes = nodes if nodes is not None else NodeRegistry(None)
        self.attested_ttl = attested_ttl

    def authorized(self, header: str | None) -> bool:
        if not header or not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].encode(), self.token.encode())

    def handle(self, method: str, path: str, auth: str | None, body: bytes,
               trace_id: str | None = None) -> tuple[int, str, bytes]:
        """Return (status, content_type, body).

        Public, read-only endpoints (health and trust bundle) are not tools and
        are not traced. Every admin request is one trace run (joined to the
        caller's trace when it sends a valid X-Trace-Id), and every action in
        it is checked against the server's own copy of the tool policy.
        """
        if method == "GET" and path == "/healthz":
            return _json(200, {"ok": True, "trust_domain": self.ca.trust_domain})
        if method == "GET" and path == "/v1/bundle":
            return 200, "application/x-pem-file", self.ca.bundle_pem()
        if method == "GET" and path == "/v1/bundle/jwks":
            return _json(200, self.ca.jwks())
        if not path.startswith("/v1/"):
            return _json(404, {"error": "not found"})
        try:
            with self.gate.run("server.request", trace_id=trace_id, method=method, path=path):
                if path.startswith("/v1/node/"):   # device-authenticated (signature), no admin token
                    return self._node(method, path, body)
                return self._admin(method, path, auth, body)
        except TraceError as e:
            log.error("refusing request, trace not writable: %s", e)
            return _json(503, {"error": "server cannot write its trace file; refusing to act"})

    def _admin(self, method: str, path: str, auth: str | None, body: bytes) -> tuple[int, str, bytes]:
        if not self.authorized(auth):
            self.gate.writer.emit("action.decision", tool="server.auth", decision="deny",
                                  reason="missing or invalid admin token", args={"method": method, "path": path})
            return _json(401, {"error": "missing or invalid admin token"})
        try:
            req = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return _json(400, {"error": "body must be JSON"})
        if not isinstance(req, dict):
            return _json(400, {"error": "body must be a JSON object"})

        try:
            if method == "GET" and path == "/v1/entries":
                with self.gate.action("server.entries.list") as summary:
                    entries = [e.__dict__ for e in self.registry.list()]
                    summary["entries"] = len(entries)
                return _json(200, entries)
            if method == "POST" and path == "/v1/entries":
                sid_text = str(req.get("spiffe_id", ""))
                with self.gate.action("server.entries.create", spiffe_id=sid_text,
                                      approved_by=str(req.get("approved_by", ""))) as summary:
                    selectors = list(req.get("selectors") or [])
                    entry, created = self.registry.create(Entry(
                        spiffe_id=sid_text, selectors=selectors,
                        source=str(req.get("source", "")), assigned_by=str(req.get("assigned_by", "")),
                        approved_by=str(req.get("approved_by", "")), rationale=str(req.get("rationale", "")),
                        extra={"attestation": self._attestation(selectors)},
                    ))
                    summary.update({"entry_id": entry.id, "created": created})
                log.info("entry %s %s -> %s (approved by %s)", "created" if created else "exists",
                         entry.id, entry.spiffe_id, entry.approved_by)
                return _json(201 if created else 200, {**entry.__dict__, "created": created})
            if method == "DELETE" and path.startswith("/v1/entries/"):
                entry_id = path.rsplit("/", 1)[1]
                with self.gate.action("server.entries.delete", entry_id=entry_id) as summary:
                    ok = self.registry.delete(entry_id)
                    summary["deleted"] = ok
                return _json(200 if ok else 404, {"deleted": ok})
            if method == "POST" and path == "/v1/svid/x509":
                sid_text = str(req.get("spiffe_id", ""))
                with self.gate.action("server.svid.x509", spiffe_id=sid_text):
                    sid = self._registered(req)
                    cert = self.ca.issue_x509_svid(str(req.get("csr", "")).encode(), sid, self.x509_ttl)
                log.info("issued X.509-SVID for %s", sid)
                return _json(200, {"svid": cert.decode(), "bundle": self.ca.bundle_pem().decode()})
            if method == "POST" and path == "/v1/svid/jwt":
                aud = req.get("audience")
                if not isinstance(aud, list) or not all(isinstance(a, str) and a for a in aud):
                    return _json(400, {"error": "audience must be a non-empty list of strings"})
                sid_text = str(req.get("spiffe_id", ""))
                with self.gate.action("server.svid.jwt", spiffe_id=sid_text, audience=aud):
                    sid = self._registered(req)
                    token = self.ca.mint_jwt_svid(sid, aud, self.jwt_ttl)
                log.info("issued JWT-SVID for %s aud=%s", sid, aud)
                return _json(200, {"token": token})
            if path.startswith("/v1/nodes") or path.startswith("/v1/builds"):
                return self._admin_nodes(method, path, req)
        except ToolDenied as e:
            return _json(403, {"error": str(e)})
        except NodeError as e:
            return _json(400, {"error": str(e)})
        except _NotRegistered as e:
            return _json(403, {"error": str(e)})
        except (CAError, RegistryError, spiffeid.SpiffeIDError) as e:
            return _json(400, {"error": str(e)})
        return _json(404, {"error": "not found"})

    # ---- attestation helpers ------------------------------------------------------

    def _attestation(self, selectors: list[str]) -> dict:
        method = attestation_method(selectors)
        return {"method": method, "confidence": confidence(method, self.gate.policy.rubric or {})}

    def _admin_nodes(self, method: str, path: str, req: dict) -> tuple[int, str, bytes]:
        parts = path.strip("/").split("/")   # v1, nodes|builds, [id], [action]
        if method == "POST" and parts == ["v1", "nodes", "enroll"]:
            pending = sum(1 for n in self.nodes.list() if n.status == "pending")
            with self.gate.action("server.nodes.enroll", pending=pending) as summary:
                node, created = self.nodes.enroll(str(req.get("public_key", "")), req.get("facts", {}),
                                                  self.gate.policy.tools["server.nodes.enroll"]["max_pending"])
                summary.update({"node_id": node.id, "short_code": node.short_code, "created": created,
                                "status": node.status})
            log.info("node enrollment %s: %s (%s)", "received" if created else "repeated", node.short_code, node.status)
            return _json(201 if created else 200, _node_view(node))
        if method == "GET" and parts == ["v1", "nodes"]:
            with self.gate.action("server.nodes.list") as summary:
                nodes = [_node_view(n) for n in self.nodes.list()]
                summary["nodes"] = len(nodes)
            return _json(200, nodes)
        if method == "GET" and parts == ["v1", "builds"]:
            with self.gate.action("server.nodes.list") as summary:
                builds = [b.__dict__ for b in self.nodes.pending_builds()]
                summary["pending_builds"] = len(builds)
            return _json(200, builds)
        if method == "POST" and len(parts) == 4 and parts[1] == "nodes":
            who = str(req.get("decided_by", ""))
            with self.gate.action("server.nodes.manage", node_id=parts[2], action=parts[3], decided_by=who):
                node = self.nodes.decide(parts[2], parts[3], who)
            log.info("node %s %s by %s", node.short_code, node.status, who)
            return _json(200, _node_view(node))
        if method == "POST" and len(parts) == 4 and parts[1] == "builds":
            who = str(req.get("decided_by", ""))
            with self.gate.action("server.nodes.manage", build_id=parts[2], action=parts[3], decided_by=who):
                build = self.nodes.builds.get(parts[2])
                if build is None:
                    raise NodeError("unknown build")
                entry = None
                if parts[3] == "approve":
                    base = next((e for e in self.registry.list() if e.id == build.base_entry_id), None)
                    if base is None:
                        raise NodeError("the entry this build replaces no longer exists")
                    selectors = [x for x in base.selectors if not x.startswith("macos:cdhash:")]
                    selectors.append(f"macos:cdhash:{build.new_cdhash}")
                    with self.gate.action("server.entries.create", spiffe_id=build.spiffe_id, approved_by=who):
                        entry, _ = self.registry.create(Entry(
                            spiffe_id=build.spiffe_id, selectors=selectors, source="node-agent",
                            assigned_by=f"build-approval:{build.id}", approved_by=who,
                            rationale=f"new build of {build.signing_id}: cdhash {build.old_cdhash[:12]}… → {build.new_cdhash[:12]}…",
                            extra={"attestation": self._attestation(selectors)},
                        ))
                build = self.nodes.decide_build(parts[2], parts[3], who)
            return _json(200, {"build": build.__dict__, "entry": entry.__dict__ if entry else None})
        return _json(404, {"error": "not found"})

    def _node(self, method: str, path: str, body: bytes) -> tuple[int, str, bytes]:
        """Device-authenticated endpoints. Failures are traced as denials, without key material."""
        try:
            req = json.loads(body) if body else {}
            if not isinstance(req, dict):
                raise ValueError
        except ValueError:
            return _json(400, {"error": "body must be a JSON object"})
        try:
            if method == "POST" and path == "/v1/node/challenge":
                node_id = str(req.get("node_id", ""))
                with self.gate.action("server.nodes.challenge", node_id=node_id):
                    nonce, expiry = self.nodes.challenge(node_id)
                return _json(200, {"nonce": nonce, "expires_at": int(expiry)})
            if method == "POST" and path == "/v1/node/svid":
                return self._attested_svid(req)
        except ToolDenied as e:
            return _json(403, {"error": str(e)})
        except NodeError as e:
            self.gate.writer.emit("action.decision", tool="server.node.auth", decision="deny", reason=str(e),
                                  args={"path": path, "node_id": str((req.get("request") or req).get("node_id", ""))[:64]})
            return _json(403, {"error": str(e)})
        except (CAError, spiffeid.SpiffeIDError) as e:
            return _json(400, {"error": str(e)})
        return _json(404, {"error": "not found"})

    def _attested_svid(self, body: dict) -> tuple[int, str, bytes]:
        if self.attested_ttl is None:
            raise NodeError("attested issuance isn't configured on this server")
        r, sig = body.get("request"), body.get("signature")
        if not isinstance(r, dict) or not isinstance(sig, str):
            raise NodeError("expected {request: {...}, signature: <base64>}")
        unknown = set(r) - {"node_id", "nonce", "spiffe_id", "csr", "workload"}
        if unknown:
            raise NodeError(f"request has unknown field(s): {sorted(unknown)}")
        node_id = str(r.get("node_id", ""))
        key = self.nodes.approved_key(node_id)              # unknown / pending / blocked / revoked -> denied
        verify_signature(key, r, sig)                        # signed by the enrolled device key
        self.nodes.consume_nonce(str(r.get("nonce", "")), node_id)   # fresh, single use, this node's
        ev = validate_evidence(r.get("workload"))
        evidence = set(evidence_selectors(node_id, ev))
        sid = spiffeid.parse(str(r.get("spiffe_id", "")))
        node_sel = f"node:id:{node_id}"
        candidates = [e for e in self.registry.list() if e.spiffe_id == str(sid) and node_sel in e.selectors]
        match = next((e for e in candidates if set(e.selectors) <= evidence), None)
        if match is None:
            # A new build of a program that's already approved on this node (decision D4)?
            for e in candidates:
                rest = {x for x in e.selectors if not x.startswith("macos:cdhash:")}
                old = next((x.split(":", 2)[2] for x in e.selectors if x.startswith("macos:cdhash:")), "")
                if old and rest <= evidence and f"macos:signing_id:{ev['signing_id']}" in rest:
                    b = self.nodes.record_build(node_id, str(sid), ev["signing_id"], old, ev["cdhash"], e.id)
                    self.gate.writer.emit("action.decision", tool="server.svid.attested", decision="deny",
                                          reason="new build awaiting approval",
                                          args={"spiffe_id": str(sid), "node_id": node_id, "build_id": b.id,
                                                "signing_id": ev["signing_id"], "new_cdhash": ev["cdhash"]})
                    return _json(403, {"error": "this is a new build of an approved program; approve it in the portal first",
                                       "build_id": b.id})
            raise NodeError("no registration entry matches this workload's evidence on this node")
        att = self._attestation(match.selectors)
        ttl_min = round(self.attested_ttl.total_seconds() / 60)
        with self.gate.action("server.svid.attested", spiffe_id=str(sid), ttl_minutes=ttl_min,
                              hardened_runtime=ev["hardened_runtime"], node_id=node_id,
                              signing_id=ev["signing_id"], method=att["method"], confidence=att["confidence"]) as summary:
            cert = self.ca.issue_x509_svid(str(r.get("csr", "")).encode(), sid, self.attested_ttl)
            summary.update({"entry_id": match.id, "ttl_minutes": ttl_min})
        log.info("attested X.509-SVID for %s (node %s, %s, %s)", sid, short_code(node_id), att["method"], att["confidence"])
        return _json(200, {"svid": cert.decode(), "bundle": self.ca.bundle_pem().decode(),
                           "ttl_minutes": ttl_min, "attestation": att})

    def _registered(self, req: dict) -> spiffeid.SpiffeID:
        sid = spiffeid.parse(str(req.get("spiffe_id", "")))
        if not self.registry.has_spiffe_id(str(sid)):
            raise _NotRegistered(f"{sid} has no registration entry; register and approve it first")
        return sid


def _node_view(n) -> dict:
    return {"id": n.id, "short_code": n.short_code, "status": n.status, "facts": n.facts,
            "enrolled_at": n.enrolled_at, "decided_by": n.decided_by, "decided_at": n.decided_at}


class _NotRegistered(Exception):
    pass


def _json(status: int, obj) -> tuple[int, str, bytes]:
    return status, "application/json", json.dumps(obj, indent=2).encode()


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "agent-identity-spiffe"

        def _dispatch(self, method: str):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                status, ctype, body = _json(413, {"error": "body too large"})
            else:
                raw = self.rfile.read(length) if length else b""
                status, ctype, body = app.handle(method, self.path.split("?", 1)[0], self.headers.get("Authorization"), raw,
                                                 trace_id=self.headers.get("X-Trace-Id"))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_DELETE(self):
            self._dispatch("DELETE")

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

    return Handler


def build(cfg: dict, admin_token: str, gate: ToolGate | None = None) -> tuple[ThreadingHTTPServer, App]:
    td = cfg["trust_domain"]
    s = config_mod.section(cfg, "server")
    req = config_mod.require
    data_dir = config_mod.resolve_path(cfg, req(s, "data_dir", str, "server"))
    host = req(s, "listen_host", str, "server")
    port = req(s, "listen_port", int, "server")
    dns_names = s.get("tls_dns_names") or []
    ips = s.get("tls_ip_addresses") or []
    if not dns_names and not ips:
        raise config_mod.ConfigError("server.tls_dns_names and/or server.tls_ip_addresses is required (names clients use to reach the server)")
    ca_ttl = dt.timedelta(hours=req(s, "ca_ttl_hours", (int, float), "server"))
    x509_ttl = dt.timedelta(minutes=req(s, "x509_svid_ttl_minutes", (int, float), "server"))
    jwt_ttl = dt.timedelta(minutes=req(s, "jwt_svid_ttl_minutes", (int, float), "server"))

    ca, created = CertificateAuthority.load_or_create(data_dir, td, ca_ttl)
    log.info("%s CA for trust domain %s in %s", "created" if created else "loaded", td, data_dir)
    registry = Registry(Path(data_dir) / "entries.json", td)
    gate = gate or gate_from_config(cfg, "server")
    attested_ttl = None
    if "server.svid.attested" in gate.policy.tools:
        minutes = req(s, "attested_svid_ttl_minutes", int, "server")
        limit = gate.policy.tools["server.svid.attested"]["max_ttl_minutes"]
        if minutes > limit:
            raise config_mod.ConfigError(f"server.attested_svid_ttl_minutes ({minutes}) exceeds the tool policy's max_ttl_minutes ({limit})")
        attested_ttl = dt.timedelta(minutes=minutes)
    nodes = NodeRegistry(Path(data_dir) / "nodes.json")
    app = App(ca, registry, admin_token, x509_ttl, jwt_ttl, gate, nodes, attested_ttl)

    server_id = spiffeid.from_parts(td, "spiffe-server")
    cert_pem, key_pem = ca.issue_server_cert(server_id, dns_names, ips, ca_ttl)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory() as tmp:  # ssl needs files; the key never persists
        cpath, kpath = Path(tmp, "c.pem"), Path(tmp, "k.pem")
        cpath.write_bytes(cert_pem)
        os.chmod(tmp, 0o700)
        kpath.write_bytes(key_pem)
        ctx.load_cert_chain(cpath, kpath)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd, app


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lightweight learning SPIFFE server")
    ap.add_argument("--config", required=True)
    ap.add_argument("--token-env", default="SPIFFE_ADMIN_TOKEN", help="env var holding the admin token")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")
    token = os.environ.get(args.token_env, "")
    if len(token) < MIN_TOKEN_LEN:
        print(f"error: set {args.token_env} to a random secret of at least {MIN_TOKEN_LEN} characters, e.g.\n"
              f"  export {args.token_env}=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')", file=sys.stderr)
        return 2
    try:
        cfg = config_mod.load(args.config)
        httpd, app = build(cfg, token)
    except (config_mod.ConfigError, ToolPolicyError, CAError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    host, port = httpd.server_address[:2]
    log.info("listening on https://%s:%s  trust bundle: %s", host, port,
             Path(config_mod.resolve_path(cfg, cfg["server"]["data_dir"])) / "bundle.pem")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
