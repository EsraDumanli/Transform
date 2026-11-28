"""Identity lifecycle: the issuance log, revocation, and delegation grants.

See REVOCATION.md and DELEGATION.md for the designs and decisions.

* ``IssuanceLog``   one record per identity issued (never keys, CSRs or the identity itself)
* ``RevocationStore`` revoked identities, and the signed lists published to verifiers
  (an X.509 CRL for certificates, a signed JWS list for JWT IDs)
* ``GrantStore``    human -> agent delegation grants, checked at issuance
* ``RevocationChecker`` the verifier side: refreshes the lists and fails closed
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import spiffeid
from .ca import CAError, verify_jws


class LifecycleError(ValueError):
    """Invalid lifecycle request. The message is safe to show to the caller."""


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.isoformat(timespec="seconds")


def _parse(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts)


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# ---- issuance log --------------------------------------------------------------------

@dataclass
class Issued:
    kind: str                   # "x509" | "jwt"
    ident: str                  # x509: serial as lowercase hex; jwt: jti
    spiffe_id: str
    issued_at: str
    expires_at: str
    entry_id: str = ""
    node_id: str = ""
    method: str = ""
    confidence: str = ""
    delegation: dict | None = None   # {"principal", "principal_verified", "grant", "scopes", "until"}
    trace_id: str = ""


class IssuanceLog:
    """Append-only JSONL of identities issued. ``path=None`` keeps it in memory."""

    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._records: list[Issued] = []
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self._records.append(Issued(**json.loads(line)))

    def record(self, rec: Issued) -> Issued:
        with self._lock:
            self._records.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a") as f:
                    f.write(json.dumps(asdict(rec), separators=(",", ":")) + "\n")
        return rec

    def find(self, kind: str, ident: str) -> Issued | None:
        with self._lock:
            return next((r for r in self._records if r.kind == kind and r.ident == ident), None)

    def active(self, now: dt.datetime | None = None) -> list[Issued]:
        now = now or _utcnow()
        with self._lock:
            return [r for r in self._records if _parse(r.expires_at) > now]


def x509_serial_hex(cert_pem: bytes) -> tuple[str, dt.datetime]:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return format(cert.serial_number, "x"), cert.not_valid_after_utc


# ---- revocation ----------------------------------------------------------------------

REASONS = {  # owner-approved list (REVOCATION.md, R4) -> RFC 5280 reason code
    "key_compromise": x509.ReasonFlags.key_compromise,
    "device_lost": x509.ReasonFlags.key_compromise,
    "superseded": x509.ReasonFlags.superseded,
    "decommissioned": x509.ReasonFlags.cessation_of_operation,
    "policy_violation": x509.ReasonFlags.privilege_withdrawn,
}


@dataclass
class Revocation:
    kind: str
    ident: str
    spiffe_id: str
    reason: str
    revoked_by: str
    revoked_at: str
    expires_at: str
    note: str = ""


class RevocationStore:
    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], Revocation] = {}
        if self.path and self.path.exists():
            for r in json.loads(self.path.read_text()):
                rev = Revocation(**r)
                self._items[(rev.kind, rev.ident)] = rev

    def revoke(self, issued: Issued, reason: str, revoked_by: str, note: str = "") -> tuple[Revocation, bool]:
        if reason not in REASONS:
            raise LifecycleError(f"reason must be one of {sorted(REASONS)}")
        if not revoked_by.strip():
            raise LifecycleError("revoked_by is required")
        if len(note) > 200:
            raise LifecycleError("note must be at most 200 characters")
        if _parse(issued.expires_at) <= _utcnow():
            raise LifecycleError("that identity has already expired; there's nothing to revoke")
        with self._lock:
            key = (issued.kind, issued.ident)
            if key in self._items:
                return self._items[key], False
            rev = Revocation(kind=issued.kind, ident=issued.ident, spiffe_id=issued.spiffe_id, reason=reason,
                             revoked_by=revoked_by.strip(), revoked_at=_iso(_utcnow()),
                             expires_at=issued.expires_at, note=note)
            self._items[key] = rev
            self._save_locked()
        return rev, True

    def is_revoked(self, kind: str, ident: str) -> bool:
        with self._lock:
            return (kind, ident) in self._items

    def current(self, now: dt.datetime | None = None) -> list[Revocation]:
        """Revocations of identities that haven't expired yet (expired ones are pruned from lists)."""
        now = now or _utcnow()
        with self._lock:
            return [r for r in self._items.values() if _parse(r.expires_at) > now]

    def _save_locked(self) -> None:
        if self.path:
            _atomic_write(self.path, [asdict(r) for r in self._items.values()])

    # -- publishing

    def crl_der(self, ca, validity: dt.timedelta) -> bytes:
        now = _utcnow()
        b = (x509.CertificateRevocationListBuilder()
             .issuer_name(ca.cert.subject)
             .last_update(now)
             .next_update(now + validity)
             .add_extension(x509.CRLNumber(int(time.time() * 1000)), critical=False))
        for r in self.current(now):
            if r.kind != "x509":
                continue
            entry = (x509.RevokedCertificateBuilder()
                     .serial_number(int(r.ident, 16))
                     .revocation_date(_parse(r.revoked_at))
                     .add_extension(x509.CRLReason(REASONS[r.reason]), critical=False)
                     .build())
            b = b.add_revoked_certificate(entry)
        return b.sign(ca.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def jwt_list(self, ca, validity: dt.timedelta) -> str:
        now = _utcnow()
        jtis = [{"jti": r.ident, "exp": int(_parse(r.expires_at).timestamp()), "reason": r.reason}
                for r in self.current(now) if r.kind == "jwt"]
        payload = {"jtis": sorted(jtis, key=lambda x: x["jti"]), "issued_at": int(now.timestamp()),
                   "next_update": int((now + validity).timestamp()), "number": int(time.time() * 1000),
                   "trust_domain": ca.trust_domain}
        return ca.sign_jws(payload, "revocation-list+jwt")


# ---- delegation grants ---------------------------------------------------------------

SCOPE_PATTERNS = {   # owner-approved scope types (DELEGATION.md, Q2)
    "tool": re.compile(r"^tool:[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+$"),
    "data:path": re.compile(r"^data:path:[^\s\x00]{1,512}$"),
    "data:host": re.compile(r"^data:host:[A-Za-z0-9.-]{1,253}$"),
}


def scope_type(scope: str) -> str:
    for t, pat in SCOPE_PATTERNS.items():
        if pat.match(scope):
            return t
    raise LifecycleError(f"invalid scope {scope!r}; use tool:<server>.<tool>, data:path:<glob> or data:host:<hostname>")


@dataclass
class Grant:
    id: str
    principal: str
    agent_spiffe_id: str
    scopes: list[str]
    not_before: str
    not_after: str
    created_by: str
    created_at: str
    status: str = "active"          # active | withdrawn   (expired is computed)
    note: str = ""
    withdrawn_by: str = ""
    withdrawn_at: str = ""
    principal_verified: bool = False

    def state(self, now: dt.datetime | None = None) -> str:
        now = now or _utcnow()
        if self.status == "withdrawn":
            return "withdrawn"
        if now >= _parse(self.not_after):
            return "expired"
        if now < _parse(self.not_before):
            return "not_yet_valid"
        return "active"


class GrantStore:
    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.grants: dict[str, Grant] = {}
        if self.path and self.path.exists():
            self.grants = {g["id"]: Grant(**g) for g in json.loads(self.path.read_text())}

    def create(self, principal: str, agent_spiffe_id: str, scopes, minutes: int, created_by: str,
               max_minutes: int, allowed_types: list[str], note: str = "") -> Grant:
        principal = (principal or "").strip()
        if not principal or len(principal) > 100:
            raise LifecycleError("principal (the person's name) is required, up to 100 characters")
        sid = spiffeid.parse(agent_spiffe_id)
        if not isinstance(scopes, list) or not scopes:
            raise LifecycleError("at least one scope is required")
        for sc in scopes:
            if not isinstance(sc, str):
                raise LifecycleError("scopes must be strings")
            t = scope_type(sc)
            if t not in allowed_types:
                raise LifecycleError(f"scope type {t!r} isn't allowed by the tool policy (allowed: {allowed_types})")
        if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes <= 0:
            raise LifecycleError("minutes must be a positive whole number")
        if minutes > max_minutes:
            raise LifecycleError(f"a grant can last at most {max_minutes} minutes (tool policy)")
        if not created_by.strip():
            raise LifecycleError("created_by is required")
        if len(note) > 200:
            raise LifecycleError("note must be at most 200 characters")
        now = _utcnow()
        g = Grant(id="g_" + secrets.token_hex(8), principal=principal, agent_spiffe_id=str(sid),
                  scopes=sorted(set(scopes)), not_before=_iso(now), not_after=_iso(now + dt.timedelta(minutes=minutes)),
                  created_by=created_by.strip(), created_at=_iso(now), note=note)
        with self._lock:
            self.grants[g.id] = g
            self._save_locked()
        return g

    def withdraw(self, grant_id: str, who: str) -> Grant:
        if not who.strip():
            raise LifecycleError("withdrawn_by is required")
        with self._lock:
            g = self.grants.get(grant_id)
            if g is None:
                raise LifecycleError("unknown grant")
            if g.status == "withdrawn":
                return g
            g.status, g.withdrawn_by, g.withdrawn_at = "withdrawn", who.strip(), _iso(_utcnow())
            self._save_locked()
        return g

    def list(self) -> list[Grant]:
        with self._lock:
            return sorted(self.grants.values(), key=lambda g: g.created_at, reverse=True)

    def authorize(self, grant_id: str, spiffe_id: str, requested_scopes) -> tuple[Grant, list[str]]:
        """Check a delegation request at issuance. Returns the grant and the scopes to embed."""
        with self._lock:
            g = self.grants.get(str(grant_id))
        if g is None:
            raise LifecycleError("unknown delegation grant")
        state = g.state()
        if state != "active":
            raise LifecycleError(f"delegation grant is {state}")
        if g.agent_spiffe_id != spiffe_id:
            raise LifecycleError("delegation grant is for a different agent identity")
        scopes = g.scopes if requested_scopes in (None, []) else requested_scopes
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise LifecycleError("delegation scopes must be a list of strings")
        extra = [s for s in scopes if s not in g.scopes]
        if extra:
            raise LifecycleError(f"scope(s) not in the grant: {extra}")
        return g, sorted(set(scopes))

    def _save_locked(self) -> None:
        if self.path:
            _atomic_write(self.path, [asdict(g) for g in self.grants.values()])


def delegation_claim(grant: Grant, scopes: list[str]) -> dict:
    return {"principal": grant.principal, "principal_verified": grant.principal_verified, "grant": grant.id,
            "scopes": scopes, "until": int(_parse(grant.not_after).timestamp())}


def capped_ttl(ttl: dt.timedelta, grant: Grant | None) -> dt.timedelta:
    """A delegated identity never outlives its grant."""
    if grant is None:
        return ttl
    remaining = _parse(grant.not_after) - _utcnow()
    if remaining <= dt.timedelta(seconds=30):
        raise LifecycleError("delegation grant ends in under 30 seconds; create a new grant")
    return min(ttl, remaining)


# ---- verifier side -------------------------------------------------------------------

class RevocationUnavailable(CAError):
    """No fresh revocation list: fail closed."""


class IdentityRevoked(CAError):
    pass


class RevocationChecker:
    """Verifier helper. Keeps the newest valid lists; refuses everything when they're stale.

    ``fetch_crl`` returns DER bytes, ``fetch_jwt_list`` returns the compact JWS string.
    ``refresh_seconds`` is how often to fetch (owner decision: 60 s). There's no default:
    callers state it explicitly.
    """

    def __init__(self, ca_cert: x509.Certificate, jwks: dict, refresh_seconds: int,
                 fetch_crl=None, fetch_jwt_list=None, clock=time.time):
        self.ca_cert, self.jwks, self.refresh_seconds = ca_cert, jwks, refresh_seconds
        self.fetch_crl, self.fetch_jwt_list, self.clock = fetch_crl, fetch_jwt_list, clock
        self._crl: x509.CertificateRevocationList | None = None
        self._crl_number = -1
        self._jwt: dict | None = None
        self._last_fetch = 0.0
        self.last_error = ""

    # -- loading
    def load_crl(self, der: bytes) -> None:
        crl = x509.load_der_x509_crl(der)
        if crl.issuer != self.ca_cert.subject or not crl.is_signature_valid(self.ca_cert.public_key()):
            raise RevocationUnavailable("revocation list isn't signed by this trust domain's CA")
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        if number < self._crl_number:
            raise RevocationUnavailable("revocation list is older than the one already held")
        self._crl, self._crl_number = crl, number

    def load_jwt_list(self, token: str) -> None:
        payload = verify_jws(token, self.jwks, typ="revocation-list+jwt")
        if self._jwt and payload.get("number", 0) < self._jwt.get("number", 0):
            raise RevocationUnavailable("JWT revocation list is older than the one already held")
        self._jwt = payload

    def refresh(self, force: bool = False) -> None:
        if not force and self.clock() - self._last_fetch < self.refresh_seconds:
            return
        try:
            if self.fetch_crl:
                self.load_crl(self.fetch_crl())
            if self.fetch_jwt_list:
                self.load_jwt_list(self.fetch_jwt_list())
            self._last_fetch = self.clock()
            self.last_error = ""
        except Exception as e:  # noqa: BLE001 - kept; the freshness check below decides
            self.last_error = f"{type(e).__name__}: {e}"

    # -- checks (fail closed)
    def check_x509(self, cert_pem: bytes) -> None:
        self.refresh()
        if self._crl is None:
            raise RevocationUnavailable(f"no revocation list available{': ' + self.last_error if self.last_error else ''}")
        next_update = self._crl.next_update_utc
        if next_update is None or self.clock() >= next_update.timestamp():
            raise RevocationUnavailable(f"revocation list expired at {next_update}; refusing identities until a fresh list is available")
        serial = x509.load_pem_x509_certificate(cert_pem).serial_number
        entry = self._crl.get_revoked_certificate_by_serial_number(serial)
        if entry is not None:
            raise IdentityRevoked(f"certificate {format(serial, 'x')} is revoked")

    def check_jwt(self, jti: str) -> None:
        self.refresh()
        if self._jwt is None:
            raise RevocationUnavailable(f"no JWT revocation list available{': ' + self.last_error if self.last_error else ''}")
        if self.clock() >= self._jwt.get("next_update", 0):
            raise RevocationUnavailable("JWT revocation list expired; refusing identities until a fresh list is available")
        if any(x.get("jti") == jti for x in self._jwt.get("jtis", [])):
            raise IdentityRevoked(f"JWT {jti} is revoked")
