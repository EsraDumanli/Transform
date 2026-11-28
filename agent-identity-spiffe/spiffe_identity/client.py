"""Client for the SPIFFE server's admin API (TLS, verified against the trust bundle)."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import trace as trace_mod


class ServerError(RuntimeError):
    pass


class Client:
    def __init__(self, server_url: str, bundle_file: str, token: str, gate, timeout: float = 10):
        if not token:
            raise ServerError("admin token is empty")
        self.gate = gate
        self.base = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=bundle_file)

    @classmethod
    def from_config(cls, cfg: dict, resolve, gate) -> "Client":
        c = cfg.get("client") or {}
        for k in ("server_url", "bundle_file", "admin_token_env"):
            if not c.get(k):
                raise ServerError(f"client.{k} is required")
        token = os.environ.get(c["admin_token_env"], "")
        if not token:
            raise ServerError(f"environment variable {c['admin_token_env']} (client.admin_token_env) is not set")
        return cls(c["server_url"], resolve(c["bundle_file"]), token, gate, c.get("timeout_seconds", 10))

    def _call(self, tool: str, method: str, path: str, body: dict | None = None, **args):
        """Every server call: policy check on the server URL and on the action, both traced."""
        self.gate.check("server.connect", url=self.base)
        with self.gate.action(tool, **args) as summary:
            result = self._http(method, path, body)
            summary["http"] = f"{method} {path}"
            return result

    def _http(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        tid = trace_mod.current_trace_id()
        if tid:
            req.add_header("X-Trace-Id", tid)  # links the server's trace events to this run
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            raise ServerError(f"{method} {path}: HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise ServerError(f"{method} {path}: {e.reason}") from e

    def create_entry(self, entry: dict) -> dict:
        return self._call("server.entries.create", "POST", "/v1/entries", entry, spiffe_id=entry.get("spiffe_id", ""))

    def delete_entry(self, entry_id: str) -> dict:
        if not entry_id or not entry_id.isalnum():
            raise ServerError("invalid entry id")
        return self._call("server.entries.delete", "DELETE", f"/v1/entries/{entry_id}", entry_id=entry_id)

    # ---- devices (node attestation) ------------------------------------------------

    def list_nodes(self) -> list[dict]:
        return self._call("server.nodes.list", "GET", "/v1/nodes")

    def node_action(self, node_id: str, action: str, decided_by: str) -> dict:
        if not node_id.isalnum() or action not in ("approve", "block", "revoke"):
            raise ServerError("invalid node id or action")
        return self._call("server.nodes.manage", "POST", f"/v1/nodes/{node_id}/{action}", {"decided_by": decided_by},
                          node_id=node_id, action=action, decided_by=decided_by)

    def list_builds(self) -> list[dict]:
        return self._call("server.nodes.list", "GET", "/v1/builds")

    def build_action(self, build_id: str, action: str, decided_by: str) -> dict:
        if not build_id.isalnum() or action not in ("approve", "reject"):
            raise ServerError("invalid build id or action")
        return self._call("server.nodes.manage", "POST", f"/v1/builds/{build_id}/{action}", {"decided_by": decided_by},
                          build_id=build_id, action=action, decided_by=decided_by)

    def list_entries(self) -> list[dict]:
        return self._call("server.entries.list", "GET", "/v1/entries")

    def x509_svid(self, spiffe_id: str, delegation: dict | None = None) -> tuple[bytes, bytes, bytes]:
        """Generate a key locally, send only the CSR. Returns (cert_pem, key_pem, bundle_pem)."""
        key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
        resp = self._call("server.svid.x509", "POST", "/v1/svid/x509", {
            "spiffe_id": spiffe_id, "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            **({"delegation": delegation} if delegation else {}),
        }, spiffe_id=spiffe_id)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return resp["svid"].encode(), key_pem, resp["bundle"].encode()

    def jwt_svid(self, spiffe_id: str, audience: list[str], delegation: dict | None = None) -> str:
        body = {"spiffe_id": spiffe_id, "audience": audience, **({"delegation": delegation} if delegation else {})}
        return self._call("server.svid.jwt", "POST", "/v1/svid/jwt", body, spiffe_id=spiffe_id, audience=audience)["token"]

    # ---- identity lifecycle: issued identities, revocation, delegation grants ------

    def list_svids(self) -> list[dict]:
        return self._call("server.svid.list_issued", "GET", "/v1/svids")

    def revoke_svid(self, kind: str, ident: str, reason: str, revoked_by: str, note: str = "") -> dict:
        return self._call("server.svid.revoke", "POST", "/v1/svids/revoke",
                          {"kind": kind, "ident": ident, "reason": reason, "revoked_by": revoked_by, "note": note},
                          kind=kind, ident=ident, reason=reason, revoked_by=revoked_by)

    def list_grants(self) -> list[dict]:
        return self._call("server.grants.list", "GET", "/v1/grants")

    def create_grant(self, principal: str, agent_spiffe_id: str, scopes: list[str], minutes: int,
                     created_by: str, note: str = "") -> dict:
        from .lifecycle import LifecycleError, scope_type
        try:
            types = sorted({scope_type(x) for x in scopes})
        except LifecycleError as e:
            raise ServerError(str(e)) from e
        return self._call("server.grants.create", "POST", "/v1/grants",
                          {"principal": principal, "agent_spiffe_id": agent_spiffe_id, "scopes": scopes,
                           "minutes": minutes, "created_by": created_by, "note": note},
                          principal=principal, agent_spiffe_id=agent_spiffe_id, minutes=minutes, scope_types=types)

    def withdraw_grant(self, grant_id: str, withdrawn_by: str) -> dict:
        if not grant_id.replace("_", "").isalnum():
            raise ServerError("invalid grant id")
        return self._call("server.grants.withdraw", "POST", f"/v1/grants/{grant_id}/withdraw",
                          {"withdrawn_by": withdrawn_by}, grant=grant_id, withdrawn_by=withdrawn_by)

    def fetch_public(self, path: str) -> bytes:
        """Unauthenticated GET of a public endpoint (trust bundle, revocation lists)."""
        req = urllib.request.Request(self.base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            raise ServerError(f"GET {path}: HTTP {e.code}: {e.read().decode(errors='replace')}") from e
        except urllib.error.URLError as e:
            raise ServerError(f"GET {path}: {e.reason}") from e
