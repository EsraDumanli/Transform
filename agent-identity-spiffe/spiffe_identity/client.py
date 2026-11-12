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


class ServerError(RuntimeError):
    pass


class Client:
    def __init__(self, server_url: str, bundle_file: str, token: str, timeout: float = 10):
        if not token:
            raise ServerError("admin token is empty")
        self.base = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=bundle_file)

    @classmethod
    def from_config(cls, cfg: dict, resolve) -> "Client":
        c = cfg.get("client") or {}
        for k in ("server_url", "bundle_file", "admin_token_env"):
            if not c.get(k):
                raise ServerError(f"client.{k} is required")
        token = os.environ.get(c["admin_token_env"], "")
        if not token:
            raise ServerError(f"environment variable {c['admin_token_env']} (client.admin_token_env) is not set")
        return cls(c["server_url"], resolve(c["bundle_file"]), token, c.get("timeout_seconds", 10))

    def _call(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
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
        return self._call("POST", "/v1/entries", entry)

    def list_entries(self) -> list[dict]:
        return self._call("GET", "/v1/entries")

    def x509_svid(self, spiffe_id: str) -> tuple[bytes, bytes, bytes]:
        """Generate a key locally, send only the CSR. Returns (cert_pem, key_pem, bundle_pem)."""
        key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
        resp = self._call("POST", "/v1/svid/x509", {
            "spiffe_id": spiffe_id, "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
        })
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return resp["svid"].encode(), key_pem, resp["bundle"].encode()

    def jwt_svid(self, spiffe_id: str, audience: list[str]) -> str:
        return self._call("POST", "/v1/svid/jwt", {"spiffe_id": spiffe_id, "audience": audience})["token"]
