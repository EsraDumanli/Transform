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
from .registry import Entry, Registry, RegistryError

log = logging.getLogger("spiffe-server")
MAX_BODY = 64 * 1024
MIN_TOKEN_LEN = 32


class App:
    """Request handling logic, independent of the HTTP plumbing (easy to test)."""

    def __init__(self, ca: CertificateAuthority, registry: Registry, admin_token: str,
                 x509_ttl: dt.timedelta, jwt_ttl: dt.timedelta):
        if len(admin_token) < MIN_TOKEN_LEN:
            raise ValueError(f"admin token must be at least {MIN_TOKEN_LEN} characters")
        self.ca, self.registry, self.token = ca, registry, admin_token
        self.x509_ttl, self.jwt_ttl = x509_ttl, jwt_ttl

    def authorized(self, header: str | None) -> bool:
        if not header or not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].encode(), self.token.encode())

    def handle(self, method: str, path: str, auth: str | None, body: bytes) -> tuple[int, str, bytes]:
        """Return (status, content_type, body)."""
        if method == "GET" and path == "/healthz":
            return _json(200, {"ok": True, "trust_domain": self.ca.trust_domain})
        if method == "GET" and path == "/v1/bundle":
            return 200, "application/x-pem-file", self.ca.bundle_pem()
        if method == "GET" and path == "/v1/bundle/jwks":
            return _json(200, self.ca.jwks())

        if not path.startswith("/v1/"):
            return _json(404, {"error": "not found"})
        if not self.authorized(auth):
            return _json(401, {"error": "missing or invalid admin token"})

        try:
            req = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return _json(400, {"error": "body must be JSON"})
        if not isinstance(req, dict):
            return _json(400, {"error": "body must be a JSON object"})

        try:
            if method == "GET" and path == "/v1/entries":
                return _json(200, [e.__dict__ for e in self.registry.list()])
            if method == "POST" and path == "/v1/entries":
                entry, created = self.registry.create(Entry(
                    spiffe_id=str(req.get("spiffe_id", "")), selectors=list(req.get("selectors") or []),
                    source=str(req.get("source", "")), assigned_by=str(req.get("assigned_by", "")),
                    approved_by=str(req.get("approved_by", "")), rationale=str(req.get("rationale", "")),
                ))
                log.info("entry %s %s -> %s (approved by %s)", "created" if created else "exists",
                         entry.id, entry.spiffe_id, entry.approved_by)
                return _json(201 if created else 200, {**entry.__dict__, "created": created})
            if method == "DELETE" and path.startswith("/v1/entries/"):
                ok = self.registry.delete(path.rsplit("/", 1)[1])
                return _json(200 if ok else 404, {"deleted": ok})
            if method == "POST" and path == "/v1/svid/x509":
                sid = self._registered(req)
                cert = self.ca.issue_x509_svid(str(req.get("csr", "")).encode(), sid, self.x509_ttl)
                log.info("issued X.509-SVID for %s", sid)
                return _json(200, {"svid": cert.decode(), "bundle": self.ca.bundle_pem().decode()})
            if method == "POST" and path == "/v1/svid/jwt":
                sid = self._registered(req)
                aud = req.get("audience")
                if not isinstance(aud, list) or not all(isinstance(a, str) and a for a in aud):
                    return _json(400, {"error": "audience must be a non-empty list of strings"})
                token = self.ca.mint_jwt_svid(sid, aud, self.jwt_ttl)
                log.info("issued JWT-SVID for %s aud=%s", sid, aud)
                return _json(200, {"token": token})
        except _NotRegistered as e:
            return _json(403, {"error": str(e)})
        except (CAError, RegistryError, spiffeid.SpiffeIDError) as e:
            return _json(400, {"error": str(e)})
        return _json(404, {"error": "not found"})

    def _registered(self, req: dict) -> spiffeid.SpiffeID:
        sid = spiffeid.parse(str(req.get("spiffe_id", "")))
        if not self.registry.has_spiffe_id(str(sid)):
            raise _NotRegistered(f"{sid} has no registration entry; register and approve it first")
        return sid


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
                status, ctype, body = app.handle(method, self.path.split("?", 1)[0], self.headers.get("Authorization"), raw)
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


def build(cfg: dict, admin_token: str) -> tuple[ThreadingHTTPServer, App]:
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
    app = App(ca, registry, admin_token, x509_ttl, jwt_ttl)

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
    except (config_mod.ConfigError, CAError, OSError) as e:
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
