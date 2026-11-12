"""A local web portal: discovered workloads, their attributes, and the identities assigned to them.

  agent-discovery portal --config config.json --approver "your-name"

What it shows
-------------
* The last saved scan (``portal.scan_file``), written by ``plan``, ``apply``
  or the portal's own "Scan now" button.
* The registration entries currently on the SPIFFE server.
* For every workload: kind, source, attributes, selectors, the proposed
  SPIFFE ID (and whether a rule or the LLM chose it), and whether it is
  registered.

What it can do
--------------
* Scan now: run discovery + policy (+ the LLM step if enabled) and save it.
* Approve a proposed identity: creates a registration entry with
  ``approved_by`` set to the ``--approver`` the portal was started with.
* Revoke: deletes a registration entry. SVIDs that were already issued stay
  valid until they expire; this learning server has no revocation list.

Security model (no login)
-------------------------
* It only binds to a loopback address, so only this computer can reach it.
* Every request must carry a ``Host`` header naming that loopback address
  and port. This blocks DNS-rebinding attacks, where another website points
  its own hostname at 127.0.0.1.
* Every action (scan, approve, revoke) must send the per-run token that is
  embedded in the page as an ``X-Portal-Token`` header with a JSON body. Other
  websites open in your browser can't read the page to learn the token, and
  can't send that header without a CORS preflight, which the portal never
  approves. That blocks cross-site request forgery.
* All workload data is inserted into the page as text, never as HTML,
  because manifest and label values are untrusted.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from . import config as config_mod, pipeline
from .client import Client, ServerError

log = logging.getLogger("portal")
MAX_BODY = 16 * 1024


class PortalError(ValueError):
    pass


def check_loopback(host: str) -> None:
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise PortalError(
        f"portal.listen_host must be a loopback address (127.0.0.1, ::1 or localhost), not {host!r}: "
        "the portal has no login, so it must not be reachable from other machines"
    )


class Portal:
    """Request handling, independent of the HTTP plumbing (so it is easy to test)."""

    def __init__(self, cfg: dict, approver: str, client: Client | None, use_llm: bool | None = None,
                 token: str | None = None, plan=pipeline.plan):
        if not approver.strip():
            raise PortalError("--approver is required: it is recorded on every entry approved from the portal")
        p = config_mod.section(cfg, "portal")
        self.host = config_mod.require(p, "listen_host", str, "portal")
        self.port = config_mod.require(p, "listen_port", int, "portal")
        check_loopback(self.host)
        self.scan_path = pipeline.scan_file(cfg)
        if not self.scan_path:
            raise PortalError("portal.scan_file is required (where the last scan is saved)")
        self.cfg, self.approver, self.client, self.use_llm = cfg, approver.strip(), client, use_llm
        self.token = token or secrets.token_urlsafe(32)
        self._plan = plan
        self._scan_lock = threading.Lock()
        self.allowed_hosts = self._allowed_hosts()

    def _allowed_hosts(self) -> set[str]:
        names = {self.host, "localhost", "127.0.0.1", "[::1]"}
        if ":" in self.host and not self.host.startswith("["):
            names.add(f"[{self.host}]")
        return {f"{n}:{self.port}" for n in names}

    # ---- data -----------------------------------------------------------------

    def _entries(self) -> tuple[list[dict] | None, str]:
        if self.client is None:
            return None, "no SPIFFE server client configured"
        try:
            return self.client.list_entries(), ""
        except ServerError as e:
            return None, str(e)

    def state(self) -> dict:
        snap, snap_error = None, ""
        try:
            snap = pipeline.load_snapshot(self.scan_path, self.cfg["trust_domain"])
        except (ValueError, OSError) as e:
            snap_error = str(e)
        entries, entries_error = self._entries()
        llm_cfg = self.cfg.get("llm") or {}
        return {
            "trust_domain": self.cfg["trust_domain"],
            "approver": self.approver,
            "llm_enabled": bool(llm_cfg.get("enabled", False) if self.use_llm is None else self.use_llm),
            "scan": snap,
            "scan_error": snap_error,
            "scan_file": self.scan_path,
            "entries": entries,
            "entries_error": entries_error,
        }

    # ---- actions --------------------------------------------------------------

    def scan(self) -> dict:
        if not self._scan_lock.acquire(blocking=False):
            raise PortalError("a scan is already running")
        try:
            result = self._plan(self.cfg, self.use_llm)
            pipeline.save_snapshot(self.scan_path, pipeline.snapshot(self.cfg, result))
        finally:
            self._scan_lock.release()
        return self.state()

    def approve(self, proposal_id: str) -> dict:
        snap = pipeline.load_snapshot(self.scan_path, self.cfg["trust_domain"])
        if snap is None:
            raise PortalError("there is no saved scan yet")
        match = next((p for p in snap["proposals"] if p["id"] == proposal_id), None)
        if match is None:
            raise PortalError("that proposal is not in the current scan; scan again and retry")
        if not match.get("spiffe_id"):
            raise PortalError("that workload has no proposed identity, so there is nothing to approve")
        if self.client is None:
            raise PortalError("no SPIFFE server client configured")
        w = match["workload"]
        entry = self.client.create_entry({
            "spiffe_id": match["spiffe_id"], "selectors": w["selectors"], "source": w["source"],
            "assigned_by": match["assigned_by"], "approved_by": self.approver, "rationale": match.get("rationale", ""),
        })
        log.info("approved %s for %s (entry %s)", match["spiffe_id"], w["name"], entry.get("id"))
        return self.state()

    def revoke(self, entry_id: str) -> dict:
        if self.client is None:
            raise PortalError("no SPIFFE server client configured")
        self.client.delete_entry(entry_id)
        log.info("revoked entry %s", entry_id)
        return self.state()

    # ---- HTTP -----------------------------------------------------------------

    def page(self) -> bytes:
        html = _static("index.html").decode()
        return html.replace("__PORTAL_TOKEN__", self.token).encode()

    def handle(self, method: str, path: str, headers, body: bytes) -> tuple[int, str, bytes]:
        if headers.get("Host", "") not in self.allowed_hosts:
            return _json(421, {"error": "unexpected Host header"})
        if method == "GET" and path in ("/", "/index.html"):
            return 200, "text/html; charset=utf-8", self.page()
        if method == "GET" and path in STATIC_ASSETS:
            name, ctype = STATIC_ASSETS[path]
            return 200, ctype, _static(name)
        if method == "GET" and path == "/api/state":
            return _json(200, self.state())
        if method != "POST" or not path.startswith("/api/"):
            return _json(404, {"error": "not found"})

        # Every action needs the page's token in a header and a JSON body.
        if not hmac.compare_digest(headers.get("X-Portal-Token", "").encode(), self.token.encode()):
            return _json(403, {"error": "missing or invalid portal token; reload the page"})
        if not headers.get("Content-Type", "").startswith("application/json"):
            return _json(415, {"error": "expected application/json"})
        try:
            req = json.loads(body or b"{}")
            if not isinstance(req, dict):
                raise ValueError
        except ValueError:
            return _json(400, {"error": "body must be a JSON object"})

        try:
            if path == "/api/scan":
                return _json(200, self.scan())
            if path == "/api/approve":
                return _json(200, self.approve(str(req.get("proposal_id", ""))))
            if path == "/api/revoke":
                return _json(200, self.revoke(str(req.get("entry_id", ""))))
        except PortalError as e:
            return _json(409, {"error": str(e)})
        except ServerError as e:
            return _json(502, {"error": f"SPIFFE server: {e}"})
        except (config_mod.ConfigError, ValueError, OSError) as e:
            return _json(500, {"error": str(e)})
        return _json(404, {"error": "not found"})


STATIC_ASSETS = {
    "/portal.js": ("portal.js", "text/javascript; charset=utf-8"),
    "/portal.css": ("portal.css", "text/css; charset=utf-8"),
}


def _static(name: str) -> bytes:
    return resources.files("spiffe_identity").joinpath("portal_static", name).read_bytes()


def _json(status: int, obj) -> tuple[int, str, bytes]:
    return status, "application/json", json.dumps(obj).encode()


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                               "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
                               "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def make_handler(portal: Portal):
    class Handler(BaseHTTPRequestHandler):
        server_version = "agent-identity-portal"

        def _dispatch(self, method: str):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                status, ctype, body = _json(413, {"error": "body too large"})
            else:
                raw = self.rfile.read(length) if length else b""
                status, ctype, body = portal.handle(method, self.path.split("?", 1)[0], self.headers, raw)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_OPTIONS(self):  # never approve a CORS preflight
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(portal: Portal) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((portal.host, portal.port), make_handler(portal))
