import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from spiffe_identity import pipeline, server
from spiffe_identity.client import Client
from spiffe_identity.portal import Portal, PortalError, check_loopback, serve

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
TOKEN = "t" * 40


def make_cfg(tmp_path, port=8765, host="127.0.0.1"):
    cfg = json.loads((EXAMPLES / "demo.config.json").read_text())
    cfg["_base_dir"] = str(EXAMPLES)
    cfg["server"]["data_dir"] = str(tmp_path / "data")
    cfg["portal"] = {"listen_host": host, "listen_port": port, "scan_file": str(tmp_path / "scan.json")}
    return cfg


class FakeClient:
    def __init__(self):
        self.entries, self.n = [], 0

    def list_entries(self):
        return list(self.entries)

    def create_entry(self, e):
        self.n += 1
        e = {**e, "id": f"e{self.n}", "created_at": "2026-11-12T00:00:00+00:00", "created": True}
        self.entries.append(e)
        return e

    def delete_entry(self, entry_id):
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        return {"deleted": True}


class H(dict):
    """Header lookup like http.client's: missing keys return ''."""

    def get(self, k, d=""):
        return super().get(k, d)


def headers(port=8765, token=TOKEN, ctype="application/json"):
    return H({"Host": f"127.0.0.1:{port}", "X-Portal-Token": token, "Content-Type": ctype})


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com", ""])
def test_refuses_non_loopback(host):
    with pytest.raises(PortalError):
        check_loopback(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.0.0.2"])
def test_accepts_loopback(host):
    check_loopback(host)


def test_requires_approver_and_scan_file(tmp_path):
    cfg = make_cfg(tmp_path)
    with pytest.raises(PortalError, match="approver"):
        Portal(cfg, "  ", FakeClient())
    del cfg["portal"]["scan_file"]
    with pytest.raises(PortalError, match="scan_file"):
        Portal(cfg, "me", FakeClient())
    cfg = make_cfg(tmp_path, host="0.0.0.0")
    with pytest.raises(PortalError, match="loopback"):
        Portal(cfg, "me", FakeClient())


def test_host_header_and_token_checks(tmp_path):
    portal = Portal(make_cfg(tmp_path), "me", FakeClient(), token=TOKEN)
    # DNS rebinding: a foreign Host header is refused, even for reads.
    assert portal.handle("GET", "/api/state", H({"Host": "evil.example:8765"}), b"")[0] == 421
    assert portal.handle("GET", "/", H({"Host": "127.0.0.1:9999"}), b"")[0] == 421
    # The page embeds the token; static assets are served.
    status, ctype, body = portal.handle("GET", "/", headers(), b"")
    assert status == 200 and TOKEN.encode() in body and b"__PORTAL_TOKEN__" not in body
    assert portal.handle("GET", "/portal.js", headers(), b"")[0] == 200
    # CSRF: actions need the token header and a JSON content type.
    assert portal.handle("POST", "/api/scan", headers(token="wrong"), b"{}")[0] == 403
    assert portal.handle("POST", "/api/scan", headers(ctype="text/plain"), b"{}")[0] == 415
    assert portal.handle("POST", "/api/scan", H({"Host": "127.0.0.1:8765"}), b"{}")[0] == 403


def test_state_before_any_scan(tmp_path):
    state = Portal(make_cfg(tmp_path), "me", FakeClient()).state()
    assert state["scan"] is None and state["scan_error"] == "" and state["entries"] == []


def test_scan_approve_revoke_flow(tmp_path):
    client = FakeClient()
    portal = Portal(make_cfg(tmp_path), "Esra", client, token=TOKEN)
    status, _, body = portal.handle("POST", "/api/scan", headers(), b"{}")
    assert status == 200
    state = json.loads(body)
    props = {p["workload"]["name"]: p for p in state["scan"]["proposals"]}
    assert set(props) == {"Ticket Triage Agent", "filesystem", "ticket-api", "notes-search"}
    assert (tmp_path / "scan.json").exists()

    # Unassigned workloads cannot be approved.
    st, _, body = portal.handle("POST", "/api/approve", headers(), json.dumps({"proposal_id": props["notes-search"]["id"]}).encode())
    assert st == 409 and "no proposed identity" in json.loads(body)["error"]
    # Unknown ids cannot be approved.
    assert portal.handle("POST", "/api/approve", headers(), b'{"proposal_id": "nope"}')[0] == 409

    triage = props["Ticket Triage Agent"]
    st, _, body = portal.handle("POST", "/api/approve", headers(), json.dumps({"proposal_id": triage["id"]}).encode())
    assert st == 200
    entry = json.loads(body)["entries"][0]
    assert entry["spiffe_id"] == "spiffe://demo.local/ai-agent/Ticket-Triage-Agent"
    assert entry["approved_by"] == "Esra" and entry["assigned_by"] == "policy:a2a-agents"

    st, _, body = portal.handle("POST", "/api/revoke", headers(), json.dumps({"entry_id": entry["id"]}).encode())
    assert st == 200 and json.loads(body)["entries"] == []


def test_snapshot_ids_are_stable_and_domain_checked(tmp_path):
    cfg = make_cfg(tmp_path)
    s1 = pipeline.snapshot(cfg, pipeline.plan(cfg, use_llm=False))
    s2 = pipeline.snapshot(cfg, pipeline.plan(cfg, use_llm=False))
    assert [p["id"] for p in s1["proposals"]] == [p["id"] for p in s2["proposals"]]
    path = str(tmp_path / "s.json")
    pipeline.save_snapshot(path, s1)
    assert pipeline.load_snapshot(path, "demo.local")["scanned_at"] == s1["scanned_at"]
    with pytest.raises(ValueError, match="trust domain"):
        pipeline.load_snapshot(path, "other.local")


def test_server_unreachable_is_reported_not_hidden(tmp_path):
    class Down(FakeClient):
        def list_entries(self):
            from spiffe_identity.client import ServerError
            raise ServerError("connection refused")

    state = Portal(make_cfg(tmp_path), "me", Down()).state()
    assert state["entries"] is None and "connection refused" in state["entries_error"]


def test_end_to_end_over_http_with_real_server(tmp_path):
    cfg = make_cfg(tmp_path, port=1)
    orig = server.ThreadingHTTPServer

    class AnyPort(orig):
        def __init__(self, addr, handler):
            super().__init__((addr[0], 0), handler)

    server.ThreadingHTTPServer = AnyPort
    try:
        httpd, _ = server.build(cfg, TOKEN)
    finally:
        server.ThreadingHTTPServer = orig
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    client = Client(f"https://127.0.0.1:{httpd.server_address[1]}", str(tmp_path / "data" / "bundle.pem"), TOKEN)

    # Find a free port for the portal itself.
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    portal = Portal(make_cfg(tmp_path, port=port), "Esra", client)
    phttpd = serve(portal)
    threading.Thread(target=phttpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        page = urllib.request.urlopen(base + "/").read().decode()
        token = page.split('name="portal-token" content="')[1].split('"')[0]
        assert token == portal.token

        # A cross-site preflight is never approved.
        req = urllib.request.Request(base + "/api/scan", method="OPTIONS")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 405

        def post(path, body):
            req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "X-Portal-Token": token})
            return json.loads(urllib.request.urlopen(req).read())

        state = post("/api/scan", {})
        pid = next(p["id"] for p in state["scan"]["proposals"] if p["workload"]["name"] == "ticket-api")
        state = post("/api/approve", {"proposal_id": pid})
        assert [e["spiffe_id"] for e in state["entries"]] == ["spiffe://demo.local/mcp/http/ticket-api"]
        resp = urllib.request.urlopen(base + "/api/state")
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
        state = post("/api/revoke", {"entry_id": state["entries"][0]["id"]})
        assert state["entries"] == []
    finally:
        phttpd.shutdown()
        httpd.shutdown()
