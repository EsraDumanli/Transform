import datetime as dt
import json
import threading

import pytest

from tests.helpers import make_gate

from spiffe_identity import ca as ca_mod, server
from spiffe_identity.client import Client, ServerError

TOKEN = "t" * 40
SERVER_TOOLS = {
    "server.entries.list": {}, "server.entries.delete": {},
    "server.entries.create": {"spiffe_id_prefixes": ["spiffe://test.local/"]},
    "server.svid.x509": {"spiffe_id_prefixes": ["spiffe://test.local/"]},
    "server.svid.jwt": {"spiffe_id_prefixes": ["spiffe://test.local/"], "audiences": ["ticket-api"]},
}


@pytest.fixture()
def running(tmp_path):
    cfg = {
        "trust_domain": "test.local", "_base_dir": str(tmp_path),
        "server": {"data_dir": "data", "listen_host": "127.0.0.1", "listen_port": 1,  # replaced below
                   "tls_dns_names": ["localhost"], "tls_ip_addresses": ["127.0.0.1"],
                   "ca_ttl_hours": 1, "x509_svid_ttl_minutes": 5, "jwt_svid_ttl_minutes": 5},
    }
    cfg["server"]["listen_port"] = 1
    # Port 0 asks the OS for a free port; the config validator wants > 0, so patch after validation.
    orig = server.ThreadingHTTPServer

    class AnyPort(orig):
        def __init__(self, addr, handler):
            super().__init__((addr[0], 0), handler)

    server.ThreadingHTTPServer = AnyPort
    try:
        httpd, app = server.build(cfg, TOKEN, make_gate(tmp_path, SERVER_TOOLS, "server"))
    finally:
        server.ThreadingHTTPServer = orig
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    port = httpd.server_address[1]
    client_gate = make_gate(tmp_path, {**SERVER_TOOLS, "server.connect": {"urls": [f"https://127.0.0.1:{port}"]}})
    yield Client(f"https://127.0.0.1:{port}", str(tmp_path / "data" / "bundle.pem"), TOKEN, client_gate), app, tmp_path
    httpd.shutdown()


def test_app_rejects_short_token(tmp_path):
    c = ca_mod.CertificateAuthority.create("test.local", dt.timedelta(hours=1))
    with pytest.raises(ValueError):
        server.App(c, None, "short", dt.timedelta(minutes=1), dt.timedelta(minutes=1), make_gate(tmp_path, {}, "server"))


def test_end_to_end(running):
    client, app, tmp_path = running
    sid = "spiffe://test.local/ai-agent/triage"

    # No entry, no identity.
    with pytest.raises(ServerError, match="403"):
        client.x509_svid(sid)

    # Bad token is refused.
    bad = Client(client.base, str(tmp_path / "data" / "bundle.pem"), "x" * 40, client.gate)
    with pytest.raises(ServerError, match="401"):
        bad.list_entries()

    # approved_by is mandatory.
    with pytest.raises(ServerError, match="approved_by"):
        client.create_entry({"spiffe_id": sid, "selectors": ["ai:agent-name:triage"]})

    e = client.create_entry({"spiffe_id": sid, "selectors": ["ai:agent-name:triage"], "source": "ai-agents",
                             "assigned_by": "policy:agents", "approved_by": "tester"})
    assert e["created"] is True
    again = client.create_entry({"spiffe_id": sid, "selectors": ["ai:agent-name:triage"], "source": "ai-agents",
                                 "assigned_by": "policy:agents", "approved_by": "tester"})
    assert again["created"] is False and again["id"] == e["id"]

    # Blocked on the agent side by its tool policy, before any request is sent.
    from spiffe_identity.toolpolicy import ToolDenied
    with pytest.raises(ToolDenied, match="outside the allowed SPIFFE ID prefixes"):
        client.create_entry({"spiffe_id": "spiffe://other.local/x", "selectors": ["a"], "approved_by": "t"})

    cert, key, bundle = client.x509_svid(sid)
    assert str(ca_mod.verify_x509_svid(cert, bundle)) == sid

    tok = client.jwt_svid(sid, ["ticket-api"])
    assert str(ca_mod.verify_jwt_svid(tok, app.ca.jwks(), "ticket-api")) == sid

    entries = client.list_entries()
    assert [x["spiffe_id"] for x in entries] == [sid]
    saved = json.loads((tmp_path / "data" / "entries.json").read_text())
    assert saved[0]["approved_by"] == "tester"
