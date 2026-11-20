import datetime as dt
import json
import os

import pytest

from spiffe_identity import ca as ca_mod, server
from spiffe_identity.registry import Registry
from spiffe_identity.toolpolicy import TOOLS, ToolDenied, ToolPolicy, ToolPolicyError, gate_from_config, origin
from spiffe_identity.trace import TraceError, read_events
from tests.helpers import events, make_gate

TOKEN = "t" * 40


def pol(tools, trace="t.jsonl"):
    return {"version": 1, "default": "deny", "trace": {"file": trace}, "tools": tools}


# ---- loading: fail closed --------------------------------------------------------

def test_missing_policy_file_blocks_everything(tmp_path):
    with pytest.raises(ToolPolicyError, match="deny-by-default"):
        ToolPolicy.load(tmp_path / "nope.json")


def test_config_without_policy_file_is_an_error(tmp_path):
    from spiffe_identity.config import ConfigError
    with pytest.raises(ConfigError, match="tool_policy_file is required"):
        gate_from_config({"_base_dir": str(tmp_path), "trust_domain": "x"}, "agent")


def test_world_writable_policy_refused(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(pol({})))
    os.chmod(f, 0o666)
    with pytest.raises(ToolPolicyError, match="writable by every user"):
        ToolPolicy.load(f)


@pytest.mark.parametrize("data, match", [
    ({"version": 1, "default": "allow", "trace": {"file": "t"}, "tools": {}}, "must be \"deny\""),
    ({"version": 2, "default": "deny", "trace": {"file": "t"}, "tools": {}}, "version"),
    ({"version": 1, "default": "deny", "tools": {}}, "trace"),
    ({"version": 1, "default": "deny", "trace": {"file": "t"}}, "tools"),
    ({**pol({}), "extra": 1}, "unknown top-level"),
    (pol({"discovery.kubernets.list_pods": {}}), "unknown tool"),
    (pol({"discovery.ai_agents.read_manifests": {}}), "required limit 'paths'"),
    (pol({"discovery.ai_agents.read_manifests": {"paths": ["a"], "depth": 3}}), "unknown limit"),
    (pol({"discovery.network.tcp_connect": {"cidrs": ["bad"], "ports": [80], "max_hosts": 1}}), "cidrs"),
    (pol({"discovery.processes.read": {"methods": ["procfs"]}}), "proc_roots is required"),
    (pol({"server.entries.create": {"spiffe_id_prefixes": ["http://x"]}}), "spiffe_id_prefixes"),
    (pol({"server.connect": {"urls": ["ftp://x"]}}), "urls"),
])
def test_invalid_policies_are_startup_errors(data, match):
    with pytest.raises(ToolPolicyError, match=match):
        ToolPolicy.from_dict(data)


def test_example_policies_are_valid():
    from pathlib import Path
    ex = Path(__file__).resolve().parent.parent / "examples"
    p = ToolPolicy.load(ex / "demo.tool-policy.json")
    assert "discovery.kubernetes.list_pods" not in p.tools  # not listed -> blocked
    for name in json.loads((ex / "tool-policy.template.json").read_text())["tools"]:
        assert name in TOOLS


# ---- decisions ---------------------------------------------------------------------

def test_unlisted_tool_denied_and_traced(tmp_path):
    g = make_gate(tmp_path, {})
    with pytest.raises(ToolDenied, match="not listed"):
        g.check("discovery.docker.list_containers", socket="/var/run/docker.sock")
    ev = events(g)[-1]
    assert ev["event"] == "action.decision" and ev["decision"] == "deny" and ev["tool"] == "discovery.docker.list_containers"


def test_path_limits_and_symlink_escape(tmp_path):
    allowed = tmp_path / "allowed"
    (allowed / "sub").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (allowed / "link").symlink_to(outside)
    g = make_gate(tmp_path, {"discovery.ai_agents.read_manifests": {"paths": [str(allowed)]}})
    g.check("discovery.ai_agents.read_manifests", path=str(allowed / "sub"))
    with pytest.raises(ToolDenied):
        g.check("discovery.ai_agents.read_manifests", path=str(outside))
    with pytest.raises(ToolDenied):  # a symlink inside the allowed folder can't reach outside it
        g.check("discovery.ai_agents.read_manifests", path=str(allowed / "link"))


def test_host_network_and_api_limits(tmp_path):
    g = make_gate(tmp_path, {
        "discovery.ai_agents.probe_a2a": {"origins": ["https://agents.example.com"]},
        "discovery.network.tcp_connect": {"cidrs": ["192.168.1.0/24"], "ports": [8080], "max_hosts": 256},
        "llm.propose_ids": {"models": ["claude-opus-5-5"], "api_origins": ["https://api.anthropic.com"],
                            "max_calls_per_run": 1, "send_attributes": ["kind"]},
    })
    g.check("discovery.ai_agents.probe_a2a", url="https://agents.example.com:443/.well-known/agent-card.json")
    for url in ("http://agents.example.com/x", "https://evil.example.com/x", "https://agents.example.com:8443/x"):
        with pytest.raises(ToolDenied):
            g.check("discovery.ai_agents.probe_a2a", url=url)
    g.check("discovery.network.tcp_connect", cidrs=["192.168.1.0/28"], ports=[8080], max_hosts=16)
    with pytest.raises(ToolDenied, match="range"):
        g.check("discovery.network.tcp_connect", cidrs=["10.0.0.0/28"], ports=[8080], max_hosts=16)
    with pytest.raises(ToolDenied, match="port"):
        g.check("discovery.network.tcp_connect", cidrs=["192.168.1.0/28"], ports=[22], max_hosts=16)
    with pytest.raises(ToolDenied, match="max_hosts"):
        g.check("discovery.network.tcp_connect", cidrs=["192.168.1.0/28"], ports=[8080], max_hosts=1000)
    args = dict(model="claude-opus-5-5", api_url="https://api.anthropic.com", send_attributes=["kind"])
    with pytest.raises(ToolDenied, match="attribute"):
        g.check("llm.propose_ids", **{**args, "send_attributes": ["cmdline"]})
    with pytest.raises(ToolDenied, match="API origin"):
        g.check("llm.propose_ids", **{**args, "api_url": "https://proxy.example.com"})
    g.check("llm.propose_ids", **args)
    with pytest.raises(ToolDenied, match="max_calls_per_run"):
        g.check("llm.propose_ids", **args)
    g.new_run()
    g.check("llm.propose_ids", **args)


def test_spiffe_prefix_is_segment_aware(tmp_path):
    g = make_gate(tmp_path, {"server.entries.create": {"spiffe_id_prefixes": ["spiffe://td/ai-agent"]}})
    g.check("server.entries.create", spiffe_id="spiffe://td/ai-agent/triage")
    with pytest.raises(ToolDenied):
        g.check("server.entries.create", spiffe_id="spiffe://td/ai-agent-evil/x")


def test_origin_normalisation():
    assert origin("HTTPS://Example.COM/path") == "https://example.com:443"
    assert origin("http://h:8080") == "http://h:8080"


# ---- tracing -------------------------------------------------------------------------

def test_action_traces_decision_result_and_run(tmp_path):
    g = make_gate(tmp_path, {"portal.scan": {}}, "portal", "Esra")
    with g.run("portal.scan") as tid:
        with g.action("portal.scan") as summary:
            summary["workloads"] = 3
    ev = events(g)
    assert [e["event"] for e in ev] == ["run.start", "action.decision", "action.result", "run.end"]
    assert {e["trace_id"] for e in ev} == {tid}
    assert ev[1]["span_id"] == ev[2]["span_id"]
    assert ev[2]["outcome"] == "ok" and ev[2]["summary"] == {"workloads": 3} and ev[2]["actor"] == "Esra"


def test_action_error_is_traced(tmp_path):
    g = make_gate(tmp_path, {"portal.scan": {}})
    with pytest.raises(RuntimeError):
        with g.action("portal.scan"):
            raise RuntimeError("boom")
    assert events(g)[-1]["outcome"] == "error" and "boom" in events(g)[-1]["error"]


def test_unwritable_trace_fails_closed(tmp_path):
    g = make_gate(tmp_path, {"portal.scan": {}})
    ran = []
    g.writer.path.unlink()
    g.writer.path.mkdir()  # a directory where the trace file should be: unwritable, even for root
    with pytest.raises(TraceError):
        with g.action("portal.scan"):
            ran.append(1)
    assert ran == []


def test_trace_never_contains_the_admin_token(tmp_path):
    srv_gate = make_gate(tmp_path, {"server.entries.list": {}}, "server")
    c = ca_mod.CertificateAuthority.create("test.local", dt.timedelta(hours=1))
    app = server.App(c, Registry(None, "test.local"), TOKEN, dt.timedelta(minutes=5), dt.timedelta(minutes=5), srv_gate)
    assert app.handle("GET", "/v1/entries", "Bearer " + TOKEN, b"")[0] == 200
    assert app.handle("GET", "/v1/entries", "Bearer wrong" + "x" * 40, b"")[0] == 401
    raw = srv_gate.writer.path.read_text()
    assert TOKEN not in raw
    denied = [e for e in read_events(srv_gate.writer.path) if e.get("tool") == "server.auth"]
    assert denied and denied[0]["decision"] == "deny"


def test_server_enforces_its_own_policy(tmp_path):
    """Even a caller with the admin token can't do what the server's policy doesn't allow."""
    srv_gate = make_gate(tmp_path, {"server.entries.list": {},
                                    "server.entries.create": {"spiffe_id_prefixes": ["spiffe://test.local/ai-agent/"]}}, "server")
    c = ca_mod.CertificateAuthority.create("test.local", dt.timedelta(hours=1))
    app = server.App(c, Registry(None, "test.local"), TOKEN, dt.timedelta(minutes=5), dt.timedelta(minutes=5), srv_gate)
    auth = "Bearer " + TOKEN
    body = lambda sid: json.dumps({"spiffe_id": sid, "selectors": ["a:b"], "approved_by": "me"}).encode()
    assert app.handle("POST", "/v1/entries", auth, body("spiffe://test.local/ai-agent/x"))[0] == 201
    status, _, out = app.handle("POST", "/v1/entries", auth, body("spiffe://test.local/admin/x"))
    assert status == 403 and b"blocked by tool policy" in out
    assert app.handle("DELETE", "/v1/entries/abc", auth, b"")[0] == 403  # delete not listed
    assert app.handle("POST", "/v1/svid/jwt", auth, json.dumps({"spiffe_id": "spiffe://test.local/ai-agent/x", "audience": ["a"]}).encode())[0] == 403


def test_server_joins_callers_trace(tmp_path):
    srv_gate = make_gate(tmp_path, {"server.entries.list": {}}, "server")
    c = ca_mod.CertificateAuthority.create("test.local", dt.timedelta(hours=1))
    app = server.App(c, Registry(None, "test.local"), TOKEN, dt.timedelta(minutes=5), dt.timedelta(minutes=5), srv_gate)
    tid = "ab" * 16
    app.handle("GET", "/v1/entries", "Bearer " + TOKEN, b"", trace_id=tid)
    assert {e["trace_id"] for e in read_events(srv_gate.writer.path)} == {tid}
    app.handle("GET", "/v1/entries", "Bearer " + TOKEN, b"", trace_id="not-a-trace-id")
    assert read_events(srv_gate.writer.path)[-1]["trace_id"] != "not-a-trace-id"


def test_discovery_respects_policy(tmp_path):
    from pathlib import Path
    from spiffe_identity import discovery
    ex = Path(__file__).resolve().parent.parent / "examples" / "manifests"
    g = make_gate(tmp_path, {"discovery.ai_agents.read_manifests": {"paths": [str(ex / "triage-agent")]}})
    results = discovery.run(discovery.build({
        "ai_agents": {"manifest_dirs": [str(ex / "triage-agent"), str(ex / "dev-tools")], "max_depth": 2},
        "docker": {"socket": "/var/run/docker.sock", "timeout_seconds": 1},
    }, g))
    ai, dock = results
    assert [w.name for w in ai.workloads] == ["Ticket Triage Agent"]          # allowed folder only
    assert any("blocked by tool policy" in w for w in ai.warnings)              # dev-tools denied
    assert "blocked by tool policy" in dock.error                               # docker not listed
