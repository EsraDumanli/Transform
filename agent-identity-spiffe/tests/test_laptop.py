"""The laptop config and policy, run against a fake home folder (no real files are read)."""

import json
from pathlib import Path

from spiffe_identity import config as config_mod, pipeline
from spiffe_identity.discovery.ai_agents import _safe_url, parse_mcp_file
from spiffe_identity.toolpolicy import ToolGate, ToolPolicy
from spiffe_identity.trace import TraceWriter

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Library/Application Support/Claude").mkdir(parents=True)
    (home / "Library/Application Support/Claude/claude_desktop_config.json").write_text(json.dumps({
        "mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/x"]}}}))
    (home / ".claude.json").write_text(json.dumps({
        "numStartups": 12, "oauthAccount": {"emailAddress": "someone@example.com"},     # unrelated data: must not be kept
        "mcpServers": {"github": {"type": "http", "url": "https://api.example.com/mcp?token=SECRET123"}},
        "projects": {"/Users/x/Transform": {"mcpServers": {"tickets": {"command": "uvx", "args": ["tickets-mcp"],
                                                                        "env": {"API_KEY": "SECRET456"}}}}}}))
    monkeypatch.setenv("HOME", str(home))
    return home


def test_claude_code_file_user_and_project_servers(tmp_path, monkeypatch):
    home = fake_home(tmp_path, monkeypatch)
    ws = {w.name: w for w in parse_mcp_file(home / ".claude.json")}
    assert ws["github"].attributes["scope"] == "user" and ws["github"].attributes["transport"] == "http"
    assert ws["tickets"].attributes["scope"] == "project" and ws["tickets"].attributes["project"] == "/Users/x/Transform"
    assert "ai:mcp-project:/Users/x/Transform" in ws["tickets"].selectors
    dumped = json.dumps([w.to_dict() for w in ws.values()])
    assert "SECRET" not in dumped and "someone@example.com" not in dumped        # tokens and account data never kept


def test_safe_url_drops_query_and_credentials():
    assert _safe_url("https://user:pw@h.example.com:8443/mcp?token=abc#x") == "https://h.example.com:8443/mcp"


def test_laptop_config_finds_local_agents_and_reads_nothing_else(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    cfg = config_mod.load(EXAMPLES / "laptop.config.json")
    policy = ToolPolicy.load(EXAMPLES / "laptop.tool-policy.json")     # loaded after HOME is set: ~ is the fake home
    gate = ToolGate(policy, TraceWriter(tmp_path / "trace.jsonl", "agent"))
    cfg["discovery"].pop("processes")                                  # don't depend on this machine's processes
    scan = pipeline.plan(cfg, gate, use_llm=False)
    found = {p.workload.name: p for p in scan.proposals}
    demo = {"Ticket Triage Agent", "ticket-api", "notes-search"}         # demo fixtures, labelled
    assert set(found) == {"github", "tickets", "Job Search Agent"} | demo | {"filesystem"}
    assert found["Job Search Agent"].spiffe_id == "spiffe://demo.local/ai-agent/Job-Search-Agent"
    assert all(found[n].workload.attributes.get("label") == "demo" for n in demo)
    assert "label" not in found["github"].workload.attributes and "label" not in found["tickets"].workload.attributes
    assert found["github"].spiffe_id == "spiffe://demo.local/mcp/http/github"
    assert found["tickets"].spiffe_id == "spiffe://demo.local/mcp/stdio/tickets"
    trace = (tmp_path / "trace.jsonl").read_text()
    assert "SECRET" not in trace


def test_laptop_policy_blocks_other_folders(tmp_path, monkeypatch):
    fake_home(tmp_path, monkeypatch)
    policy = ToolPolicy.load(EXAMPLES / "laptop.tool-policy.json")
    assert policy.decide("discovery.ai_agents.read_manifests", {"path": str(Path.home() / ".claude.json")}) is None
    assert policy.decide("discovery.ai_agents.read_manifests", {"path": str(Path.home() / ".ssh/config")}) is not None
    assert policy.decide("discovery.docker.list_containers", {"socket": "/var/run/docker.sock"}) is not None


def test_per_folder_depth_and_label(tmp_path, monkeypatch):
    from spiffe_identity.discovery import AIAgents
    from spiffe_identity.discovery.base import ConfigError
    import pytest
    from tests.helpers import make_gate
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "agent-card.json").write_text(json.dumps({"name": "Deep", "url": "https://d"}))
    gate = make_gate(tmp_path, {"discovery.ai_agents.read_manifests": {"paths": [str(tmp_path)]}})
    assert AIAgents({"manifest_dirs": [{"path": str(tmp_path), "max_depth": 1}]}, gate).discover()[0] == []
    ws, _ = AIAgents({"manifest_dirs": [{"path": str(tmp_path), "max_depth": 3, "label": "demo"}]}, gate).discover()
    assert [(w.name, w.attributes["label"]) for w in ws] == [("Deep", "demo")]
    with pytest.raises(ConfigError, match="max_depth"):
        AIAgents({"manifest_dirs": [{"path": str(tmp_path)}]}, gate)
    with pytest.raises(ConfigError, match="unknown key"):
        AIAgents({"manifest_dirs": [{"path": str(tmp_path), "max_depth": 1, "depth": 2}]}, gate)


def test_job_search_agent_card_and_process_merge_into_one_agent(tmp_path):
    from spiffe_identity import discovery
    from spiffe_identity.discovery.base import Result, Workload
    from spiffe_identity.nodes import attestation_method
    card_dir = (EXAMPLES / "../../job-search-agent").resolve()
    from spiffe_identity.discovery.ai_agents import parse_a2a_file
    card = parse_a2a_file(card_dir / "agent-card.json")
    assert card.name == "Job Search Agent" and "url" not in card.attributes       # no fake A2A endpoint
    proc = Workload(source="processes", kind="process", name="Python[3722]",
                    attributes={"pid": "3722", "uid": "501", "comm": "Python", "cmdline": "Python app.py",
                                "exe": "/opt/homebrew/Cellar/python@3.12/3.12.14/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python",
                                "cwd": str(card_dir)},
                    selectors=["unix:uid:501", "unix:comm:Python", f"unix:cwd:{card_dir}",
                               "unix:path:/opt/homebrew/Cellar/python@3.12/3.12.14/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python"])
    other = Workload(source="processes", kind="process", name="Python[9]", attributes={"cwd": "/elsewhere"}, selectors=["unix:comm:Python"])
    results = [Result("ai-agents", [card]), Result("processes", [proc, other])]
    notes = pipeline.correlate(results)
    assert [w.name for w in results[1].workloads] == ["Python[9]"]                 # merged process removed
    merged = results[0].workloads[0]
    assert merged.kind == "ai-agent" and merged.attributes["running"] == "yes" and merged.attributes["pid"] == "3722"
    assert f"unix:cwd:{card_dir}" in merged.selectors and notes
    assert merged.source == "ai-agents" and merged.attributes["also_seen_by"] == "processes"
    assert attestation_method(merged.selectors) == "process-name"                  # interpreter path doesn't count


def test_cwd_is_recorded_on_macos_ps(tmp_path):
    from spiffe_identity.discovery import Processes
    from tests.helpers import make_gate
    out = {"pid=,uid=,comm=": "  3722   501 /opt/homebrew/bin/python3.12\n", "pid=,args=": "  3722 python3.12 app.py\n"}
    gate = make_gate(tmp_path, {"discovery.processes.read": {"methods": ["ps"]}})
    ws, _ = Processes({"method": "ps", "include": ["python*"], "cmdline_contains": ["app.py"]}, gate,
                      run_ps=lambda f: out[f], run_cwd=lambda pid: "/Users/x/Transform/job-search-agent").discover()
    assert ws[0].attributes["cwd"] == "/Users/x/Transform/job-search-agent"
    assert "unix:cwd:/Users/x/Transform/job-search-agent" in ws[0].selectors
