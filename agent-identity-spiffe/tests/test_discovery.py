import io
import json
from pathlib import Path

import pytest

from spiffe_identity import discovery
from spiffe_identity.discovery import AIAgents, ConfigError, Docker, Kubernetes, Network, Processes
from spiffe_identity.discovery.network import expand

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "manifests"


def test_ai_agents_requires_explicit_targets():
    with pytest.raises(ConfigError):
        AIAgents({})
    with pytest.raises(ConfigError, match="max_depth"):
        AIAgents({"manifest_dirs": ["."]})
    with pytest.raises(ConfigError, match="timeout"):
        AIAgents({"a2a_urls": ["http://x"]})


def test_ai_agents_finds_demo_fixtures():
    ws, warns = AIAgents({"manifest_dirs": [str(EXAMPLES)], "max_depth": 3}).discover()
    by_name = {w.name: w for w in ws}
    assert by_name["Ticket Triage Agent"].kind == "ai-agent"
    assert by_name["Ticket Triage Agent"].attributes["skills"] == "classify-ticket,route-ticket"
    assert by_name["filesystem"].attributes["transport"] == "stdio"
    assert "args" not in by_name["filesystem"].attributes  # args are never copied
    assert by_name["ticket-api"].attributes["transport"] == "http"
    assert "transport" not in by_name["notes-search"].attributes
    assert warns == []


def test_ai_agents_ignores_non_card_agent_json(tmp_path):
    (tmp_path / "agent.json").write_text(json.dumps({"some": "other format"}))
    ws, _ = AIAgents({"manifest_dirs": [str(tmp_path)], "max_depth": 1}).discover()
    assert ws == []


def test_ai_agents_max_depth(tmp_path):
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "agent-card.json").write_text(json.dumps({"name": "x", "url": "https://x"}))
    assert AIAgents({"manifest_dirs": [str(tmp_path)], "max_depth": 2}).discover()[0] == []
    assert len(AIAgents({"manifest_dirs": [str(tmp_path)], "max_depth": 3}).discover()[0]) == 1


def test_ai_agents_probe():
    calls = []

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(url, timeout):
        calls.append(url)
        if url.endswith("agent-card.json"):
            raise OSError("404")
        return Resp(json.dumps({"name": "Remote", "url": "https://r", "skills": []}).encode())

    ws, warns = AIAgents({"a2a_urls": ["https://r/"], "timeout_seconds": 1}, opener=opener).discover()
    assert [w.name for w in ws] == ["Remote"] and warns == []
    assert calls == ["https://r/.well-known/agent-card.json", "https://r/.well-known/agent.json"]


def test_kubernetes(tmp_path):
    tok = tmp_path / "token"
    tok.write_text("t0k\n")
    pods = {"items": [{
        "metadata": {"name": "triage-7f", "namespace": "agents", "uid": "u1", "labels": {"app": "triage"}},
        "spec": {"serviceAccountName": "triage-sa", "nodeName": "n1", "containers": [{"name": "c", "image": "triage:1"}]},
        "status": {"phase": "Running"},
    }]}
    seen = {}

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        seen["url"], seen["auth"] = req.full_url, req.headers["Authorization"]
        return Resp(json.dumps(pods).encode())

    k = Kubernetes({"api_server": "https://k:6443", "token_file": str(tok), "ca_file": "x", "namespaces": ["agents"],
                    "timeout_seconds": 1, "label_selector_keys": ["app"]}, opener=opener)
    ws, warns = k.discover()
    assert seen == {"url": "https://k:6443/api/v1/namespaces/agents/pods", "auth": "Bearer t0k"}
    assert ws[0].selectors == ["k8s:ns:agents", "k8s:sa:triage-sa", "k8s:pod-label:app:triage"]
    assert ws[0].attributes["label.app"] == "triage"


def test_kubernetes_requires_namespaces_and_connection():
    with pytest.raises(ConfigError, match="namespaces"):
        Kubernetes({"timeout_seconds": 1, "api_server": "x", "token_file": "x", "ca_file": "x"})
    with pytest.raises(ConfigError, match="api_server"):
        Kubernetes({"timeout_seconds": 1, "namespaces": ["a"]})


def test_processes_with_fake_procfs(tmp_path):
    def proc(pid, comm, uid, cmd):
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "comm").write_text(comm + "\n")
        (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (d / "cmdline").write_bytes(cmd.replace(" ", "\0").encode())
    proc(10, "python3", 1000, "python3 -m google.adk run agent")
    proc(11, "python3", 1000, "python3 manage.py runserver")
    proc(12, "bash", 0, "bash")
    (tmp_path / "self").mkdir()
    ws, warns = Processes({"method": "procfs", "proc_root": str(tmp_path), "include": ["python*"], "cmdline_contains": ["google.adk"]}).discover()
    assert [w.name for w in ws] == ["python3[10]"]
    assert "unix:uid:1000" in ws[0].selectors
    assert any("executable path" in w for w in warns)  # fake procfs has no exe link


def test_processes_requires_method_include_and_proc_root():
    with pytest.raises(ConfigError, match="method"):
        Processes({"proc_root": "/proc", "include": ["x"]})
    with pytest.raises(ConfigError, match="include"):
        Processes({"method": "ps"})
    with pytest.raises(ConfigError, match="proc_root"):
        Processes({"method": "procfs", "include": ["x"]})


def test_processes_procfs_missing_root_mentions_ps(tmp_path):
    with pytest.raises(OSError, match='"ps"'):
        Processes({"method": "procfs", "proc_root": str(tmp_path / "nope"), "include": ["x"]}).discover()


def test_processes_ps_macos_output():
    # Shaped like macOS ps: comm is the full executable path and may contain spaces.
    outputs = {
        "pid=,uid=,comm=": (
            "  101   501 /opt/homebrew/Cellar/python@3.12/3.12.7/bin/python3.12\n"
            "  102   501 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"
            "  103     0 /usr/libexec/logd\n"
            "  104   501 python3\n"
        ),
        "pid=,args=": (
            "  101 python3.12 -m google.adk.cli run agent\n"
            "  102 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"
            "  103 /usr/libexec/logd\n"
            "  104 python3 -m google.adk.cli web\n"
        ),
    }
    p = Processes({"method": "ps", "include": ["python*", "Google Chrome"], "cmdline_contains": ["google.adk"]},
                  run_ps=lambda f: outputs[f])
    ws, warns = p.discover()
    by_pid = {w.attributes["pid"]: w for w in ws}
    assert sorted(by_pid) == ["101", "104"]  # Chrome matches include but not cmdline_contains
    assert by_pid["101"].attributes["comm"] == "python3.12"
    assert "unix:path:/opt/homebrew/Cellar/python@3.12/3.12.7/bin/python3.12" in by_pid["101"].selectors
    assert "exe" not in by_pid["104"].attributes
    assert any("absolute executable path" in w for w in warns)


def test_processes_ps_on_this_machine():
    import shutil
    if not shutil.which("ps"):
        pytest.skip("no ps binary")
    ws, _ = Processes({"method": "ps", "include": ["python*", "Python*"]}).discover()  # macOS framework builds run as "Python"
    assert any(w.attributes["pid"] == str(__import__("os").getpid()) for w in ws)


def test_build_resolves_docker_socket_home():
    d = discovery.build({"docker": {"socket": "~/.docker/run/docker.sock", "timeout_seconds": 1}},
                        resolve=lambda p: str(Path(p).expanduser()))[0]
    assert d.socket == str(Path.home() / ".docker/run/docker.sock")


def test_docker():
    data = [{"Id": "abc", "Names": ["/triage"], "Image": "triage:1", "ImageID": "sha256:1", "State": "running",
             "Labels": {"com.docker.compose.service": "triage"}}]
    d = Docker({"socket": "/x.sock", "timeout_seconds": 1, "label_selector_keys": ["com.docker.compose.service"]}, fetch=lambda: data)
    ws, _ = d.discover()
    assert ws[0].name == "triage"
    assert ws[0].selectors == ["docker:image_id:sha256:1", "docker:label:com.docker.compose.service:triage"]


def test_network_limits_and_scan():
    with pytest.raises(ConfigError):
        Network({"cidrs": ["10.0.0.0/24"], "ports": [80], "timeout_ms": 10, "max_hosts": 10, "concurrency": 1})
    with pytest.raises(ConfigError):
        Network({"cidrs": ["10.0.0.0/30"], "ports": [], "timeout_ms": 10, "max_hosts": 10, "concurrency": 1})
    assert expand(["10.0.0.0/30"], 4) == ["10.0.0.1", "10.0.0.2"]
    n = Network({"cidrs": ["10.0.0.0/30"], "ports": [80, 443], "timeout_ms": 10, "max_hosts": 4, "concurrency": 2},
                connect=lambda h, p: (h, p) == ("10.0.0.2", 443))
    ws, _ = n.discover()
    assert [w.selectors for w in ws] == [["net:addr:10.0.0.2:443"]]


def test_build_rejects_unknown_source():
    with pytest.raises(ConfigError, match="unknown"):
        discovery.build({"kubernets": {}})


def test_run_isolates_failures():
    class Boom:
        name = "boom"

        def discover(self):
            raise RuntimeError("nope")

    class Ok:
        name = "ok"

        def discover(self):
            return [], ["w"]

    r = discovery.run([Boom(), Ok()])
    assert r[0].error.startswith("RuntimeError") and r[1].warnings == ["w"]


def test_build_resolves_paths_relative_to_config():
    ds = discovery.build({"ai_agents": {"manifest_dirs": ["manifests"], "max_depth": 3}},
                         resolve=lambda p: str(EXAMPLES.parent / p))
    ws, warns = discovery.run(ds)[0].workloads, discovery.run(ds)[0].warnings
    assert len(ws) == 4 and warns == []
