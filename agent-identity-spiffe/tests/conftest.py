from pathlib import Path

import pytest

from tests.helpers import make_gate

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture()
def gate(tmp_path):
    """A gate whose policy allows what the discovery tests exercise (and nothing else)."""
    return make_gate(tmp_path, {
        "discovery.ai_agents.read_manifests": {"paths": [str(EXAMPLES), str(tmp_path)]},
        "discovery.ai_agents.probe_a2a": {"origins": ["https://r"]},
        "discovery.kubernetes.list_pods": {"api_servers": ["https://k:6443"], "namespaces": ["agents"]},
        "discovery.docker.list_containers": {"sockets": ["/x.sock", "~/.docker/run/docker.sock"]},
        "discovery.processes.read": {"methods": ["ps", "procfs"], "proc_roots": [str(tmp_path), "/proc"]},
        "discovery.network.tcp_connect": {"cidrs": ["10.0.0.0/24"], "ports": [80, 443], "max_hosts": 256},
    })
