"""Test helpers: build a real ToolGate from an in-memory policy that writes to a temp trace."""

from spiffe_identity.toolpolicy import ToolGate, ToolPolicy
from spiffe_identity.trace import TraceWriter, read_events


def make_gate(tmp_path, tools: dict, component: str = "agent", actor: str = "") -> ToolGate:
    trace = tmp_path / "trace.jsonl"
    policy = ToolPolicy.from_dict({"version": 1, "default": "deny", "trace": {"file": str(trace)}, "tools": tools})
    return ToolGate(policy, TraceWriter(trace, component), actor)


def events(gate: ToolGate) -> list[dict]:
    return read_events(gate.writer.path)
