import io
import json
from types import SimpleNamespace

import pytest

from spiffe_identity import approval
from spiffe_identity.classifier import ClaudeProposer, LLMError
from spiffe_identity.discovery.base import Workload
from spiffe_identity.policy import Policy, PolicyError

TD = "test.local"
RULES = {"rules": [
    {"name": "agents", "match": {"kind": "ai-agent"}, "spiffe_id_path": "/ai-agent/{name}"},
    {"name": "pods", "match": {"kind": "k8s-pod", "attributes": {"namespace": "agent*"}},
     "spiffe_id_path": "/k8s/ns/{attr.namespace}/sa/{attr.service_account}"},
]}


def wl(kind, name="x", **attrs):
    return Workload(source="s", kind=kind, name=name, attributes=attrs, selectors=[f"s:{name}"])


def test_policy_assigns_first_match():
    p = Policy.from_config(TD, RULES)
    r = p.assign(wl("ai-agent", "Ticket Triage Agent"))
    assert r.spiffe_id == "spiffe://test.local/ai-agent/Ticket-Triage-Agent" and r.assigned_by == "policy:agents"
    r = p.assign(wl("k8s-pod", namespace="agents", service_account="triage"))
    assert r.spiffe_id == "spiffe://test.local/k8s/ns/agents/sa/triage"


def test_policy_never_invents_missing_values():
    p = Policy.from_config(TD, RULES)
    r = p.assign(wl("k8s-pod", namespace="agents", service_account=""))
    assert r.spiffe_id is None and "service_account" in r.problems[0]
    r = p.assign(wl("container"))
    assert r.spiffe_id is None and r.problems == ["no policy rule matched"]


def test_policy_validation():
    with pytest.raises(PolicyError):
        Policy.from_config(TD, {"rules": [{"name": "a", "match": {}, "spiffe_id_path": "no-slash"}]})
    with pytest.raises(PolicyError):
        Policy.from_config(TD, {})


class FakeClient:
    def __init__(self, text, stop_reason="end_turn"):
        self.sent = None
        self._resp = SimpleNamespace(stop_reason=stop_reason, model="claude-opus-5-5",
                                     content=[SimpleNamespace(type="text", text=text)])
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.sent = kw
        return self._resp


def test_llm_requires_explicit_attribute_allowlist():
    with pytest.raises(LLMError, match="send_attributes"):
        ClaudeProposer(TD, {}, client=FakeClient("{}"))


def test_llm_only_sends_allowlisted_attributes_and_validates():
    props = [Policy.from_config(TD, RULES).assign(wl("container", "a", image="nginx", cmdline="secret --token=abc")),
             Policy.from_config(TD, RULES).assign(wl("container", "b")),
             Policy.from_config(TD, RULES).assign(wl("container", "c"))]
    answer = {"proposals": [
        {"index": 0, "insufficient_data": False, "path_segments": ["container", "nginx"], "confidence": "high", "rationale": "image"},
        {"index": 1, "insufficient_data": True, "path_segments": [], "confidence": "low", "rationale": "no attributes"},
        {"index": 2, "insufficient_data": False, "path_segments": ["..", "x"], "confidence": "low", "rationale": "bad"},
    ]}
    client = FakeClient(json.dumps(answer))
    ClaudeProposer(TD, {"send_attributes": ["image"]}, client=client).propose(props)
    user_msg = client.sent["messages"][0]["content"]
    assert "nginx" in user_msg and "secret" not in user_msg
    assert props[0].spiffe_id == "spiffe://test.local/container/nginx" and props[0].assigned_by.startswith("llm:")
    assert props[1].spiffe_id is None and "insufficient" in props[1].problems[-1]
    assert props[2].spiffe_id is None and "invalid" in props[2].problems[-1]


def test_llm_refusal_is_an_error():
    props = [Policy.from_config(TD, RULES).assign(wl("container"))]
    with pytest.raises(LLMError):
        ClaudeProposer(TD, {"send_attributes": []}, client=FakeClient("", stop_reason="refusal")).propose(props)


def test_approval_gate():
    p = Policy.from_config(TD, RULES)
    props = [p.assign(wl("ai-agent", "a")), p.assign(wl("ai-agent", "b")), p.assign(wl("container"))]
    answers = iter(["y", "n"])
    approved = approval.gate(props, ask=lambda _: next(answers), out=io.StringIO())
    assert [a.workload.name for a in approved] == ["a"]
    answers = iter(["maybe", "q"])
    assert approval.gate(props, ask=lambda _: next(answers), out=io.StringIO()) == []
    assert len(approval.gate(props, approve_all=True, out=io.StringIO())) == 2
