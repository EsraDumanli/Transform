"""
The triage orchestrator -- the "Act / Plan" part of the agent loop from the
guide, and the box labeled "Triage Orchestrator" in the reference
architecture diagram. Two interchangeable brains behind one interface:

  - rule_based_triage(): the "crawl" rung. Plain scoring logic, no LLM
    calls, deterministic. This is what runs by default.
  - MultiAgentTriage: the "run" rung. Three least-privileged specialist
    agents (identity, network, policy) investigate in parallel, each with
    a Claude tool-use loop scoped to exactly one read-only lookup tool --
    the API call itself never carries the other two domains' tool
    schemas, so there's nothing for the model to misuse even if it wanted
    to. A fourth agent, the orchestrator, has no tools at all: it receives
    all three specialists' findings and correlates them into one
    cross-domain root cause and recommendation. Runs automatically when
    ANTHROPIC_API_KEY is set and the anthropic package is installed;
    falls back to rule-based otherwise.

No agent in this file is allowed to call a mutating action -- all of them
only ever produce read-only lookups or a Recommendation. main.py is the
only thing that, after the human gate, calls tools.ACTIONS[...].
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from correlator import Incident
from tools import (
    ACTION_NEEDS_APPROVAL,
    IDENTITY_TOOL_SCHEMAS, IDENTITY_TOOLS,
    NETWORK_TOOL_SCHEMAS, NETWORK_TOOLS,
    POLICY_TOOL_SCHEMAS, POLICY_TOOLS,
    identity_lookup, network_lookup,
)

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
MAX_TOOL_TURNS = 4


@dataclass
class SpecialistFinding:
    domain: str          # "identity" | "network" | "policy"
    risk_level: str      # "low" | "medium" | "high"
    summary: str
    key_signals: list[str]


@dataclass
class Recommendation:
    tier: str
    confidence: float
    rationale: str
    suggested_action: str
    needs_approval: bool
    source: str                                          # "rule_based" | "llm"
    root_cause: str = ""                                  # multi-agent path only
    specialist_findings: list[SpecialistFinding] = field(default_factory=list)


def _incident_prompt(incident: Incident) -> str:
    lines = [f"Incident {incident.incident_id} -- entity: {incident.entity}",
              "Anomaly signals from the ML detection layer:"]
    for s in incident.signals:
        lines.append(f"  - [{s.source}] score={s.score:.2f} :: {s.detail}")
    return "\n".join(lines)


def _extract_json(content) -> dict:
    text = "".join(b.text for b in content if getattr(b, "type", None) == "text").strip()
    text = text.strip("`")
    if text.lower().startswith("json"):
        text = text[4:].strip()
    return json.loads(text)


def rule_based_triage(incident: Incident) -> Recommendation:
    """Deterministic scoring -- no LLM. This is the crawl rung: get the
    pipeline and the gate right before handing decisions to a model."""
    num_sources = len(incident.sources)
    identity = identity_lookup(incident.entity)
    network = network_lookup(incident.entity)

    risk_weight = {"low": 0, "medium": 1, "high": 2}
    score = num_sources
    score += risk_weight.get(identity.get("risk_level", "low"), 0)
    score += 1 if network.get("reputation") == "suspicious" else 0
    score += 1 if incident.max_score >= 3.0 else 0

    if score >= 5:
        tier, action = "critical", "quarantine_session"
    elif score >= 3:
        tier, action = "high", "adjust_policy"
    else:
        tier, action = "moderate", "open_ticket"

    confidence = min(0.95, 0.45 + 0.12 * num_sources + 0.08 * score)
    sources_desc = ", ".join(sorted(incident.sources))
    rationale = (
        f"{num_sources} independent detector(s) flagged this entity ({sources_desc}); "
        f"identity risk={identity.get('risk_level')}, network reputation={network.get('reputation')}. "
        f"Combined score {score} -> {tier}."
    )

    return Recommendation(tier, confidence, rationale, action,
                           needs_approval=ACTION_NEEDS_APPROVAL[action], source="rule_based")


class SpecialistAgent:
    """Base class for a single-domain Claude tool-use loop. Least privilege
    by construction: every `messages.create` call this makes carries only
    this specialist's own tool schema in `tools=`. The model can't request
    another domain's lookup because it was never told the tool exists --
    that's an actual capability boundary, not a prompt-level instruction
    the model could ignore."""

    domain: str = ""
    tool_schemas: list[dict] = []
    tools: dict = {}

    def __init__(self, client):
        self._client = client

    def _system_prompt(self) -> str:
        tool_names = ", ".join(self.tools)
        return (
            f"You are the {self.domain} specialist on a SASE triage team. You investigate ONE "
            f"domain -- {self.domain} -- and nothing else. Your only tool is {tool_names}; you have "
            f"no visibility into the other domains' data and should not speculate about them.\n\n"
            f"You'll be given a security incident: an entity plus the ML anomaly signals raised "
            f"about it. Use your tool to pull {self.domain} context for that entity, then report "
            f"ONLY what your own domain shows.\n\n"
            "Respond with ONLY a JSON object (no markdown fences, no other text):\n"
            '{"risk_level": "low"|"medium"|"high", '
            '"summary": "<1-2 sentences: what your lookup showed and whether it corroborates the anomaly>", '
            '"key_signals": ["<short fact from your lookup>", ...]}'
        )

    def investigate(self, incident: Incident) -> SpecialistFinding:
        messages = [{"role": "user", "content": _incident_prompt(incident)}]

        for _ in range(MAX_TOOL_TURNS):
            resp = self._client.messages.create(
                model=MODEL, max_tokens=512, system=self._system_prompt(),
                tools=self.tool_schemas, messages=messages,
            )
            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason != "tool_use":
                data = _extract_json(resp.content)
                return SpecialistFinding(
                    domain=self.domain, risk_level=data["risk_level"],
                    summary=data["summary"], key_signals=list(data.get("key_signals", [])),
                )

            tool_results = []
            for block in resp.content:
                if block.type == "tool_use":
                    fn = self.tools.get(block.name)
                    result = fn(**block.input) if fn else {"error": f"unknown tool {block.name}"}
                    tool_results.append({
                        "type": "tool_result", "tool_use_id": block.id,
                        "content": json.dumps(result),
                    })
            messages.append({"role": "user", "content": tool_results})

        raise RuntimeError(f"{self.domain} specialist did not converge within MAX_TOOL_TURNS")


class IdentitySpecialist(SpecialistAgent):
    domain = "identity"
    tool_schemas = IDENTITY_TOOL_SCHEMAS
    tools = IDENTITY_TOOLS


class NetworkSpecialist(SpecialistAgent):
    domain = "network"
    tool_schemas = NETWORK_TOOL_SCHEMAS
    tools = NETWORK_TOOLS


class PolicySpecialist(SpecialistAgent):
    domain = "policy"
    tool_schemas = POLICY_TOOL_SCHEMAS
    tools = POLICY_TOOLS


ORCHESTRATOR_SYSTEM_PROMPT = """You are the triage orchestrator for a SASE security operations pipeline.
You have no tools and cannot look anything up yourself -- three specialist agents (identity,
network, policy) have each already investigated this incident independently, blind to each other's
findings and to any data outside their own domain. Your job is to correlate their reports into a
single cross-domain root cause and one recommendation. You can never take an action yourself.

Look for the story that connects the domains -- e.g. an identity risk that a network signal
corroborates, or a policy gap that explains why the anomaly was possible in the first place. A
critical/high call should be backed by agreement across at least two domains, not one specialist's
opinion alone.

Respond with ONLY a JSON object (no markdown fences, no other text) of this exact shape:
{"root_cause": "<1-2 sentences connecting findings across domains into one explanation>",
 "tier": "critical"|"high"|"moderate", "confidence": <0.0-1.0>,
 "rationale": "<2-3 sentences citing the specific specialist findings that drove this call>",
 "suggested_action": "quarantine_session"|"adjust_policy"|"open_ticket"}

Stay honest about weak evidence -- moderate + open_ticket is the right call when specialists
disagree or the signals don't clearly point to a live threat. Reserve quarantine_session for cases
where at least two domains corroborate real risk, not just a single statistical outlier."""


class MultiAgentTriage:
    """The `run` rung: three least-privileged specialists investigate their
    own domain in parallel, then a tool-less orchestrator correlates their
    findings into one recommendation. Only instantiated when an API key is
    present; see `build_triage_agent()` for the fallback logic."""

    def __init__(self):
        import anthropic  # deferred import so the module is optional
        self._client = anthropic.Anthropic()
        self._specialists = [
            IdentitySpecialist(self._client),
            NetworkSpecialist(self._client),
            PolicySpecialist(self._client),
        ]

    def triage(self, incident: Incident) -> Recommendation:
        with ThreadPoolExecutor(max_workers=len(self._specialists)) as pool:
            findings = list(pool.map(lambda s: s.investigate(incident), self._specialists))

        findings_prompt = "\n\n".join(
            f"[{f.domain} specialist] risk_level={f.risk_level}\n"
            f"summary: {f.summary}\n"
            f"key_signals: {', '.join(f.key_signals) or '(none)'}"
            for f in findings
        )
        messages = [{
            "role": "user",
            "content": f"{_incident_prompt(incident)}\n\nSpecialist findings:\n\n{findings_prompt}",
        }]
        resp = self._client.messages.create(
            model=MODEL, max_tokens=1024, system=ORCHESTRATOR_SYSTEM_PROMPT, messages=messages,
        )
        data = _extract_json(resp.content)
        action = data["suggested_action"]
        return Recommendation(
            tier=data["tier"], confidence=float(data["confidence"]), rationale=data["rationale"],
            suggested_action=action, needs_approval=ACTION_NEEDS_APPROVAL[action], source="llm",
            root_cause=data["root_cause"], specialist_findings=findings,
        )


def build_triage_agent():
    """Returns a callable incident -> Recommendation. Uses the multi-agent
    specialist/orchestrator path when ANTHROPIC_API_KEY is set and the
    anthropic package imports cleanly; otherwise returns the rule-based
    function so the pipeline still runs end to end."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            multi_agent = MultiAgentTriage()
            return multi_agent.triage, "llm"
        except Exception as e:  # missing package, bad key, network -- fall back, don't crash the demo
            print(f"  (LLM triage unavailable ({e}); falling back to rule-based)")
    return rule_based_triage, "rule_based"
