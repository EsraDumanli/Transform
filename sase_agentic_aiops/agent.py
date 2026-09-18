"""
The triage orchestrator -- the "Act / Plan" part of the agent loop from the
guide, and the box labeled "Triage Orchestrator" in the reference
architecture diagram. Two interchangeable brains behind one interface:

  - rule_based_triage(): the "crawl" rung. Plain scoring logic, no LLM
    calls, deterministic. This is what runs by default.
  - LLMTriageAgent: the "walk" rung. A real Claude tool-use loop that calls
    the read-only lookup tools itself and ends on a structured
    recommendation. Runs automatically when ANTHROPIC_API_KEY is set and
    the anthropic package is installed; falls back to rule-based otherwise.

Neither brain is allowed to call a mutating action directly -- both only
produce a Recommendation. main.py is the only thing that, after the human
gate, calls tools.ACTIONS[...].
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from correlator import Incident
from tools import ACTION_NEEDS_APPROVAL, READ_TOOL_SCHEMAS, READ_TOOLS, identity_lookup, network_lookup

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
MAX_TOOL_TURNS = 6

SYSTEM_PROMPT = """You are the triage orchestrator for a SASE security operations pipeline.
You receive one correlated incident -- a user entity plus the anomaly signals ML
detectors raised about them. Your job is ONLY to investigate and recommend; you can
never take an action yourself.

You have three read-only lookup tools: identity_lookup, network_lookup, policy_lookup.
Use them to gather the context you need before deciding.

When you have enough evidence, respond with ONLY a JSON object (no markdown fences,
no other text) of this exact shape:
{"tier": "critical"|"high"|"moderate", "confidence": <0.0-1.0>,
 "rationale": "<2-3 sentences citing the specific signals and lookups>",
 "suggested_action": "quarantine_session"|"adjust_policy"|"open_ticket"}

Stay honest about weak evidence -- moderate + open_ticket is the right call when the
signals don't clearly point to a live threat. Reserve quarantine_session for cases
with corroborating identity or network risk, not just a single statistical outlier."""


@dataclass
class Recommendation:
    tier: str
    confidence: float
    rationale: str
    suggested_action: str
    needs_approval: bool
    source: str  # "rule_based" | "llm"


def _incident_prompt(incident: Incident) -> str:
    lines = [f"Incident {incident.incident_id} -- entity: {incident.entity}", "Signals:"]
    for s in incident.signals:
        lines.append(f"  - [{s.source}] score={s.score:.2f} :: {s.detail}")
    return "\n".join(lines)


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


class LLMTriageAgent:
    """A real Claude tool-use loop. Only instantiated when an API key is
    present; see `build_triage_agent()` below for the fallback logic."""

    def __init__(self):
        import anthropic  # deferred import so the module is optional
        self._client = anthropic.Anthropic()

    def triage(self, incident: Incident) -> Recommendation:
        messages = [{"role": "user", "content": _incident_prompt(incident)}]

        for _ in range(MAX_TOOL_TURNS):
            resp = self._client.messages.create(
                model=MODEL, max_tokens=1024, system=SYSTEM_PROMPT,
                tools=READ_TOOL_SCHEMAS, messages=messages,
            )
            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason != "tool_use":
                return self._parse_final(resp.content)

            tool_results = []
            for block in resp.content:
                if block.type == "tool_use":
                    fn = READ_TOOLS.get(block.name)
                    result = fn(**block.input) if fn else {"error": f"unknown tool {block.name}"}
                    tool_results.append({
                        "type": "tool_result", "tool_use_id": block.id,
                        "content": json.dumps(result),
                    })
            messages.append({"role": "user", "content": tool_results})

        raise RuntimeError("LLM triage did not converge within MAX_TOOL_TURNS")

    @staticmethod
    def _parse_final(content) -> Recommendation:
        text = "".join(b.text for b in content if getattr(b, "type", None) == "text").strip()
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
        data = json.loads(text)
        action = data["suggested_action"]
        return Recommendation(
            tier=data["tier"], confidence=float(data["confidence"]), rationale=data["rationale"],
            suggested_action=action, needs_approval=ACTION_NEEDS_APPROVAL[action], source="llm",
        )


def build_triage_agent():
    """Returns a callable incident -> Recommendation. Uses the LLM path
    when ANTHROPIC_API_KEY is set and the anthropic package imports
    cleanly; otherwise returns the rule-based function so the pipeline
    still runs end to end."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            llm_agent = LLMTriageAgent()
            return llm_agent.triage, "llm"
        except Exception as e:  # missing package, bad key, network -- fall back, don't crash the demo
            print(f"  (LLM triage unavailable ({e}); falling back to rule-based)")
    return rule_based_triage, "rule_based"
