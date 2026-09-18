# SASE Agentic AIOps -- hands-on companion project

Companion to the [Agentic AIOps for SASE](https://claude.ai/artifact/DLSbnNaRM4G2Nzz14Lmu26) field guide.
This implements the reference architecture from that guide, scaled down to something you can run on a laptop:

```
telemetry.py    synthetic access logs, daily usage series, per-user profiles
detectors.py    Isolation Forest / time-series baseline / DBSCAN peer clustering
correlator.py   groups flags from all three detectors into per-entity incidents
tools.py        read-only lookups (identity/network/policy) + gated actions
agent.py        the triage orchestrator -- rule-based, or a real Claude tool-use loop
main.py         runs the pipeline end to end and prints the trace
```

## Quickstart

```bash
pip install -r requirements.txt
python main.py
```

You'll see the pipeline run in the same order as the reference architecture diagram: telemetry
generation, the three detectors, correlation into incidents, triage, the human-approval gate, and
(for anything the gate clears) the action executor. Three users are deliberately planted with
anomalous behavior so there's always something to find -- `user_007` (impossible travel + a huge
upload), `user_022` (a peer-clustering outlier -- too many devices, mostly off-hours), and
`user_015` (a slow usage ramp a single-point check would miss).

By default, mutating recommendations (`quarantine_session`, `adjust_policy`) come back **PENDING**
-- the gate does not execute them. Run with `--approve` to simulate a human clearing every gated
recommendation, so you can see the full trace including the executor:

```bash
python main.py --approve
```

Never wire `--approve` to anything real. It exists so the demo can show you what an approved
action looks like without requiring you to sit in a loop clicking "yes."

## Switching on the LLM triage path

By default, `agent.py` uses `rule_based_triage()` -- plain scoring logic, no API calls, fully
deterministic. That's the **crawl** rung from the guide's practice ladder: get the plumbing and the
gate right before handing decisions to a model.

Set an API key and the same pipeline switches the orchestrator onto a real Claude tool-use loop
(the **walk** rung) with no other code changes:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python main.py
```

`LLMTriageAgent` in `agent.py` gives Claude the three *read-only* lookup tools
(`identity_lookup`, `network_lookup`, `policy_lookup`) and nothing else -- it can investigate, but
it can't act. It has to end on a structured JSON recommendation, which `main.py` then runs through
the exact same gate as the rule-based path. Compare the `rationale` text between the two modes on
the same incident; it's the fastest way to see what an LLM-orchestrated agent adds over a fixed
scoring function -- and where it can go wrong (an ungrounded rationale, an over-confident tier) in
a way the rule-based version structurally can't.

## Extending it (the "run" rung)

Ideas, roughly in order of how much they change:

1. **Change the gate threshold.** `tools.ACTION_NEEDS_APPROVAL` decides what's gated. Try making
   `open_ticket` gated too, or add a fourth action that's never allowed to auto-execute regardless
   of tier.
2. **Add a fourth telemetry source and detector.** Extend `telemetry.py` and `detectors.py` without
   touching `agent.py` or `main.py` -- if that's easy, the perception/reasoning split is doing its
   job.
3. **Split triage into a real handoff.** Right now one orchestrator calls all three lookup tools
   itself. The guide's reference architecture has three separate specialist agents (identity,
   network, policy) that the orchestrator delegates to. Try building that with the
   [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview)'s subagents, so each
   specialist only ever sees the one tool it needs.
4. **Harden it.** Before this touches anything real: rate limits on the action executor, an audit
   log that persists (not just prints), a kill switch, and permission scoping per the Agent SDK's
   [permissions](https://code.claude.com/docs/en/agent-sdk/permissions) model.

## What's simulated vs. real

Every "lookup" and "action" in `tools.py` is a Python dict -- there is no real SASE platform behind
this. `detectors.py` runs real scikit-learn models on synthetic-but-structured data, and
`agent.py`'s LLM path makes real calls to the Claude API when a key is set. The point of the project
is the shape of the pipeline and the discipline of the gate, not the specific telemetry.
