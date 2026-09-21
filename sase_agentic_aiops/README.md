# SASE Agentic AIOps -- hands-on companion project

Companion to the [Agentic AIOps for SASE](https://claude.ai/artifact/DLSbnNaRM4G2Nzz14Lmu26) field guide.
This implements the reference architecture from that guide, scaled down to something you can run on a laptop:

```
telemetry.py    synthetic access logs, daily usage series, per-user profiles
detectors.py    Isolation Forest / time-series baseline / DBSCAN peer clustering
correlator.py   groups flags from all three detectors into per-entity incidents
tools.py        read-only lookups (identity/network/policy) + gated actions
agent.py        rule-based triage, or 3 least-privileged specialists (identity/network/
                policy) + a tool-less orchestrator that correlates their findings
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

Set an API key and the same pipeline switches the orchestrator onto a real multi-agent triage --
the **walk/run** rungs -- with no other code changes:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python main.py
```

`agent.py` implements this as four agents, not one:

- **Three specialists** (`IdentitySpecialist`, `NetworkSpecialist`, `PolicySpecialist`), each a
  separate Claude tool-use loop scoped to exactly one read-only lookup tool. This is least privilege
  by construction, not by prompt instruction: an `IdentitySpecialist`'s API call only ever carries
  `IDENTITY_TOOL_SCHEMAS` in its `tools=` list, so the model has no way to request a network or
  policy lookup -- the tool isn't in the request. They run concurrently (`ThreadPoolExecutor`) since
  their lookups are independent.
- **One orchestrator** with *no tools at all*. It receives all three specialists' findings --
  each blind to the other two domains and to any data outside its own -- and has to correlate them
  into a single cross-domain `root_cause` plus a tier/action recommendation. `main.py` prints the
  specialist findings and the orchestrator's root-cause synthesis as separate trace steps (4a/4b) so
  you can see the correlation happen, not just the final answer.

Neither the specialists nor the orchestrator can act -- all four only ever produce a lookup result
or a structured `Recommendation`, which `main.py` then runs through the exact same human-approval
gate as the rule-based path. Compare the `rationale`/`root_cause` text against the rule-based
version on the same incident; it's the fastest way to see what correlating independent,
domain-scoped investigations adds over both a fixed scoring function and a single agent that just
calls all three tools itself -- and where it can still go wrong (an ungrounded root cause, a tier
call backed by only one domain) in a way the rule-based version structurally can't.

## Extending it further

Ideas, roughly in order of how much they change:

1. **Change the gate threshold.** `tools.ACTION_NEEDS_APPROVAL` decides what's gated. Try making
   `open_ticket` gated too, or add a fourth action that's never allowed to auto-execute regardless
   of tier.
2. **Add a fourth telemetry source, detector, and specialist.** Extend `telemetry.py` and
   `detectors.py` without touching the correlator, then give the new domain its own specialist in
   `agent.py` (a lookup tool in `tools.py`, a `SpecialistAgent` subclass, and one more entry in
   `MultiAgentTriage._specialists`) -- if that's a small, additive change, the domain-scoping
   pattern is doing its job.
3. **Move the specialists onto the Claude Agent SDK.** They're currently hand-rolled tool-use loops
   using the raw `anthropic` client. Try rebuilding them as real
   [subagents](https://code.claude.com/docs/en/agent-sdk/subagents) with SDK-level
   [permission scoping](https://code.claude.com/docs/en/agent-sdk/permissions) instead of the
   per-instance `tools=` list doing the enforcement.
4. **Harden it.** Before this touches anything real: rate limits on the action executor, an audit
   log that persists (not just prints), a kill switch, and a timeout/circuit-breaker around the
   specialist and orchestrator calls (e.g. what should `main.py` do if one specialist fails but the
   other two succeed?).

## What's simulated vs. real

Every "lookup" and "action" in `tools.py` is a Python dict -- there is no real SASE platform behind
this. `detectors.py` runs real scikit-learn models on synthetic-but-structured data, and
`agent.py`'s LLM path makes real calls to the Claude API when a key is set. The point of the project
is the shape of the pipeline and the discipline of the gate, not the specific telemetry.
