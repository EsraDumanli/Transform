"""
Runs the full pipeline once and prints the trace: telemetry -> ML detection
-> correlation -> triage -> human gate -> (maybe) action. This is the
reference architecture diagram from the guide, executing.

Usage:
    python main.py                # rule-based triage, gate defaults to PENDING
    python main.py --approve      # simulate a human approving every gated
                                   # recommendation (demo only -- never wire
                                   # this flag to a real environment)

Set ANTHROPIC_API_KEY to switch triage onto a real Claude tool-use loop
(the "walk" rung) without changing anything else in this file.
"""

from __future__ import annotations

import argparse

from agent import build_triage_agent
from correlator import correlate
from detectors import run_isolation_forest, run_peer_clustering, run_time_series_baseline
from telemetry import build_user_profiles, generate_access_events, generate_daily_usage_series
from tools import ACTIONS

DIVIDER = "-" * 72


def main():
    parser = argparse.ArgumentParser(description="SASE agentic AIOps demo pipeline")
    parser.add_argument("--approve", action="store_true",
                         help="Simulate a human approving every gated recommendation (demo only).")
    args = parser.parse_args()

    print(DIVIDER)
    print("1. TELEMETRY  -- generating synthetic SASE events")
    events = generate_access_events()
    daily_series = generate_daily_usage_series()
    profiles = build_user_profiles(events)
    print(f"   {len(events)} access events, {len(daily_series)} users' 30-day usage series, "
          f"{len(profiles)} aggregate user profiles")

    print(DIVIDER)
    print("2. ML DETECTION LAYER")
    if_flags = run_isolation_forest(events)
    ts_flags = run_time_series_baseline(daily_series)
    peer_flags = run_peer_clustering(profiles)
    print(f"   isolation_forest:      {len(if_flags)} event(s) flagged")
    print(f"   time_series_baseline:  {len(ts_flags)} user(s) flagged")
    print(f"   peer_clustering:       {len(peer_flags)} user(s) flagged")

    print(DIVIDER)
    print("3. CORRELATION WINDOW")
    incidents = correlate(if_flags, ts_flags, peer_flags)
    print(f"   {len(incidents)} incident(s) opened (one per flagged entity)")

    triage_fn, mode = build_triage_agent()
    print(f"   triage brain: {mode}")

    audit_log = []

    for incident in incidents:
        print(DIVIDER)
        print(f"INCIDENT {incident.incident_id}  entity={incident.entity}  "
              f"sources={sorted(incident.sources)}")
        for s in incident.signals:
            print(f"   [{s.source}] score={s.score:.2f} :: {s.detail}")

        print("4. TRIAGE")
        rec = triage_fn(incident)
        if rec.specialist_findings:
            print("   4a. SPECIALISTS (identity | network | policy -- each scoped to one domain, run in parallel)")
            for f in rec.specialist_findings:
                print(f"       [{f.domain:<8}] risk={f.risk_level:<6} {f.summary}")
                if f.key_signals:
                    print(f"                    signals: {', '.join(f.key_signals)}")
            print("   4b. ORCHESTRATOR -- cross-domain correlation")
            print(f"       root_cause: {rec.root_cause}")
        print(f"   tier={rec.tier}  confidence={rec.confidence:.2f}  source={rec.source}")
        print(f"   rationale: {rec.rationale}")
        print(f"   suggested_action: {rec.suggested_action}  "
              f"(needs_approval={rec.needs_approval})")

        print("5. HUMAN APPROVAL GATE")
        if not rec.needs_approval:
            decision = "auto-approved (non-mutating)"
            should_execute = True
        elif args.approve:
            decision = "approved (--approve demo flag)"
            should_execute = True
        else:
            decision = "PENDING -- run with --approve to simulate a human approving this"
            should_execute = False
        print(f"   {decision}")

        print("6. ACTION EXECUTOR")
        if should_execute:
            if rec.suggested_action == "adjust_policy":
                result = ACTIONS[rec.suggested_action](
                    "default-access-policy", f"tighten MFA requirement for {incident.entity}")
            elif rec.suggested_action == "open_ticket":
                result = ACTIONS[rec.suggested_action](
                    f"Review anomaly for {incident.entity} (tier={rec.tier}): {rec.rationale}")
            else:
                result = ACTIONS[rec.suggested_action](incident.entity)
            print(f"   executed: {result}")
            audit_log.append({"incident": incident.incident_id, "tier": rec.tier,
                               "action": rec.suggested_action, "result": result["result"]})
        else:
            print("   not executed -- awaiting approval")
            audit_log.append({"incident": incident.incident_id, "tier": rec.tier,
                               "action": rec.suggested_action, "result": "pending approval"})

    print(DIVIDER)
    print("AUDIT LOG")
    for row in audit_log:
        print(f"   {row['incident']:<16} tier={row['tier']:<9} action={row['action']:<18} {row['result']}")
    print(DIVIDER)


if __name__ == "__main__":
    main()
