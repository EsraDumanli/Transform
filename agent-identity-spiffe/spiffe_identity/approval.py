"""Human approval gate: nothing is registered until a person says yes."""

from __future__ import annotations

import sys
from typing import Callable, TextIO

from .policy import Proposal


def describe(p: Proposal) -> str:
    w = p.workload
    lines = [
        f"  workload : {w.name}  ({w.kind}, from {w.source})",
        f"  selectors: {', '.join(w.selectors)}",
        f"  identity : {p.spiffe_id}",
        f"  assigned : {p.assigned_by}" + (f"  confidence={p.confidence}" if p.confidence else ""),
    ]
    if p.rationale:
        lines.append(f"  why      : {p.rationale}")
    if w.kind == "network-service":
        lines.append("  WARNING  : IP:port selectors are weak; anything that takes over this address inherits the identity.")
    if p.assigned_by.startswith("llm:"):
        lines.append("  NOTE     : proposed by an LLM, check it against what you know about this workload.")
    return "\n".join(lines)


def gate(
    proposals: list[Proposal],
    approve_all: bool = False,
    ask: Callable[[str], str] = input,
    out: TextIO = sys.stdout,
) -> list[Proposal]:
    """Return the proposals a human approved.

    ``approve_all`` exists for demos and tests. Never wire it to a schedule
    that runs against real infrastructure.
    """
    candidates = [p for p in proposals if p.assignable]
    if not candidates:
        print("Nothing to approve.", file=out)
        return []
    if approve_all:
        print(f"--approve-all: approving {len(candidates)} proposal(s) without prompting.", file=out)
        return candidates
    if not sys.stdin.isatty() and ask is input:
        print("stdin is not a terminal and --approve-all was not given: approving nothing.", file=out)
        return []
    approved = []
    for i, p in enumerate(candidates, 1):
        print(f"\n[{i}/{len(candidates)}]\n{describe(p)}", file=out)
        while True:
            ans = ask("  approve? [y]es / [n]o / [q]uit: ").strip().lower()
            if ans in ("y", "yes"):
                approved.append(p)
                break
            if ans in ("n", "no", ""):
                break
            if ans in ("q", "quit"):
                return approved
    return approved
