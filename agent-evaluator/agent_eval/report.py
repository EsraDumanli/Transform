from __future__ import annotations

from collections import defaultdict
from typing import Any

from .checks.builtin import STATUS_FAIL, STATUS_NOT_APPLICABLE, STATUS_PASS
from .rubric import Rubric


def _pass_rate(verdicts: list, criterion_id: str) -> tuple[int, int]:
    relevant = [v for v in verdicts if v.criterion_id == criterion_id and v.status in (STATUS_PASS, STATUS_FAIL)]
    passed = sum(1 for v in relevant if v.status == STATUS_PASS)
    return passed, len(relevant)


def render_report(rubric: Rubric, verdicts: list, errors: list, manifest: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Agent Evaluator report: {rubric.name} v{rubric.version}")
    lines.append("")
    lines.append(f"- Run: `{manifest['run_id']}`")
    lines.append(
        f"- Dataset: `{manifest['dataset']['path']}` "
        f"({manifest['dataset']['case_count']} cases, hash `{manifest['dataset']['hash'][:12]}`)"
    )
    lines.append(f"- Rubric hash: `{manifest['rubric']['hash'][:12]}`")
    lines.append(f"- Judge: {'enabled' if manifest['judge']['enabled'] else 'disabled'}")
    lines.append(f"- Network checks: {'enabled' if manifest['settings']['allow_network'] else 'disabled'}")
    lines.append("")

    critical_failures = [v for v in verdicts if v.status == STATUS_FAIL and v.severity == "critical"]
    if critical_failures:
        lines.append("## Critical failures")
        lines.append("")
        for v in sorted(critical_failures, key=lambda v: (v.criterion_id, v.case_id)):
            lines.append(f"- **{v.criterion_id}** on `{v.case_id}`: {v.reason}")
        lines.append("")

    lines.append("## Pass rate per criterion")
    lines.append("")
    lines.append("| Criterion | Severity | Pass rate | Not applicable | Errors |")
    lines.append("|---|---|---|---|---|")
    for criterion in rubric.criteria:
        passed, total = _pass_rate(verdicts, criterion.id)
        na = sum(1 for v in verdicts if v.criterion_id == criterion.id and v.status == STATUS_NOT_APPLICABLE)
        err_count = sum(1 for e in errors if e.criterion_id == criterion.id)
        rate = f"{passed}/{total}" if total else "n/a"
        lines.append(f"| {criterion.id} | {criterion.severity} | {rate} | {na} | {err_count} |")
    lines.append("")

    failures_by_criterion: dict[str, list] = defaultdict(list)
    for v in verdicts:
        if v.status == STATUS_FAIL:
            failures_by_criterion[v.criterion_id].append(v)
    if failures_by_criterion:
        lines.append("## Failures by criterion")
        lines.append("")
        for criterion_id, group in sorted(failures_by_criterion.items()):
            lines.append(f"### {criterion_id} ({len(group)} failing)")
            for v in sorted(group, key=lambda v: v.case_id):
                lines.append(f"- `{v.case_id}`: {v.reason}")
            lines.append("")

    if errors:
        lines.append("## Errors (not counted as failures)")
        lines.append("")
        by_class: dict[str, int] = defaultdict(int)
        for e in errors:
            by_class[e.failure_class] += 1
        for failure_class, count in sorted(by_class.items()):
            lines.append(f"- {failure_class}: {count}")
        lines.append("")

    judge_criteria = [c for c in rubric.criteria if c.type == "judge"]
    if judge_criteria:
        lines.append("## Judge criteria")
        lines.append("")
        for c in judge_criteria:
            lines.append(f"- `{c.id}`: uncalibrated, don't rely on it yet (judge not implemented before M3)")
        lines.append("")

    return "\n".join(lines) + "\n"
