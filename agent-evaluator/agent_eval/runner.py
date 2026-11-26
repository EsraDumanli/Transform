from __future__ import annotations

import json
import platform
import secrets
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .cases import hash_dataset, load_cases
from .checks import builtin
from .checks.builtin import STATUS_ERROR, STATUS_NOT_APPLICABLE, CheckContext
from .report import render_report
from .rubric import Rubric, hash_rubric, load_rubric, validate_rubric


class RunnerError(Exception):
    pass


@dataclass(frozen=True)
class RunConfig:
    dataset_path: Path
    rubric_path: Path
    out_dir: Path
    allow_network: bool = False
    network_timeout: float = 5.0


@dataclass(frozen=True)
class Verdict:
    case_id: str
    criterion_id: str
    severity: str
    status: str
    reason: str
    evidence: Any = None


@dataclass(frozen=True)
class EvalError:
    case_id: str
    criterion_id: str
    failure_class: str
    message: str


def _run_folder_name(rubric: Rubric) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    safe_name = "".join(c if c.isalnum() or c in "-_." else "-" for c in rubric.name)
    # A short random suffix avoids collisions between two runs started in the same second;
    # it doesn't affect reproducibility, which is tracked via the dataset/rubric hashes instead.
    return f"{stamp}-{safe_name}-{secrets.token_hex(3)}"


def run(config: RunConfig) -> dict[str, Any]:
    cases = load_cases(config.dataset_path)
    rubric = load_rubric(config.rubric_path)

    problems = validate_rubric(rubric, builtin.known_checks())
    if problems:
        raise RunnerError("rubric failed validation:\n  " + "\n  ".join(problems))

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    context = CheckContext(
        all_cases=tuple(cases),
        allow_network=config.allow_network,
        network_timeout=config.network_timeout,
    )

    verdicts: list[Verdict] = []
    errors: list[EvalError] = []

    for case in cases:
        for criterion in rubric.criteria:
            if not criterion.applies(case.tags):
                verdicts.append(
                    Verdict(
                        case.id,
                        criterion.id,
                        criterion.severity,
                        STATUS_NOT_APPLICABLE,
                        "criterion's applies_to tags do not match this case",
                    )
                )
                continue
            if criterion.type == "judge":
                errors.append(
                    EvalError(
                        case.id,
                        criterion.id,
                        "judge_not_implemented",
                        "the LLM judge is not implemented yet (planned for M3)",
                    )
                )
                continue

            check_type = criterion.check.get("type")
            params = criterion.check.get("params", {})
            result = builtin.run_check(check_type, case, params, context)
            if result.status == STATUS_ERROR:
                errors.append(EvalError(case.id, criterion.id, "check_error", result.reason))
            else:
                verdicts.append(
                    Verdict(case.id, criterion.id, criterion.severity, result.status, result.reason, result.evidence)
                )

    run_id = _run_folder_name(rubric)
    run_dir = config.out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    with (run_dir / "results.jsonl").open("w", encoding="utf-8") as fh:
        for v in sorted(verdicts, key=lambda v: (v.case_id, v.criterion_id)):
            fh.write(json.dumps(asdict(v), default=str) + "\n")

    with (run_dir / "errors.jsonl").open("w", encoding="utf-8") as fh:
        for e in sorted(errors, key=lambda e: (e.case_id, e.criterion_id)):
            fh.write(json.dumps(asdict(e)) + "\n")

    manifest = {
        "run_id": run_id,
        "harness_version": __version__,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "rubric": {
            "name": rubric.name,
            "version": rubric.version,
            "hash": hash_rubric(rubric),
            "source": str(config.rubric_path),
        },
        "dataset": {"path": str(config.dataset_path), "hash": hash_dataset(cases), "case_count": len(cases)},
        "settings": {"allow_network": config.allow_network, "network_timeout": config.network_timeout},
        "judge": {"enabled": False},
        "started_at": started_at,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (run_dir / "run.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report_md = render_report(rubric, verdicts, errors, manifest)
    (run_dir / "report.md").write_text(report_md, encoding="utf-8")

    return {"run_dir": run_dir, "manifest": manifest, "verdicts": verdicts, "errors": errors}
