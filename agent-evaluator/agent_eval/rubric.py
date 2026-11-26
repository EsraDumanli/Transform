from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_VALID_SEVERITIES = ("critical", "major", "minor")
_VALID_TYPES = ("check", "judge")


class RubricError(Exception):
    """Raised for both load and validation problems; collects every issue found."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Criterion:
    id: str
    type: str
    description: str
    severity: str
    applies_to: tuple[str, ...] = ()
    weight: float = 1.0
    check: dict[str, Any] | None = None
    judge: dict[str, Any] | None = None

    def applies(self, tags: tuple[str, ...]) -> bool:
        if not self.applies_to:
            return True
        return any(t in tags for t in self.applies_to)


@dataclass(frozen=True)
class Rubric:
    name: str
    version: str
    criteria: tuple[Criterion, ...]
    source: str = "<unknown>"


def _parse_criterion(raw: dict, index: int, problems: list[str]) -> Criterion | None:
    where = f"criteria[{index}]"
    for required in ("id", "type", "description", "severity"):
        if required not in raw:
            problems.append(f"{where}: missing '{required}'")
    if "id" not in raw or "type" not in raw or "severity" not in raw:
        return None

    cid = raw["id"]
    ctype = raw["type"]
    severity = raw["severity"]
    if ctype not in _VALID_TYPES:
        problems.append(f"{where} ('{cid}'): unknown type '{ctype}', expected one of {_VALID_TYPES}")
    if severity not in _VALID_SEVERITIES:
        problems.append(f"{where} ('{cid}'): unknown severity '{severity}', expected one of {_VALID_SEVERITIES}")

    check = raw.get("check")
    judge = raw.get("judge")
    if ctype == "check" and not check:
        problems.append(f"{where} ('{cid}'): type is 'check' but no 'check' block given")
    if ctype == "judge" and not judge:
        problems.append(f"{where} ('{cid}'): type is 'judge' but no 'judge' block given")
    if ctype == "judge" and judge:
        scale = judge.get("scale")
        if scale is None:
            problems.append(f"{where} ('{cid}'): judge criterion has no concrete 'scale'")
        elif scale == "pass_fail":
            pass
        elif isinstance(scale, dict) and scale.get("type") == "likert":
            levels = scale.get("levels")
            if not isinstance(levels, dict) or not levels:
                problems.append(f"{where} ('{cid}'): likert scale needs a non-empty 'levels' description map")
        else:
            problems.append(f"{where} ('{cid}'): scale must be 'pass_fail' or a likert scale with levels")

    applies_to = raw.get("applies_to", [])
    if not isinstance(applies_to, list) or not all(isinstance(t, str) for t in applies_to):
        problems.append(f"{where} ('{cid}'): 'applies_to' must be a list of strings")
        applies_to = []

    weight = raw.get("weight", 1.0)
    if not isinstance(weight, (int, float)):
        problems.append(f"{where} ('{cid}'): 'weight' must be a number")
        weight = 1.0

    return Criterion(
        id=str(cid),
        type=ctype if ctype in _VALID_TYPES else "check",
        description=str(raw.get("description", "")),
        severity=severity if severity in _VALID_SEVERITIES else "minor",
        applies_to=tuple(applies_to),
        weight=float(weight),
        check=check,
        judge=judge,
    )


def load_rubric(path: str | Path) -> Rubric:
    path = Path(path)
    if not path.exists():
        raise RubricError([f"rubric not found: {path}"])
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RubricError([f"{path}: invalid JSON ({exc})"]) from exc

    problems: list[str] = []
    for required in ("name", "version", "criteria"):
        if required not in raw:
            problems.append(f"{path}: missing top-level '{required}'")
    if problems:
        raise RubricError(problems)

    if not isinstance(raw["criteria"], list) or not raw["criteria"]:
        raise RubricError([f"{path}: 'criteria' must be a non-empty list"])

    criteria: list[Criterion] = []
    seen_ids: dict[str, int] = {}
    for index, raw_criterion in enumerate(raw["criteria"]):
        criterion = _parse_criterion(raw_criterion, index, problems)
        if criterion is None:
            continue
        if criterion.id in seen_ids:
            problems.append(
                f"criteria[{index}]: duplicate criterion id '{criterion.id}' "
                f"(first seen at criteria[{seen_ids[criterion.id]}])"
            )
        else:
            seen_ids[criterion.id] = index
            criteria.append(criterion)

    if problems:
        raise RubricError(problems)

    return Rubric(name=str(raw["name"]), version=str(raw["version"]), criteria=tuple(criteria), source=str(path))


def validate_rubric(rubric: Rubric, known_checks: set[str]) -> list[str]:
    """Returns a list of problems (empty if the rubric is valid against this check registry)."""
    problems: list[str] = []
    for criterion in rubric.criteria:
        if criterion.type == "check":
            check_type = (criterion.check or {}).get("type")
            if check_type not in known_checks:
                problems.append(
                    f"criterion '{criterion.id}': unknown check type '{check_type}', "
                    f"known types are {sorted(known_checks)}"
                )
    return problems


def hash_rubric(rubric: Rubric) -> str:
    payload = {
        "name": rubric.name,
        "version": rubric.version,
        "criteria": [
            {
                "id": c.id,
                "type": c.type,
                "severity": c.severity,
                "applies_to": list(c.applies_to),
                "weight": c.weight,
                "check": c.check,
                "judge": c.judge,
            }
            for c in sorted(rubric.criteria, key=lambda c: c.id)
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
