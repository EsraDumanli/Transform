from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class CaseLoadError(Exception):
    pass


@dataclass(frozen=True)
class Case:
    id: str
    subject: str
    input: dict[str, Any]
    output: dict[str, Any]
    reference: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def get(self, path: str) -> Any:
        """Resolve a dotted path like 'output.role' or 'reference' against this case."""
        parts = path.split(".")
        root = parts[0]
        if root not in ("id", "subject", "input", "output", "reference", "metadata", "tags"):
            raise KeyError(f"unknown case field '{root}' in path '{path}'")
        value: Any = getattr(self, root)
        for part in parts[1:]:
            if not isinstance(value, dict):
                raise KeyError(f"path '{path}' goes through a non-dict value at '{part}'")
            if part not in value:
                raise KeyError(f"path '{path}' has no key '{part}'")
            value = value[part]
        return value

    def has(self, path: str) -> bool:
        try:
            self.get(path)
            return True
        except KeyError:
            return False


_REQUIRED_FIELDS = ("id", "subject", "input", "output")


def _parse_case(raw: dict, line_no: int, source: str) -> Case:
    missing = [f for f in _REQUIRED_FIELDS if f not in raw]
    if missing:
        raise CaseLoadError(f"{source}:{line_no}: missing required field(s) {missing}")
    if not isinstance(raw["input"], dict):
        raise CaseLoadError(f"{source}:{line_no}: 'input' must be an object")
    if not isinstance(raw["output"], dict):
        raise CaseLoadError(f"{source}:{line_no}: 'output' must be an object")
    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise CaseLoadError(f"{source}:{line_no}: 'tags' must be a list of strings")
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise CaseLoadError(f"{source}:{line_no}: 'metadata' must be an object")
    return Case(
        id=str(raw["id"]),
        subject=str(raw["subject"]),
        input=raw["input"],
        output=raw["output"],
        reference=raw.get("reference"),
        metadata=metadata,
        tags=tuple(tags),
    )


def load_cases(path: str | Path) -> list[Case]:
    path = Path(path)
    if not path.exists():
        raise CaseLoadError(f"dataset not found: {path}")
    cases: list[Case] = []
    seen_ids: dict[str, int] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                raw = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise CaseLoadError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
            if not isinstance(raw, dict):
                raise CaseLoadError(f"{path}:{line_no}: each line must be a JSON object")
            case = _parse_case(raw, line_no, str(path))
            if case.id in seen_ids:
                raise CaseLoadError(
                    f"{path}:{line_no}: duplicate case id '{case.id}' (first seen at line {seen_ids[case.id]})"
                )
            seen_ids[case.id] = line_no
            cases.append(case)
    if not cases:
        raise CaseLoadError(f"{path}: dataset is empty")
    return sorted(cases, key=lambda c: c.id)


def hash_dataset(cases: list[Case]) -> str:
    """Deterministic hash of a dataset's contents, independent of file formatting or order."""
    digest = hashlib.sha256()
    for case in sorted(cases, key=lambda c: c.id):
        payload = {
            "id": case.id,
            "subject": case.subject,
            "input": case.input,
            "output": case.output,
            "reference": case.reference,
            "metadata": case.metadata,
            "tags": list(case.tags),
        }
        digest.update(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))
    return digest.hexdigest()
