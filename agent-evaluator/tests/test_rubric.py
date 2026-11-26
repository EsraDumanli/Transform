import json

import pytest

from agent_eval.rubric import RubricError, load_rubric, validate_rubric


def _write(tmp_path, payload):
    path = tmp_path / "rubric.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _base_criterion(**overrides):
    criterion = {
        "id": "c1",
        "type": "check",
        "description": "d",
        "severity": "major",
        "check": {"type": "enum", "params": {"field": "output.x", "values": ["a"]}},
    }
    criterion.update(overrides)
    return criterion


def test_loads_valid_rubric(tmp_path):
    path = _write(tmp_path, {"name": "r", "version": "1", "criteria": [_base_criterion()]})
    rubric = load_rubric(path)
    assert rubric.name == "r"
    assert len(rubric.criteria) == 1


def test_duplicate_criterion_id_is_rejected(tmp_path):
    path = _write(tmp_path, {"name": "r", "version": "1", "criteria": [_base_criterion(), _base_criterion()]})
    with pytest.raises(RubricError, match="duplicate criterion id"):
        load_rubric(path)


def test_judge_criterion_without_scale_is_rejected(tmp_path):
    criterion = _base_criterion(type="judge", check=None, judge={"model": "claude-opus-5-5"})
    path = _write(tmp_path, {"name": "r", "version": "1", "criteria": [criterion]})
    with pytest.raises(RubricError, match="no concrete 'scale'"):
        load_rubric(path)


def test_judge_criterion_with_pass_fail_scale_is_accepted(tmp_path):
    criterion = _base_criterion(type="judge", check=None, judge={"scale": "pass_fail"})
    path = _write(tmp_path, {"name": "r", "version": "1", "criteria": [criterion]})
    rubric = load_rubric(path)
    assert rubric.criteria[0].type == "judge"


def test_validate_rubric_rejects_unknown_check_type(tmp_path):
    criterion = _base_criterion(check={"type": "not_a_real_check", "params": {}})
    path = _write(tmp_path, {"name": "r", "version": "1", "criteria": [criterion]})
    rubric = load_rubric(path)
    problems = validate_rubric(rubric, known_checks={"enum"})
    assert any("not_a_real_check" in p for p in problems)


def test_criterion_applies_respects_tags():
    from agent_eval.rubric import Criterion

    criterion = Criterion(id="c", type="check", description="d", severity="minor", applies_to=("mcp",))
    assert criterion.applies(("mcp", "other"))
    assert not criterion.applies(("other",))
