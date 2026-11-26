import pytest

from agent_eval.cases import CaseLoadError, hash_dataset, load_cases


def _write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_loads_valid_cases_sorted_by_id(tmp_path):
    path = _write(
        tmp_path,
        "d.jsonl",
        [
            '{"id": "b", "subject": "s", "input": {}, "output": {"x": 1}}',
            '{"id": "a", "subject": "s", "input": {}, "output": {"x": 2}}',
        ],
    )
    cases = load_cases(path)
    assert [c.id for c in cases] == ["a", "b"]


def test_missing_required_field_names_it(tmp_path):
    path = _write(tmp_path, "d.jsonl", ['{"id": "a", "subject": "s", "output": {}}'])
    with pytest.raises(CaseLoadError, match="input"):
        load_cases(path)


def test_duplicate_id_is_an_error(tmp_path):
    path = _write(
        tmp_path,
        "d.jsonl",
        [
            '{"id": "a", "subject": "s", "input": {}, "output": {}}',
            '{"id": "a", "subject": "s", "input": {}, "output": {}}',
        ],
    )
    with pytest.raises(CaseLoadError, match="duplicate case id"):
        load_cases(path)


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(CaseLoadError, match="not found"):
        load_cases(tmp_path / "nope.jsonl")


def test_empty_dataset_is_an_error(tmp_path):
    path = _write(tmp_path, "d.jsonl", [])
    with pytest.raises(CaseLoadError, match="empty"):
        load_cases(path)


def test_case_get_resolves_dotted_paths(tmp_path):
    path = _write(tmp_path, "d.jsonl", ['{"id": "a", "subject": "s", "input": {}, "output": {"role": "eng"}}'])
    case = load_cases(path)[0]
    assert case.get("output.role") == "eng"
    assert not case.has("output.missing")


def test_hash_dataset_is_order_independent(tmp_path):
    path_a = _write(
        tmp_path,
        "a.jsonl",
        [
            '{"id": "a", "subject": "s", "input": {}, "output": {}}',
            '{"id": "b", "subject": "s", "input": {}, "output": {}}',
        ],
    )
    path_b = _write(
        tmp_path,
        "b.jsonl",
        [
            '{"id": "b", "subject": "s", "input": {}, "output": {}}',
            '{"id": "a", "subject": "s", "input": {}, "output": {}}',
        ],
    )
    assert hash_dataset(load_cases(path_a)) == hash_dataset(load_cases(path_b))
