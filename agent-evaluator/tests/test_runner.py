from pathlib import Path

from agent_eval.checks.builtin import STATUS_FAIL, STATUS_PASS
from agent_eval.runner import RunConfig, run

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_oracle_dataset_scores_about_100_percent(tmp_path):
    config = RunConfig(
        dataset_path=EXAMPLES / "oracle_dataset.jsonl",
        rubric_path=EXAMPLES / "oracle_rubric.json",
        out_dir=tmp_path,
    )
    result = run(config)
    assert not result["errors"]
    assert all(v.status == STATUS_PASS for v in result["verdicts"])
    assert (result["run_dir"] / "report.md").exists()
    assert (result["run_dir"] / "run.json").exists()


def test_null_dataset_scores_about_0_percent(tmp_path):
    config = RunConfig(
        dataset_path=EXAMPLES / "null_dataset.jsonl",
        rubric_path=EXAMPLES / "oracle_rubric.json",
        out_dir=tmp_path,
    )
    result = run(config)
    assert not result["errors"]
    assert all(v.status == STATUS_FAIL for v in result["verdicts"])


def test_run_rejects_rubric_with_unknown_check_type(tmp_path):
    rubric_path = tmp_path / "bad_rubric.json"
    rubric_path.write_text(
        '{"name": "r", "version": "1", "criteria": [{"id": "c", "type": "check", '
        '"description": "d", "severity": "minor", "check": {"type": "nope", "params": {}}}]}',
        encoding="utf-8",
    )
    config = RunConfig(dataset_path=EXAMPLES / "oracle_dataset.jsonl", rubric_path=rubric_path, out_dir=tmp_path)
    try:
        run(config)
        assert False, "expected RunnerError"
    except Exception as exc:
        assert "unknown check type" in str(exc)


def test_run_is_deterministic_across_repeats(tmp_path):
    config_a = RunConfig(
        dataset_path=EXAMPLES / "oracle_dataset.jsonl", rubric_path=EXAMPLES / "oracle_rubric.json", out_dir=tmp_path
    )
    config_b = RunConfig(
        dataset_path=EXAMPLES / "oracle_dataset.jsonl", rubric_path=EXAMPLES / "oracle_rubric.json", out_dir=tmp_path
    )
    result_a = run(config_a)
    result_b = run(config_b)
    verdicts_a = {(v.case_id, v.criterion_id): v.status for v in result_a["verdicts"]}
    verdicts_b = {(v.case_id, v.criterion_id): v.status for v in result_b["verdicts"]}
    assert verdicts_a == verdicts_b
    assert result_a["manifest"]["dataset"]["hash"] == result_b["manifest"]["dataset"]["hash"]
    assert result_a["manifest"]["rubric"]["hash"] == result_b["manifest"]["rubric"]["hash"]
