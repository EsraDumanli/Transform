# Agent Evaluator

A report-only harness that grades any agent's outputs against a rubric: deterministic checks first, an optional Claude judge for what a rule can't decide. See [REQUIREMENTS.md](REQUIREMENTS.md) for the full design and the open questions still being decided.

**Status: M1 (skeleton) only.** Case schema, rubric loader/validator, the built-in deterministic check library, the runner, and markdown reporting all work. No adapters yet (`cases` is a stub), no LLM judge yet (`judge`-type criteria are recorded as errors, not graded), no calibration or compare mode.

## Quickstart

```bash
./scripts/setup.sh
source .venv/bin/activate
agent-eval run --dataset examples/oracle_dataset.jsonl --rubric examples/oracle_rubric.json --out runs/
```

This writes `runs/<timestamp>-self-test/{results.jsonl,errors.jsonl,run.json,report.md}`. Re-run against `examples/null_dataset.jsonl` with the same rubric and every criterion should fail — that's the harness self-test described in REQUIREMENTS.md FR-29, wrapped in [scripts/selftest.sh](scripts/selftest.sh).

## Layout

- `agent_eval/cases.py` — case schema (FR-1) and dataset loading/hashing.
- `agent_eval/rubric.py` — rubric schema, loading, and validation (FR-5–FR-7).
- `agent_eval/checks/builtin.py` — the built-in check library (FR-8).
- `agent_eval/runner.py` — runs a rubric against a dataset, writes the run folder.
- `agent_eval/report.py` — renders `report.md` from a run's verdicts and errors.
- `agent_eval/cli.py` — the `agent-eval` command (`run`, `report`; `cases`/`calibrate`/`compare` are stubs for later milestones).
- `examples/` — the oracle/null self-test fixtures.
- `tests/` — runs fully offline, no network or API key needed (NFR-5).

## Writing a rubric

A rubric is a JSON file with `name`, `version`, and a list of `criteria`. See `examples/oracle_rubric.json` for a worked example covering most of the built-in checks, and REQUIREMENTS.md sections 5–6 for the Job Search Agent and SPIFFE rubrics this harness is meant to grade next.
