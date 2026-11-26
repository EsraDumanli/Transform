# agent-evaluator

A report-only harness that grades any agent's outputs against a rubric: deterministic checks always run; an optional Claude judge only handles what a rule can't decide. It never changes, blocks, or deletes anything in the agent it grades.

The design is fully specified in [REQUIREMENTS.md](REQUIREMENTS.md) — read it before making a structural change. It records decisions already made, the functional/non-functional requirements (FR-*/NFR-*), the two example rubrics (Job Search Agent, SPIFFE identity), the milestone plan (M1–M5), and nine open questions (Q1–Q9) in section 9 that only the repo owner can answer. If a change touches one of those open questions, ask rather than guessing.

## Current status

M1 (skeleton) is built: case schema, rubric loader/validator, the full built-in deterministic check library, the runner, `results.jsonl`/`errors.jsonl`/`run.json`/`report.md` output, and the oracle/null self-test (FR-29). No adapters (M2), no LLM judge execution (M3 — `judge`-type criteria are recorded as `judge_not_implemented` errors, never graded), no calibration (M4), no compare mode or HTML report (M5).

## Working in this repo

- **Report only.** Never add code that mutates, blocks, or deletes something in the agent under test (N2). This harness reads subject data read-only (FR-3) and only ever writes under `runs/`.
- **No silent defaults** (NFR-4). A missing path, budget, or threshold is an error that names the missing key — never a fallback value. An `insufficient_information`/`not_applicable`/`error` verdict is always preferred over guessing, and errors are never counted as failures.
- **Criteria are atomic** (FR-6): one gradable property per criterion, never a blended "overall quality" score.
- **Everything in `agent_eval/` must run offline** (NFR-5): no network calls and no API key required to pass `pytest`. `url_reachable` and the future LLM judge are opt-in per run and gated behind explicit flags.
- **Determinism matters** (NFR-6): case order is sorted by id, and the rubric/dataset are hashed into every run manifest. Don't introduce dict-ordering or filesystem-ordering dependence.
- Run the test suite from this folder after any change: `./scripts/setup.sh && source .venv/bin/activate && pytest -q`. `./scripts/selftest.sh` exercises the CLI end-to-end against `examples/oracle_dataset.jsonl` (expect ~100% pass) and `examples/null_dataset.jsonl` (expect ~0% pass).
- New built-in checks go in `agent_eval/checks/builtin.py` and get registered via `register_check`; a check function must never raise past `run_check` — catch and return `CheckResult(STATUS_ERROR, ...)` instead, so a buggy check can't crash a run.
- Match the sibling projects' conventions (see `../agent-identity-spiffe`): `pyproject.toml` + `requirements*.txt` + `scripts/setup.sh` + `scripts/_python.sh`, Python 3.10+, macOS/Linux only, nothing hosted or multi-user (N4).
