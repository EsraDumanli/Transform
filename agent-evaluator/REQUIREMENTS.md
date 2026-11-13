# Agent Evaluator: Requirements (draft v0.1)

**Status:** draft for review. Nothing is built yet. Items marked **[OPEN]** are decisions only you can make. They're collected in [section 9](#9-open-questions); the rest of this document is written so it holds whichever way you answer them.

## 1. Purpose

A reusable harness that takes the **outputs of any agent**, grades them against a **rubric**, and produces a **report**. It's an "LLM-as-a-judge" harness, but cheap, repeatable checks come first and the LLM judge is only used where a rule can't decide.

Decisions already made (from our conversation):

| Decision | Choice |
|---|---|
| What it judges | Any agent, through a generic harness. The Job Search Agent and the SPIFFE identity proposals plug in as adapters. |
| How it judges | Deterministic checks always run. An optional Claude judge handles subjective criteria, only when enabled. |
| What it does with verdicts | **Report only.** It never changes, blocks or deletes anything in the agent it judges. |
| Where it lives | New top-level project `agent-evaluator/` in this repo: modular, runs locally, on macOS and Linux. |

## 2. Goals and non-goals

**Goals**
- G1. Answer "how good are this agent's outputs, and where exactly do they fail?" with evidence per item.
- G2. Work on outputs from any agent, through small adapters, with no changes to the agents themselves.
- G3. Be cheap by default: a full run with the LLM judge off costs nothing.
- G4. Be trustworthy: the judge itself is measured against human labels before its scores are relied on.
- G5. Be reproducible: the same inputs, rubric and settings give the same deterministic results, and LLM-judge variance is measured and reported.

**Non-goals (v1)**
- N1. Running or controlling the agent under test. The harness grades outputs that already exist. Re-running the agent to generate fresh outputs is a possible v2 feature.
- N2. Gating or blocking actions. Report only, as decided.
- N3. Optimising or rewriting the agent's prompts automatically.
- N4. A hosted service, multi-user access, or a database server.

## 3. Concepts

| Term | Meaning |
|---|---|
| **Subject** | The agent being evaluated, e.g. `job-search-agent`. |
| **Case** | One item to grade: the input the agent got, the output it produced, and optionally a reference (expected) answer and metadata. |
| **Dataset** | A versioned set of cases (a JSONL file). |
| **Adapter** | Code that reads a subject's native output, such as the Job Search Agent's SQLite database, and turns it into cases. |
| **Rubric** | A versioned list of **criteria**. |
| **Criterion** | One independently gradable property, such as "posting link resolves" or "role matches target roles". Each criterion is either a **check** (deterministic) or a **judge** (LLM). |
| **Verdict** | The result of one criterion on one case: `pass`, `fail` or `not_applicable`, plus a score where relevant, a reason, and evidence. |
| **Error** | A criterion that couldn't be evaluated (network down, API error, unparseable judge output). Errors are recorded separately and **never counted as a fail**. |
| **Run** | One execution of rubric × dataset, producing results plus a report. |

## 4. Functional requirements

### 4.1 Inputs
- **FR-1:** Load cases from a JSONL file following a documented case schema: `id`, `subject`, `input`, `output`, optional `reference`, optional `metadata`, optional `tags`.
- **FR-2:** Adapters convert a subject's native output into that schema. v1 ships with:
  - FR-2a: **Job Search Agent adapter.** It reads postings from `data/job_agent.db`, read-only, and makes one case per posting, with the profile's target roles, resume reference and companies as input. **[OPEN Q1, Q2]**
  - FR-2b: **SPIFFE adapter.** It reads the portal's saved scan snapshot and makes one case per proposed identity, with the workload attributes as input and the proposed ID plus rationale as output.
- **FR-3:** Adapters never write to the subject's data. They open files read-only.
- **FR-4:** There are no default data sources. Each run names its dataset or adapter and its source path explicitly. A missing input is an error that names what's missing.

### 4.2 Rubrics
- **FR-5:** A rubric is a JSON file with `name`, `version`, and a list of criteria. Each criterion has `id`, `type` (`check` or `judge`), `description`, `applies_to` (an optional filter on tags), `weight`, and `severity` (`critical`, `major` or `minor`).
- **FR-6:** Criteria are **atomic**: one property each, never a blended "overall quality" score.
- **FR-7:** The harness validates the rubric before running and refuses unknown check types, duplicate ids, and judge criteria without a concrete scale.

### 4.3 Deterministic checks (always on, free)
- **FR-8:** A built-in check library:
  - `required_fields`: fields are present and non-empty.
  - `json_schema`: output matches a schema.
  - `regex` and `not_regex`: text matches or doesn't match a pattern.
  - `enum`: a value is one of an allowed set.
  - `range`: a number is within bounds.
  - `duplicate`: no two cases share the same key.
  - `reference_match`: exact or normalised match against `reference`. Normalisation covers whitespace, case and punctuation.
  - `url_reachable`: an HTTP HEAD/GET returns 2xx/3xx. **Network use is opt-in per run** (FR-9).
  - `spiffe_id_valid`: the SPIFFE ID is valid, in the expected trust domain, and its path follows the naming policy.
- **FR-9:** Any check that touches the network is off unless the run enables it. It respects a timeout and a per-host rate limit, and a network failure is an **error**, never a fail.
- **FR-10:** Custom checks are plain Python functions registered by name, so a subject can add its own without changing the core.

### 4.4 LLM judge (optional, off by default)
- **FR-11:** Each `judge` criterion is graded by a **separate** Claude call. Criteria are never batched into one blended prompt.
- **FR-12:** Every judge criterion defines its scale explicitly: either `pass/fail` or an anchored 1–5 scale with a written description for each level.
- **FR-13:** The judge returns structured output with a fixed JSON schema: `verdict` or `score`, `reason`, `evidence` (quoted spans from the case), and `insufficient_information` (true/false). It's told to prefer `insufficient_information` over guessing, matching the "never assume" rule used across this repo.
- **FR-14:** Agent outputs are framed as **untrusted data, not instructions**, so a posting or agent card containing "ignore previous instructions" can't steer the judge.
- **FR-15:** Bias controls:
  - The judge is told not to reward length.
  - It's never told which answer is a reference or baseline.
  - For pairwise comparisons, if added later, order is randomised per case.
- **FR-16:** **Privacy allowlist.** Only the case fields listed in the rubric's `send_fields` are sent to the API. For example, resume text is never sent unless you list it. **[OPEN Q4]**
- **FR-17:** **Cost controls:**
  - a `--dry-run` that shows which cases and criteria would be judged, plus a rough upper-bound cost estimate, without calling the API,
  - a `max_cases` limit, and a hard spending cap per run that stops judging when reached, **[OPEN Q5]**
  - actual tokens and cost recorded from each API response's `usage`, never estimated after the fact.
- **FR-18:** Judge model: Claude Opus 5.5 (`claude-opus-5-5`) by default, configurable per rubric. The served model recorded in each response is checked against the requested model; a mismatch is flagged in the report. **[OPEN Q6]**
- **FR-19:** API problems are retried with backoff and a capped number of attempts:
  - rate limits, server errors and timeouts are retried, and the attempt count is recorded,
  - a refusal or a truncated reply is recorded as its own status, never as a fail.

### 4.5 Judging the judge (calibration)
- **FR-20:** A **calibration mode** runs the judge on a set of cases you labelled by hand and reports agreement per criterion: percent agreement plus a confusion matrix.
- **FR-21:** The report marks any judge criterion that hasn't been calibrated, or whose agreement is below a threshold, as **"uncalibrated, don't rely on it yet"**. **[OPEN Q7]**
- **FR-22:** A **known-negatives** test feeds each judge criterion an empty output, "I don't know", and an answer to the wrong question, and confirms all three fail.
- **FR-23:** A **repeatability** test judges the same case twice and reports how often the verdict changes.

### 4.6 Results and reporting
- **FR-24:** Every run writes a folder `runs/<timestamp>-<rubric>/` containing:
  - `results.jsonl`: one verdict per case × criterion, with reason and evidence,
  - `errors.jsonl`: evaluations that couldn't run, with a failure class,
  - `run.json`: the manifest, with rubric name, version and hash, dataset hash, adapter and source, judge model, harness version, settings, start and end times, and token totals and cost,
  - `judge_transcripts/`: the exact judge input and output per call, after the privacy filter, so any score can be traced,
  - `report.md`, plus `report.html` if wanted. **[OPEN Q8]**
- **FR-25:** The report shows:
  - pass rate per criterion, never blended into a single score unless asked,
  - **critical** failures listed first,
  - failures grouped by criterion with links to the cases,
  - error counts, kept separate from failures,
  - judge cost and calibration status,
  - for scores, the number of cases and a confidence interval, so small samples aren't over-read.
- **FR-26:** Aggregation fits the severity. For `critical` criteria (e.g. "posting is fabricated"), a single failure is highlighted, not averaged away.
- **FR-27:** **Compare mode** diffs two runs on the same dataset and rubric version: per criterion, which cases flipped pass→fail or fail→pass.

### 4.7 Interface
- **FR-28:** A CLI, `agent-eval`, with these commands:
  - `cases` (run an adapter and write a dataset),
  - `run` (grade a dataset against a rubric),
  - `calibrate`,
  - `compare`,
  - `report` (re-render the report from a run folder).
- **FR-29:** A harness self-test: an **oracle** dataset that should score about 100% and a **null** dataset (empty outputs) that should score about 0%, run through the whole pipeline. It catches wiring bugs before real runs.

## 5. Example rubric: Job Search Agent (to be refined with you)

| Id | Type | Severity | Criterion |
|---|---|---|---|
| `has_required_fields` | check | major | `company`, `role` and `link` present (`location`, `posting_date` and `job_id` are optional in the app's schema, so they're reported but not required) |
| `link_reachable` | check (network) | critical | `link` responds (opt-in network) |
| `company_matches_link` | check | major | the `link`'s domain matches the company's `url` from the profile, when the profile has one; otherwise `not_applicable` |
| `not_duplicate` | check | minor | no two postings share company + role + `job_id` |
| `tier_valid` | check | minor | `tier` is one of `strong`, `good`, `watch` |
| `role_fits_targets` | judge, pass/fail | major | `role` is one of the profile's `target_roles` or a clear equivalent |
| `tier_justified` | judge, pass/fail | major | the assigned `tier` is justified by the resume vs the posting (e.g. a `strong` tier isn't given to a role the resume clearly doesn't fit) |
| `description_grounded` | judge, pass/fail | critical | the posting `description` only states things the agent could have found, with no invented requirements, salaries or benefits (checked against the live page only if network checks are on; otherwise `insufficient_information`) |

These criteria use only columns that exist in the app's database (`postings`: company, role, location, posting_date, job_id, link, description, tier; `profiles`: target_roles, resume_text; `companies`: name, url). The app doesn't store a separate "why it matches" explanation, so there's no criterion for one. **[OPEN Q2]**

## 6. Example rubric: SPIFFE identity proposals

| Id | Type | Severity | Criterion |
|---|---|---|---|
| `id_valid` | check | critical | valid SPIFFE ID in the configured trust domain |
| `path_follows_policy` | check | major | path prefix matches the workload kind (e.g. `/mcp/…` for MCP servers) |
| `selector_strength` | check | major | doesn't rely only on weak selectors (e.g. `net:addr`) |
| `id_justified_by_attributes` | judge, pass/fail | critical | every path segment comes from an observed attribute; nothing invented |
| `not_overbroad` | judge, pass/fail | major | the ID wouldn't plausibly fit unrelated workloads (e.g. "any `app.py`") |

## 7. Non-functional requirements

- **NFR-1 (Modular):** standalone Python package, `pip install -e .`, with one module per concern: `cases`, `adapters/`, `rubric`, `checks/`, `judge`, `runner`, `report`, `calibrate`. Each adapter and check stays independent.
- **NFR-2 (Portable):** Python 3.10+, macOS and Linux, setup scripts like the other projects. Downloadable and pushable to GitHub as-is.
- **NFR-3 (Privacy):** nothing leaves the machine unless the LLM judge or network checks are explicitly enabled. Run folders are git-ignored by default, because they may contain resume excerpts.
- **NFR-4 (No assumptions):** no default data, paths, budgets or thresholds that silently apply. Missing values are errors that name the missing key. An "insufficient information" verdict is always available, and it's reported as such, not as a pass or fail.
- **NFR-5 (Testable offline):** the full test suite runs without network access or an API key, using a fake judge client.
- **NFR-6 (Reproducible):** sorted, deterministic case order; the rubric and dataset hashed in every run manifest; dependencies pinned.
- **NFR-7 (Honest output):** the report states what wasn't evaluated and why (disabled, errored, uncalibrated) rather than leaving it out.

## 8. Milestones (proposed)

1. **M1: skeleton.** Case schema, rubric loader and validator, deterministic check library, runner, `results.jsonl`, `errors.jsonl` and markdown report, oracle and null self-tests. No LLM, no network.
2. **M2: adapters.** Job Search Agent (read-only SQLite) and SPIFFE (scan snapshot), plus the two example rubrics.
3. **M3: LLM judge.** Structured-output judge, privacy allowlist, dry-run, cost cap, transcripts.
4. **M4: calibration.** Labelling file format, agreement report, known-negatives and repeatability tests.
5. **M5: compare mode and HTML report.**

M1 and M2 cost nothing to run. API credit is needed from M3 onward, and only when you enable the judge.

## 9. Open questions

Decisions only you can make. Each one changes what gets built.

1. **Q1: First subject.** Which adapter should come first: the Job Search Agent, SPIFFE, or both in M2?
2. **Q2: Job Search data.** Do you already have postings in `data/job_agent.db` from earlier runs? Without them (your API balance is low), M2 needs a small hand-made sample dataset, and I won't invent realistic-looking postings without you agreeing to clearly labelled synthetic ones.
3. **Q3: Criteria.** Are the criteria in sections 5 and 6 the right ones? What should be added, removed, or have its severity changed?
4. **Q4: Privacy.** May the judge ever see resume text, or only the parsed target roles and a short skills summary you write yourself?
5. **Q5: Budget.** What spending cap per run should the default config file use? There's no built-in default, but the example config needs a value you choose.
6. **Q6: Judge model.** Opus 5.5 by default. Do you want a cheaper model option (e.g. Sonnet 5.5 or Haiku 5.5) for bulk runs? That's your call on cost versus quality.
7. **Q7: Calibration.** How many cases are you willing to label by hand per criterion (e.g. 20–30), and what agreement threshold makes a judge "trusted"?
8. **Q8: Report format.** Markdown only, or also a self-contained HTML report like the portal?
9. **Q9: Re-running agents (v2).** Should a later version be able to re-run the agent on a fixed input set, so you can compare agent versions? That's where eval sets become most useful, but it costs API credit per run.
