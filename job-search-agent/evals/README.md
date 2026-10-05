# Job Search Agent Evaluation Framework

This directory contains comprehensive tests to validate the job search agent's ability to:
- Extract and parse resumes accurately
- Match job postings to candidate profiles with correct tier classification
- Detect and deduplicate identical postings across runs
- Handle edge cases and formatting variations

## Structure

```
evals/
├── README.md                    # This file
├── conftest.py                  # Shared pytest fixtures
├── eval_config.yaml             # Configuration for different test modes
├── fixtures/
│   ├── sample_resumes/
│   │   ├── pm_resume.txt
│   │   ├── eng_resume.txt
│   │   └── sparse_resume.txt
│   ├── sample_companies.json
│   └── sample_responses.json
├── unit/
│   ├── test_searcher_parsing.py
│   ├── test_resume_extraction.py
│   ├── test_prompt_building.py
│   └── test_dedup_logic.py
├── integration/
│   ├── test_end_to_end_search.py
│   ├── test_dedup_correctness.py
│   └── test_schedule_execution.py
└── behavioral/
    ├── test_match_quality.py
    ├── test_tier_accuracy.py
    └── test_fresh_results.py
```

## Running Evals

### Fast unit tests (no API calls, ~30s)
```bash
cd job-search-agent
pytest evals/unit -v
```

### Integration tests (mocked API, ~1-2m)
```bash
pytest evals/unit evals/integration -v
```

### Full suite with real API (slow, requires ANTHROPIC_API_KEY)
```bash
export ANTHROPIC_API_KEY="sk-..."
pytest evals/ -v --run-slow
```

## Test Scenarios

Each test file focuses on one aspect of the agent's behavior:

### Unit Tests
- **test_searcher_parsing.py**: JSON extraction, tier validation, field requirements
- **test_resume_extraction.py**: PDF, DOCX, TXT parsing quality
- **test_prompt_building.py**: Prompt structure, company inclusion, token budgets
- **test_dedup_logic.py**: Dedup key generation, collision detection

### Integration Tests
- **test_end_to_end_search.py**: Full pipeline from resume upload to DB insert
- **test_dedup_correctness.py**: Multi-run dedup verification
- **test_schedule_execution.py**: Scheduler job creation and execution

### Behavioral Tests (slow, real API)
- **test_match_quality.py**: Resume-to-job matching accuracy
- **test_tier_accuracy.py**: Strong/good/watch classification correctness
- **test_fresh_results.py**: No duplicate reporting across runs

## Quality Metrics

### Accuracy
- Tier classification correctness (expected vs actual)
- Match count accuracy (false positives, false negatives)
- Resume understanding (inferred vs provided roles)

### Sensitivity
- Dedup stability (same posting never re-added)
- Case/whitespace robustness (Acme vs ACME vs acme)
- Title normalization ("Senior PM" vs "Sr. Product Mgr")

### Reliability
- Error handling for malformed API responses
- Graceful degradation under API limits
- Schedule execution consistency
