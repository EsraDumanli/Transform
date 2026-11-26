#!/usr/bin/env bash
# Runs the harness self-test (FR-29): an oracle dataset that should score ~100% and
# a null dataset (empty outputs) that should score ~0%, through the whole pipeline.
# Run from the project folder: ./scripts/selftest.sh
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/_python.sh

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "== oracle dataset (expect ~100% pass) =="
"$PY" -m agent_eval.cli run --dataset examples/oracle_dataset.jsonl --rubric examples/oracle_rubric.json --out "$OUT"

echo; echo "== null dataset (expect ~0% pass) =="
"$PY" -m agent_eval.cli run --dataset examples/null_dataset.jsonl --rubric examples/oracle_rubric.json --out "$OUT"

echo; echo "Self-test run folders are under $OUT (deleted on exit)."
