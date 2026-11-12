#!/usr/bin/env bash
# Creates a local virtualenv and installs the project (with the optional LLM and test extras).
# Works on macOS and Linux. Override the interpreter with: PYTHON=python3.12 ./scripts/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: $PYTHON not found. On macOS: brew install python@3.12  (https://brew.sh)" >&2
  exit 1
fi
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "error: $("$PYTHON" --version 2>&1) is too old; this project needs Python 3.10 or newer." >&2
  echo "  macOS: brew install python@3.12, then run: PYTHON=python3.12 ./scripts/setup.sh" >&2
  exit 1
fi

"$PYTHON" -m venv .venv
. .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -e ".[llm,dev]"
echo "Done ($(python --version)). Activate with: source .venv/bin/activate"
