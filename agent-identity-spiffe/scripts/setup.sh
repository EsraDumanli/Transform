#!/usr/bin/env bash
# Creates a local virtualenv and installs the project (with the optional LLM and test extras).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -e ".[llm,dev]"
echo "Done. Activate with: source .venv/bin/activate"
