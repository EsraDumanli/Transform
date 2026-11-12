# Sourced by the other scripts: picks this project's own Python and checks it is set up.
# Uses ./.venv if it exists, whatever environment happens to be active in the shell,
# so another project's virtualenv can't be picked up by accident.
if [ -x .venv/bin/python ]; then
  PY=.venv/bin/python
else
  PY="${PYTHON:-python3}"
fi
if ! "$PY" -c 'import cryptography, spiffe_identity' >/dev/null 2>&1; then
  echo "error: $PY is missing this project's packages (it is $("$PY" -c 'import sys; print(sys.executable)' 2>/dev/null || echo "not runnable"))." >&2
  echo "Fix it from the agent-identity-spiffe folder with:" >&2
  echo "  ./scripts/setup.sh" >&2
  exit 1
fi
