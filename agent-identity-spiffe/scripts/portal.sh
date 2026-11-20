#!/usr/bin/env bash
# Starts the SPIFFE server and the portal for the localhost demo, then opens the portal.
# Usage: ./scripts/portal.sh "Your Name"   (the name is recorded on everything you approve)
# Stop both with Ctrl+C.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/_python.sh

if [ $# -lt 1 ] || [ -z "$1" ]; then
  echo "usage: $0 \"Your Name\"   (recorded as the approver on every identity you approve)" >&2
  exit 2
fi
APPROVER="$1"
CONFIG="${CONFIG:-examples/demo.config.json}"
export SPIFFE_ADMIN_TOKEN="${SPIFFE_ADMIN_TOKEN:-$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')}"

"$PY" -m spiffe_identity.server --config "$CONFIG" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
for _ in $(seq 1 20); do [ -f .data/demo/bundle.pem ] && break; sleep 0.25; done
sleep 0.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "error: the SPIFFE server did not start; see the message above." >&2
  exit 1
fi

URL="http://127.0.0.1:8765/"
(
  sleep 1.5
  if command -v open >/dev/null; then open "$URL"          # macOS
  elif command -v xdg-open >/dev/null; then xdg-open "$URL"  # Linux desktop
  fi
) >/dev/null 2>&1 &
"$PY" -m spiffe_identity.cli portal --config "$CONFIG" --approver "$APPROVER"
