#!/usr/bin/env bash
# Runs the whole flow on localhost against the made-up fixtures in examples/manifests.
# Nothing outside this folder is scanned. Run from the project folder: ./scripts/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG=examples/demo.config.json
export SPIFFE_ADMIN_TOKEN="${SPIFFE_ADMIN_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')}"

python3 -m spiffe_identity.server --config "$CONFIG" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
for _ in $(seq 1 20); do [ -f .data/demo/bundle.pem ] && break; sleep 0.25; done
sleep 0.5

echo; echo "== 1. plan (read-only: discover + propose) =="
python3 -m spiffe_identity.cli plan --config "$CONFIG"

echo; echo "== 2. apply (you approve each identity) =="
python3 -m spiffe_identity.cli apply --config "$CONFIG" --approver "${USER:-demo}" --issue-dir out/

echo; echo "== 3. verify the issued X.509-SVIDs =="
for d in out/*/; do
  [ -f "$d/svid.pem" ] && python3 -m spiffe_identity.cli verify-x509 --cert "$d/svid.pem" --bundle "$d/bundle.pem"
done
echo; echo "Done. Delete .data/ and out/ to start over."
