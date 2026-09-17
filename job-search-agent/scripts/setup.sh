#!/usr/bin/env bash
# One-command bootstrap for a fresh clone: creates a virtualenv, installs
# dependencies, and sets up a local .env file. Doesn't touch data/ -- a new
# clone has no database until you run the app for the first time, and it's
# entirely local to your machine (see .gitignore).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v python3 &>/dev/null; then
  echo "python3 is required but wasn't found on PATH." >&2
  exit 1
fi

if [ ! -d .venv ]; then
  echo "Creating virtual environment in .venv ..."
  python3 -m venv .venv
fi

echo "Installing dependencies ..."
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example -- edit it now and add your ANTHROPIC_API_KEY"
  echo "and a random FLASK_SECRET_KEY (a suggestion has been filled in for you below)."
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  # Portable in-place sed for both GNU and BSD/macOS sed
  if sed --version >/dev/null 2>&1; then
    sed -i "s/^FLASK_SECRET_KEY=.*/FLASK_SECRET_KEY=${SECRET}/" .env
  else
    sed -i '' "s/^FLASK_SECRET_KEY=.*/FLASK_SECRET_KEY=${SECRET}/" .env
  fi
else
  echo ".env already exists -- leaving it as-is."
fi

echo ""
echo "Setup complete. Next steps:"
echo "  1. Open .env and set ANTHROPIC_API_KEY to your own key."
echo "  2. source .venv/bin/activate"
echo "  3. python app.py"
echo "  4. Open http://localhost:5000 and sign up for an account."
echo ""
echo "Your data (accounts, resumes, postings) lives only in data/job_agent.db"
echo "on this machine -- it's gitignored and never shared with anyone else's copy."
