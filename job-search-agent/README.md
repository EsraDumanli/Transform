# Job Search Agent

A small, self-hosted tool that searches the web for job postings matching
*your* resume, and shows them on a simple dashboard. Upload a resume, list
the companies (or job boards) you want checked, and run it on demand or on a
schedule.

It doesn't scrape or maintain its own job index. Instead, each run hands your
resume and company list to Claude, which uses its built-in web search tool to
check those companies' career pages (and the open web generally) for roles
that fit, and scores each one as a **strong**, **good**, or **watch** match.
New postings are saved to a local database so re-runs only surface what's
actually new.

## Features

- Accounts with email/password login -- each person only ever sees their own
  profiles, resumes, and results.
- Upload a resume (PDF, DOCX, or plain text) -- no manual retyping of your background.
- List any companies or career-page URLs you want checked; leave it blank and
  it searches broadly based on your resume and target roles instead.
- Every profile can run **on-demand** (click a button) and/or **on a
  schedule** (daily, weekly, or a custom cron expression) -- pick whichever
  fits, per profile.
- Multiple people can use the same instance, each with their own account --
  there's no hard-coded resume or company list baked into the app.
- Automatic de-duplication: postings already on a profile's dashboard are
  never re-added, and prior generated data on a row is never touched by a
  later run.
- All data stays in a local SQLite database on whatever machine you run this
  on. Nothing is sent anywhere except to the Anthropic API to do the search.

Every clone of this repo starts completely empty -- no accounts, no
profiles, no sample data. Cloning it and running it is how you get *your
own* private instance; nothing from anyone else's copy (including whoever
you got the link from) comes with it. Data only ever exists in the local
`data/job_agent.db` file that gets created the first time you run the app,
which is gitignored and never leaves your machine.

## Requirements

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com/) (the search itself
  runs through Claude's web search tool)

## Setup

**Option A -- one command:**

```bash
git clone <this-repo-url>
cd job-search-agent
./scripts/setup.sh          # Windows: scripts\setup.bat
```

This creates a virtual environment, installs dependencies, and creates your
`.env` file with a random session secret already filled in. It'll tell you
the one thing you still need to do by hand: add your own `ANTHROPIC_API_KEY`
to `.env`.

**Option B -- by hand:**

```bash
git clone <this-repo-url>
cd job-search-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and add your ANTHROPIC_API_KEY and a random FLASK_SECRET_KEY
python app.py
```

Either way, then run:

```bash
source .venv/bin/activate   # if not already active
python app.py
```

and open **http://localhost:5000**. Sign up for an account (this account
exists only in your local database -- there's no shared server anywhere),
click "New profile", upload a resume, add some companies, and either run a
search now or set a schedule.

### Starting over with a clean slate

If you want to wipe your local accounts/profiles/postings and start fresh
without re-cloning:

```bash
python scripts/reset_local_data.py
```

This only touches your own `data/` and `uploads/` folders -- it has no way
to affect anyone else's copy of the app.

## How scheduling works

The app runs an in-process scheduler ([APScheduler](https://apscheduler.readthedocs.io/))
that fires while `python app.py` is running. That's enough for running this
on a machine or small server that stays up. A few things to know:

- **Don't run multiple copies of `app.py` behind a load balancer** without
  extra work -- each copy would run its own scheduler and you'd get
  duplicate searches. For a single self-hosted instance (the common case)
  this isn't a concern.
- If you'd rather trigger runs from your own cron / CI schedule instead of
  the built-in scheduler, use `scripts/run_once.py`:

  ```bash
  python scripts/run_once.py --slug jane-smith
  python scripts/run_once.py --all
  ```

  and set every profile's schedule to "on-demand only" in the UI so the
  built-in scheduler doesn't also fire.

## How matching works

Each run sends Claude:
- the extracted text of the uploaded resume,
- any target-role keywords you entered (or "infer from the resume" if left blank),
- the list of companies/URLs to check,
- a compact list of postings already found on a previous run (so it doesn't re-report them).

Claude uses the `web_search` tool (server-side, built into the Anthropic API)
to check each company and returns a JSON list of new postings with a fit
tier. The app parses that JSON, generates a de-duplication key per posting
(company + job ID, or company + normalized title if no ID is shown), and
inserts only the ones it hasn't seen before.

You can change the model via `JOB_AGENT_MODEL` in `.env` -- any current
Claude model with web search support works. See
[the model list](https://docs.claude.com/en/docs/about-claude/models) for
what's currently available.

**Cost note:** the Anthropic web search tool is billed per search
(check [current pricing](https://docs.claude.com/en/docs/agents-and-tools/tool-use/web-search-tool))
plus normal token costs. A run against a dozen companies typically uses on
the order of a dozen-plus searches; `JOB_AGENT_MAX_SEARCHES` in `.env` caps
this per run if you want a hard ceiling.

## Project layout

```
app.py                        Flask routes / web UI
core/
  auth.py                      Password hashing + Flask-Login user object
  resume_parser.py              PDF/DOCX/TXT -> plain text
  db.py                          SQLite schema + queries (users, profiles, companies, postings, runs)
  searcher.py                     Builds the prompt, calls Claude + web_search, parses results
  scheduler.py                     APScheduler wiring for on-demand + recurring runs
templates/, static/            Web UI
scripts/setup.sh, setup.bat    One-command bootstrap for a fresh clone
scripts/reset_local_data.py    Wipe your own local data and start over
scripts/run_once.py            CLI runner (for external cron, or manual testing)
tests/                          pytest unit tests for the pieces above
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests cover resume parsing, the SQLite layer, and the search/dedup logic
(with the Anthropic API mocked out -- no API key or network access needed to
run the test suite).

## Accounts & security

- Each profile belongs to exactly one account. Every route that reads or
  changes a profile checks that it belongs to the logged-in user; a mismatch
  returns a 404 (not a 403), so a guessed or leaked URL can't even confirm
  that a profile with that name exists.
- Passwords are hashed with Werkzeug's `generate_password_hash` (PBKDF2) --
  plain-text passwords are never stored. Login timing is constant whether or
  not the email exists, to avoid leaking which emails are registered.
- All forms are protected against CSRF via Flask-WTF.
- Session cookies are `HttpOnly` and `SameSite=Lax` by default. If you deploy
  this behind HTTPS (which you should, for anything beyond localhost), set
  `SESSION_COOKIE_SECURE=1` in your environment so cookies are never sent
  over plain HTTP.

**What this does *not* include**, and what to add before a public deployment:
- Email verification or password-reset flows -- signup is instant and
  there's no way to recover a forgotten password except editing the database
  directly.
- Brute-force / rate limiting on login attempts.
- Any kind of admin role, team sharing, or account deletion UI.

For personal or small-team self-hosting behind your own network or a
reverse proxy with TLS, the built-in auth is enough to keep users' resumes
and results private from each other. For a genuinely public, internet-facing
deployment, treat the items above as a pre-launch checklist.

## Data & privacy

Resumes and search results are stored in plain text in a local SQLite file
(`data/job_agent.db` by default) -- not encrypted at rest. Anyone with direct
access to that file (e.g. shell access to the host) can read every user's
resume, regardless of the web-layer auth above. Keep normal server hygiene in
mind: restrict who can log into the host, and back up (or don't) the way you
would for any file containing personal data.

## Limitations / ideas for contributions

- Company career pages that render entirely client-side (heavy JS, no
  server-rendered content) are sometimes hard for web search to read
  accurately; results for those are still useful as leads but worth
  double-checking manually.
- The scheduler is in-process; a more robust production setup would run
  `scripts/run_once.py` from an external scheduler (cron, systemd timers,
  a hosted cron service) instead.
- PRs welcome for email verification / password reset, encryption at rest,
  resume-vs-posting match explanations, export to CSV, etc.

## License

MIT -- see [LICENSE](LICENSE).
