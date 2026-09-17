"""Job Search Agent -- a small self-hosted tool that takes a resume and a
list of target companies, searches the web for matching job postings using
Claude, and shows them on a dashboard. Supports both on-demand and scheduled
(recurring) searches per profile.

Run it with:
    python app.py
then open http://localhost:5000
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()  # so ANTHROPIC_API_KEY etc. from .env are available before anything else runs

from flask import Flask, abort, flash, redirect, render_template, request, url_for, jsonify
from flask_login import (current_user, login_required, login_user, logout_user)
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

from core import db, scheduler
from core.auth import User, login_manager, hash_password, verify_password, password_error
from core.resume_parser import extract_text, UnsupportedResumeFormat
from core.searcher import SearchError

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB, generous for a resume

# Session cookie hardening. SESSION_COOKIE_SECURE is opt-in via env because it
# requires the app to actually be served over HTTPS (it'll silently break
# login over plain http:// otherwise) -- turn it on once you've got TLS in
# front of this, e.g. behind a reverse proxy.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]

login_manager.init_app(app)
csrf = CSRFProtect(app)

WEEKDAYS = [("mon", "Monday"), ("tue", "Tuesday"), ("wed", "Wednesday"),
            ("thu", "Thursday"), ("fri", "Friday"), ("sat", "Saturday"), ("sun", "Sunday")]


def _get_owned_profile_or_404(slug: str):
    """Fetch a profile by slug and 404 (not 403) unless it belongs to the
    logged-in user -- a 403 would confirm the slug exists, which is exactly
    the kind of leak that matters for something guessable like a name-based
    slug. Every route that touches a specific profile must go through this."""
    profile = db.get_profile_by_slug(slug)
    if profile is None or profile["user_id"] != current_user.id:
        abort(404)
    return profile


def _parse_companies_field(raw: str) -> list[dict]:
    """Parse the companies textarea: one per line, either "Name" or
    "Name, https://url"."""
    companies = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "," in line:
            name, url = line.split(",", 1)
            companies.append({"name": name.strip(), "url": url.strip() or None})
        else:
            companies.append({"name": line, "url": None})
    return companies


def _companies_to_field(companies) -> str:
    lines = []
    for c in companies:
        if c["url"]:
            lines.append(f"{c['name']}, {c['url']}")
        else:
            lines.append(c["name"])
    return "\n".join(lines)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))

        err = password_error(password, confirm)
        if err:
            flash(err, "error")
            return redirect(url_for("register"))

        if db.get_user_by_email(email) is not None:
            flash("An account with that email already exists. Try logging in instead.", "error")
            return redirect(url_for("login"))

        user_id = db.create_user(email, hash_password(password))
        login_user(User.get(user_id))
        flash("Account created.", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        row = db.get_user_by_email(email)
        # Always run check_password_hash even on a missing user (against a
        # fixed dummy hash) so a wrong email and a wrong password take the
        # same amount of time -- otherwise timing differences leak which
        # emails are registered.
        password_hash = row["password_hash"] if row else \
            "pbkdf2:sha256:600000$dummy$0000000000000000000000000000000000000000000000000000000000000000"
        ok = verify_password(password, password_hash) and row is not None
        if not ok:
            flash("Incorrect email or password.", "error")
            return redirect(url_for("login"))
        login_user(User.get(row["id"]), remember=True)
        flash("Logged in.", "success")
        next_url = request.args.get("next")
        return redirect(next_url or url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    profiles = db.list_profiles(user_id=current_user.id)
    profiles_with_meta = []
    for p in profiles:
        last = db.last_run(p["id"])
        postings = db.list_postings(p["id"])
        profiles_with_meta.append({
            "profile": p,
            "last_run": last,
            "posting_count": len(postings),
        })
    return render_template("index.html", profiles=profiles_with_meta)


@app.route("/new")
@login_required
def new_profile_form():
    return render_template("new_profile.html", weekdays=WEEKDAYS)


@app.route("/profiles", methods=["POST"])
@login_required
def create_profile():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip() or None
    target_roles = request.form.get("target_roles", "").strip() or None
    companies_raw = request.form.get("companies", "")
    schedule_type = request.form.get("schedule_type", "none")
    schedule_time = request.form.get("schedule_time") or None
    schedule_day = request.form.get("schedule_day") or None
    schedule_cron = request.form.get("schedule_cron") or None

    if not name:
        flash("Please enter your name (used to label this profile).", "error")
        return redirect(url_for("new_profile_form"))

    resume_file = request.files.get("resume")
    if not resume_file or not resume_file.filename:
        flash("Please upload a resume file (PDF, DOCX, or TXT).", "error")
        return redirect(url_for("new_profile_form"))

    filename = secure_filename(resume_file.filename)
    try:
        resume_text = extract_text(resume_file.read(), filename)
    except UnsupportedResumeFormat as e:
        flash(str(e), "error")
        return redirect(url_for("new_profile_form"))

    companies = _parse_companies_field(companies_raw)

    profile_id = db.create_profile(
        user_id=current_user.id,
        name=name,
        email=email,
        resume_text=resume_text,
        resume_filename=filename,
        target_roles=target_roles,
        companies=companies,
        schedule_type=schedule_type,
        schedule_time=schedule_time,
        schedule_day=schedule_day,
        schedule_cron=schedule_cron,
    )
    scheduler.schedule_profile(profile_id)

    profile = db.get_profile(profile_id)
    flash(f"Profile created for {name}. Run a search whenever you're ready.", "success")
    return redirect(url_for("dashboard", slug=profile["slug"]))


@app.route("/p/<slug>")
@login_required
def dashboard(slug):
    profile = _get_owned_profile_or_404(slug)
    postings = db.list_postings(profile["id"])
    companies = db.get_companies(profile["id"])
    runs = db.list_runs(profile["id"], limit=10)
    counts = {"strong": 0, "good": 0, "watch": 0}
    for p in postings:
        counts[p["tier"]] = counts.get(p["tier"], 0) + 1
    return render_template(
        "dashboard.html",
        profile=profile,
        postings=postings,
        companies=companies,
        companies_field=_companies_to_field(companies),
        runs=runs,
        counts=counts,
        weekdays=WEEKDAYS,
    )


@app.route("/p/<slug>/run", methods=["POST"])
@login_required
def run_now(slug):
    profile = _get_owned_profile_or_404(slug)
    scheduler.run_now(profile["id"])
    flash("Search started in the background -- refresh in a minute or two to see results.", "success")
    return redirect(url_for("dashboard", slug=slug))


@app.route("/p/<slug>/status.json")
@login_required
def status_json(slug):
    profile = _get_owned_profile_or_404(slug)
    last = db.last_run(profile["id"])
    return jsonify({
        "status": last["status"] if last else None,
        "started_at": last["started_at"] if last else None,
        "finished_at": last["finished_at"] if last else None,
        "new_postings_count": last["new_postings_count"] if last else 0,
        "error_message": last["error_message"] if last else None,
        "posting_count": len(db.list_postings(profile["id"])),
    })


@app.route("/p/<slug>/schedule", methods=["POST"])
@login_required
def update_schedule(slug):
    profile = _get_owned_profile_or_404(slug)

    schedule_type = request.form.get("schedule_type", "none")
    schedule_time = request.form.get("schedule_time") or None
    schedule_day = request.form.get("schedule_day") or None
    schedule_cron = request.form.get("schedule_cron") or None

    db.update_schedule(
        profile["id"],
        schedule_type=schedule_type,
        schedule_time=schedule_time,
        schedule_day=schedule_day,
        schedule_cron=schedule_cron,
    )
    scheduler.schedule_profile(profile["id"])
    flash("Schedule updated.", "success")
    return redirect(url_for("dashboard", slug=slug))


@app.route("/p/<slug>/companies", methods=["POST"])
@login_required
def update_companies(slug):
    profile = _get_owned_profile_or_404(slug)
    companies = _parse_companies_field(request.form.get("companies", ""))
    db.replace_companies(profile["id"], companies)
    flash("Company list updated.", "success")
    return redirect(url_for("dashboard", slug=slug))


@app.route("/p/<slug>/delete", methods=["POST"])
@login_required
def delete_profile(slug):
    profile = _get_owned_profile_or_404(slug)
    sched = scheduler.get_scheduler()
    if sched:
        job_id = f"profile-search-{profile['id']}"
        if sched.get_job(job_id):
            sched.remove_job(job_id)
    db.delete_profile(profile["id"])
    flash(f"Deleted profile for {profile['name']}.", "success")
    return redirect(url_for("index"))


@app.errorhandler(SearchError)
def handle_search_error(e):
    flash(f"Search failed: {e}", "error")
    return redirect(url_for("index"))


def create_app():
    db.init_db()
    scheduler.init_scheduler()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    # use_reloader is forced off: the reloader spawns a second process, which
    # would start a second background scheduler and double-run every job.
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
