"""Background scheduling for recurring searches, plus the shared "run a
search for this profile" job used by both scheduled and on-demand runs.

Uses APScheduler's BackgroundScheduler, which runs inside the same process as
the Flask app. That's simple and fine for a single-process deployment (the
common case for a self-hosted tool like this); if you deploy with multiple
worker processes, run the scheduler in exactly one of them (e.g. a separate
`python scripts/run_scheduler.py` process) to avoid duplicate runs -- see the
README.
"""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from core import db
from core.searcher import search_jobs, SearchError

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _job_id(profile_id: int) -> str:
    return f"profile-search-{profile_id}"


def run_search_for_profile(profile_id: int) -> int:
    """Run one search pass for a profile and persist results. Returns the
    number of new postings found. Safe to call directly (on-demand) or from
    a scheduled trigger."""
    profile = db.get_profile(profile_id)
    if profile is None:
        log.warning("run_search_for_profile: profile %s no longer exists", profile_id)
        return 0

    companies = [dict(c) for c in db.get_companies(profile_id)]
    already_seen = [dict(p) for p in db.list_postings(profile_id)]

    run_id = db.start_run(profile_id)
    try:
        new_postings = search_jobs(
            resume_text=profile["resume_text"],
            target_roles=profile["target_roles"],
            companies=companies,
            already_seen=already_seen,
        )
        inserted = db.insert_postings(profile_id, new_postings)
        db.finish_run(run_id, status="success", new_postings_count=inserted)
        return inserted
    except SearchError as e:
        log.exception("Search failed for profile %s", profile_id)
        db.finish_run(run_id, status="error", error_message=str(e))
        raise
    except Exception as e:  # noqa: BLE001 -- want to record *any* failure
        log.exception("Unexpected error searching for profile %s", profile_id)
        db.finish_run(run_id, status="error", error_message=f"Unexpected error: {e}")
        raise


def _trigger_for_profile(profile) -> CronTrigger | None:
    schedule_type = profile["schedule_type"]
    if schedule_type == "none":
        return None
    if schedule_type == "daily":
        hour, minute = _parse_time(profile["schedule_time"])
        return CronTrigger(hour=hour, minute=minute)
    if schedule_type == "weekly":
        hour, minute = _parse_time(profile["schedule_time"])
        day = profile["schedule_day"] or "mon"
        return CronTrigger(day_of_week=day, hour=hour, minute=minute)
    if schedule_type == "cron":
        cron_expr = (profile["schedule_cron"] or "").strip()
        if not cron_expr:
            return None
        return CronTrigger.from_crontab(cron_expr)
    log.warning("Unknown schedule_type %r for profile %s", schedule_type, profile["id"])
    return None


def _parse_time(hhmm: str | None) -> tuple[int, int]:
    if not hhmm:
        return 8, 0  # default: 8am
    hour_str, _, minute_str = hhmm.partition(":")
    try:
        return int(hour_str), int(minute_str or 0)
    except ValueError:
        return 8, 0


def schedule_profile(profile_id: int):
    """(Re)register the recurring job for a profile based on its current
    schedule_type/time/day/cron, or remove it if schedule_type is 'none'."""
    if _scheduler is None:
        return
    profile = db.get_profile(profile_id)
    if profile is None:
        return
    job_id = _job_id(profile_id)
    trigger = _trigger_for_profile(profile)
    if trigger is None:
        if _scheduler.get_job(job_id):
            _scheduler.remove_job(job_id)
        return
    _scheduler.add_job(
        run_search_for_profile,
        trigger=trigger,
        args=[profile_id],
        id=job_id,
        replace_existing=True,
        misfire_grace_time=3600,
        coalesce=True,
        max_instances=1,
    )


def run_now(profile_id: int):
    """Queue an immediate one-off run on the scheduler's worker pool, so it
    doesn't block the Flask request thread and doesn't collide with that
    profile's recurring job (max_instances=1 on the shared job id would
    reject overlaps; a one-off run uses its own id)."""
    if _scheduler is None:
        # No background scheduler available (e.g. a script context) -- just
        # run inline.
        return run_search_for_profile(profile_id)
    _scheduler.add_job(
        run_search_for_profile,
        args=[profile_id],
        id=f"{_job_id(profile_id)}-once-{db.now_iso()}",
        misfire_grace_time=3600,
    )


def init_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler()
    _scheduler.start()
    for profile in db.list_profiles():
        schedule_profile(profile["id"])
    return _scheduler


def get_scheduler() -> BackgroundScheduler | None:
    return _scheduler
