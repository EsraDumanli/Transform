"""SQLite data layer.

Deliberately plain sqlite3 (no ORM) -- this is a small self-hosted tool and
the schema is simple enough that an ORM would just add a dependency without
buying much. Every function opens its own short-lived connection, which is
fine at this scale and avoids cross-thread connection-sharing issues with the
background scheduler.
"""
from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable, Optional

DATA_DIR = os.environ.get("JOB_AGENT_DATA_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data"))
DB_PATH = os.path.join(DATA_DIR, "job_agent.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    resume_text TEXT NOT NULL,
    resume_filename TEXT,
    target_roles TEXT,
    schedule_type TEXT NOT NULL DEFAULT 'none',   -- none | daily | weekly | cron
    schedule_time TEXT,                            -- 'HH:MM' for daily/weekly
    schedule_day TEXT,                              -- 'mon'..'sun' for weekly
    schedule_cron TEXT,                             -- raw cron expression for 'cron'
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT
);

CREATE TABLE IF NOT EXISTS postings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    dedup_key TEXT NOT NULL,
    company TEXT NOT NULL,
    role TEXT NOT NULL,
    location TEXT,
    posting_date TEXT,
    job_id TEXT,
    link TEXT,
    description TEXT,
    tier TEXT NOT NULL DEFAULT 'watch',   -- strong | good | watch
    found_date TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(profile_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',  -- running | success | error
    new_postings_count INTEGER DEFAULT 0,
    error_message TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def get_conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "profile"


def unique_slug(conn, base_slug: str) -> str:
    slug = base_slug
    n = 2
    while conn.execute("SELECT 1 FROM profiles WHERE slug = ?", (slug,)).fetchone():
        slug = f"{base_slug}-{n}"
        n += 1
    return slug


# -------------------------------------------------------------------- users --

def create_user(email: str, password_hash: str) -> int:
    ts = now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email.strip().lower(), password_hash, ts),
        )
        return cur.lastrowid


def get_user(user_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.strip().lower(),)
        ).fetchone()


# ---------------------------------------------------------------- profiles --

def create_profile(
    *,
    user_id: int,
    name: str,
    email: Optional[str],
    resume_text: str,
    resume_filename: Optional[str],
    target_roles: Optional[str],
    companies: Iterable[dict],
    schedule_type: str = "none",
    schedule_time: Optional[str] = None,
    schedule_day: Optional[str] = None,
    schedule_cron: Optional[str] = None,
) -> int:
    ts = now_iso()
    with get_conn() as conn:
        slug = unique_slug(conn, slugify(name))
        cur = conn.execute(
            """INSERT INTO profiles
               (user_id, slug, name, email, resume_text, resume_filename, target_roles,
                schedule_type, schedule_time, schedule_day, schedule_cron,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, slug, name, email, resume_text, resume_filename, target_roles,
             schedule_type, schedule_time, schedule_day, schedule_cron, ts, ts),
        )
        profile_id = cur.lastrowid
        for c in companies:
            conn.execute(
                "INSERT INTO companies (profile_id, name, url) VALUES (?, ?, ?)",
                (profile_id, c["name"], c.get("url")),
            )
        return profile_id


def get_profile(profile_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()


def get_profile_by_slug(slug: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM profiles WHERE slug = ?", (slug,)).fetchone()


def list_profiles(user_id: Optional[int] = None):
    """List profiles, optionally scoped to one user. Every route in the web
    app should pass user_id -- an unscoped call is only for admin/CLI use."""
    with get_conn() as conn:
        if user_id is None:
            return conn.execute("SELECT * FROM profiles ORDER BY created_at DESC").fetchall()
        return conn.execute(
            "SELECT * FROM profiles WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
        ).fetchall()


def update_schedule(profile_id: int, *, schedule_type: str, schedule_time=None, schedule_day=None, schedule_cron=None):
    with get_conn() as conn:
        conn.execute(
            """UPDATE profiles SET schedule_type=?, schedule_time=?, schedule_day=?,
               schedule_cron=?, updated_at=? WHERE id=?""",
            (schedule_type, schedule_time, schedule_day, schedule_cron, now_iso(), profile_id),
        )


def delete_profile(profile_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))


def get_companies(profile_id: int):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM companies WHERE profile_id = ? ORDER BY id", (profile_id,)
        ).fetchall()


def replace_companies(profile_id: int, companies: Iterable[dict]):
    with get_conn() as conn:
        conn.execute("DELETE FROM companies WHERE profile_id = ?", (profile_id,))
        for c in companies:
            conn.execute(
                "INSERT INTO companies (profile_id, name, url) VALUES (?, ?, ?)",
                (profile_id, c["name"], c.get("url")),
            )


# ---------------------------------------------------------------- postings --

def existing_dedup_keys(profile_id: int) -> set:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT dedup_key FROM postings WHERE profile_id = ?", (profile_id,)
        ).fetchall()
        return {r["dedup_key"] for r in rows}


def insert_postings(profile_id: int, postings: Iterable[dict]) -> int:
    """Insert postings, skipping any whose dedup_key already exists for this
    profile. Returns the number actually inserted."""
    ts = now_iso()
    inserted = 0
    with get_conn() as conn:
        for p in postings:
            try:
                conn.execute(
                    """INSERT INTO postings
                       (profile_id, dedup_key, company, role, location, posting_date,
                        job_id, link, description, tier, found_date, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        profile_id, p["dedup_key"], p["company"], p["role"],
                        p.get("location"), p.get("posting_date"), p.get("job_id"),
                        p.get("link"), p.get("description"), p.get("tier", "watch"),
                        p.get("found_date", ts[:10]), ts,
                    ),
                )
                inserted += 1
            except sqlite3.IntegrityError:
                continue  # already have this posting for this profile
    return inserted


def list_postings(profile_id: int):
    with get_conn() as conn:
        return conn.execute(
            """SELECT * FROM postings WHERE profile_id = ?
               ORDER BY CASE tier WHEN 'strong' THEN 0 WHEN 'good' THEN 1 ELSE 2 END,
                        found_date DESC, id DESC""",
            (profile_id,),
        ).fetchall()


# -------------------------------------------------------------------- runs --

def start_run(profile_id: int) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO runs (profile_id, started_at, status) VALUES (?, ?, 'running')",
            (profile_id, now_iso()),
        )
        return cur.lastrowid


def finish_run(run_id: int, *, status: str, new_postings_count: int = 0, error_message: Optional[str] = None):
    with get_conn() as conn:
        conn.execute(
            """UPDATE runs SET finished_at=?, status=?, new_postings_count=?, error_message=?
               WHERE id=?""",
            (now_iso(), status, new_postings_count, error_message, run_id),
        )


def list_runs(profile_id: int, limit: int = 10):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM runs WHERE profile_id = ? ORDER BY id DESC LIMIT ?",
            (profile_id, limit),
        ).fetchall()


def last_run(profile_id: int):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM runs WHERE profile_id = ? ORDER BY id DESC LIMIT 1",
            (profile_id,),
        ).fetchone()
