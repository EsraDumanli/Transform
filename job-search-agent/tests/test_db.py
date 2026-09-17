import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


@pytest.fixture
def db_module(monkeypatch, tmp_path):
    monkeypatch.setenv("JOB_AGENT_DATA_DIR", str(tmp_path))
    # db.py reads JOB_AGENT_DATA_DIR at import time, so re-import fresh each test
    import importlib
    from core import db as db_module
    importlib.reload(db_module)
    db_module.init_db()
    return db_module


@pytest.fixture
def user_id(db_module):
    return db_module.create_user("jane@example.com", "hashed-password")


def test_create_and_get_user(db_module, user_id):
    user = db_module.get_user(user_id)
    assert user["email"] == "jane@example.com"
    assert db_module.get_user_by_email("JANE@example.com")["id"] == user_id  # case-insensitive
    assert db_module.get_user_by_email("nobody@example.com") is None


def test_duplicate_email_rejected(db_module, user_id):
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db_module.create_user("jane@example.com", "another-hash")


def test_create_and_get_profile(db_module, user_id):
    pid = db_module.create_profile(
        user_id=user_id, name="Jane Smith", email=None, resume_text="resume text", resume_filename="r.pdf",
        target_roles="PM", companies=[{"name": "Acme", "url": "https://acme.com"}],
    )
    profile = db_module.get_profile(pid)
    assert profile["name"] == "Jane Smith"
    assert profile["slug"] == "jane-smith"
    assert profile["user_id"] == user_id
    companies = db_module.get_companies(pid)
    assert len(companies) == 1
    assert companies[0]["name"] == "Acme"


def test_slug_collision_gets_suffixed(db_module, user_id):
    p1 = db_module.create_profile(user_id=user_id, name="Jane Smith", email=None, resume_text="r",
                                   resume_filename=None, target_roles=None, companies=[])
    p2 = db_module.create_profile(user_id=user_id, name="Jane Smith", email=None, resume_text="r",
                                   resume_filename=None, target_roles=None, companies=[])
    assert db_module.get_profile(p1)["slug"] != db_module.get_profile(p2)["slug"]


def test_list_profiles_scoped_per_user(db_module):
    u1 = db_module.create_user("a@example.com", "h1")
    u2 = db_module.create_user("b@example.com", "h2")
    db_module.create_profile(user_id=u1, name="Alice", email=None, resume_text="r",
                              resume_filename=None, target_roles=None, companies=[])
    db_module.create_profile(user_id=u2, name="Bob", email=None, resume_text="r",
                              resume_filename=None, target_roles=None, companies=[])
    assert [p["name"] for p in db_module.list_profiles(user_id=u1)] == ["Alice"]
    assert [p["name"] for p in db_module.list_profiles(user_id=u2)] == ["Bob"]
    assert len(db_module.list_profiles()) == 2  # unscoped call sees everything


def test_insert_postings_dedupes(db_module, user_id):
    pid = db_module.create_profile(user_id=user_id, name="Jane", email=None, resume_text="r",
                                    resume_filename=None, target_roles=None, companies=[])
    posting = {"dedup_key": "acme:jr1", "company": "Acme", "role": "PM", "tier": "strong"}
    first = db_module.insert_postings(pid, [posting])
    second = db_module.insert_postings(pid, [posting])
    assert first == 1
    assert second == 0
    assert len(db_module.list_postings(pid)) == 1


def test_postings_ordered_by_tier(db_module, user_id):
    pid = db_module.create_profile(user_id=user_id, name="Jane", email=None, resume_text="r",
                                    resume_filename=None, target_roles=None, companies=[])
    db_module.insert_postings(pid, [
        {"dedup_key": "a:1", "company": "A", "role": "R1", "tier": "watch"},
        {"dedup_key": "a:2", "company": "A", "role": "R2", "tier": "strong"},
        {"dedup_key": "a:3", "company": "A", "role": "R3", "tier": "good"},
    ])
    tiers = [p["tier"] for p in db_module.list_postings(pid)]
    assert tiers == ["strong", "good", "watch"]


def test_run_lifecycle(db_module, user_id):
    pid = db_module.create_profile(user_id=user_id, name="Jane", email=None, resume_text="r",
                                    resume_filename=None, target_roles=None, companies=[])
    run_id = db_module.start_run(pid)
    assert db_module.last_run(pid)["status"] == "running"
    db_module.finish_run(run_id, status="success", new_postings_count=3)
    last = db_module.last_run(pid)
    assert last["status"] == "success"
    assert last["new_postings_count"] == 3


def test_deleting_user_cascades_to_profiles(db_module, user_id):
    pid = db_module.create_profile(user_id=user_id, name="Jane", email=None, resume_text="r",
                                    resume_filename=None, target_roles=None, companies=[])
    with db_module.get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    assert db_module.get_profile(pid) is None


def test_fresh_database_starts_completely_empty(db_module):
    """Regression guard: a newly initialized database must never ship with
    seed/demo data -- every clone of this app starts from zero."""
    assert db_module.list_profiles() == []
    with db_module.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM postings").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
