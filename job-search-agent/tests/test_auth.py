"""End-to-end auth tests against the real Flask app: registration, login,
login-required redirects, and -- most importantly -- that one user can never
see or act on another user's profile."""
import io
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("JOB_AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret")
    monkeypatch.setenv("WTF_CSRF_ENABLED", "false")  # exercised separately in test_csrf_required

    import importlib
    from core import db as db_module
    importlib.reload(db_module)

    import app as app_module
    importlib.reload(app_module)
    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    with flask_app.test_client() as c:
        yield c

    sched = app_module.scheduler.get_scheduler()
    if sched:
        sched.shutdown(wait=False)
        app_module.scheduler._scheduler = None


def _register(client, email, password="password123"):
    return client.post("/register", data={
        "email": email, "password": password, "confirm_password": password,
    }, follow_redirects=True)


def _create_profile(client, name):
    data = {"name": name, "companies": "", "schedule_type": "none"}
    data["resume"] = (io.BytesIO(f"{name}'s resume".encode()), "resume.txt")
    return client.post("/profiles", data=data, content_type="multipart/form-data", follow_redirects=True)


def test_index_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_register_and_login_flow(client):
    r = _register(client, "jane@example.com")
    assert r.status_code == 200
    assert b"No profiles yet" in r.data  # landed on the (now-authenticated) index page

    client.post("/logout", follow_redirects=True)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302  # logged out -> bounced to login again

    r = client.post("/login", data={"email": "jane@example.com", "password": "password123"},
                     follow_redirects=True)
    assert r.status_code == 200
    assert b"No profiles yet" in r.data


def test_register_rejects_short_password(client):
    r = client.post("/register", data={
        "email": "jane@example.com", "password": "short", "confirm_password": "short",
    }, follow_redirects=True)
    assert b"at least 8 characters" in r.data


def test_register_rejects_mismatched_passwords(client):
    r = client.post("/register", data={
        "email": "jane@example.com", "password": "password123", "confirm_password": "password456",
    }, follow_redirects=True)
    assert b"don" in r.data.lower() and b"match" in r.data.lower()


def test_register_rejects_duplicate_email(client):
    _register(client, "jane@example.com")
    client.post("/logout", follow_redirects=True)
    r = client.post("/register", data={
        "email": "jane@example.com", "password": "password123", "confirm_password": "password123",
    }, follow_redirects=True)
    assert b"already exists" in r.data


def test_login_rejects_wrong_password(client):
    _register(client, "jane@example.com")
    client.post("/logout", follow_redirects=True)
    r = client.post("/login", data={"email": "jane@example.com", "password": "wrong-password"},
                     follow_redirects=True)
    assert b"Incorrect email or password" in r.data


def test_login_rejects_unknown_email(client):
    r = client.post("/login", data={"email": "nobody@example.com", "password": "whatever1"},
                     follow_redirects=True)
    assert b"Incorrect email or password" in r.data


def test_user_cannot_see_another_users_profile(client):
    _register(client, "jane@example.com")
    _create_profile(client, "Jane's Profile")
    from core import db
    jane_slug = db.list_profiles()[0]["slug"]
    client.post("/logout", follow_redirects=True)

    _register(client, "bob@example.com")
    # Bob's own dashboard list should be empty
    r = client.get("/", follow_redirects=True)
    assert b"No profiles yet" in r.data

    # Bob hitting Jane's dashboard URL directly gets a 404, not her data
    r = client.get(f"/p/{jane_slug}")
    assert r.status_code == 404

    # ...and can't run, edit, or delete it either
    assert client.post(f"/p/{jane_slug}/run").status_code == 404
    assert client.post(f"/p/{jane_slug}/schedule", data={"schedule_type": "none"}).status_code == 404
    assert client.post(f"/p/{jane_slug}/companies", data={"companies": ""}).status_code == 404
    assert client.post(f"/p/{jane_slug}/delete").status_code == 404


def test_csrf_required_on_state_changing_routes(monkeypatch, tmp_path):
    """With CSRF protection actually enabled, a POST without a token must be
    rejected -- this is the one test that runs with WTF_CSRF_ENABLED left on."""
    monkeypatch.setenv("JOB_AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret")
    monkeypatch.delenv("WTF_CSRF_ENABLED", raising=False)

    import importlib
    from core import db as db_module
    importlib.reload(db_module)
    import app as app_module
    importlib.reload(app_module)
    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True)

    with flask_app.test_client() as client:
        # Registration itself is a POST, so even it should be blocked without a token.
        r = client.post("/register", data={
            "email": "jane@example.com", "password": "password123", "confirm_password": "password123",
        })
        assert r.status_code == 400  # Flask-WTF's CSRF failure response

    sched = app_module.scheduler.get_scheduler()
    if sched:
        sched.shutdown(wait=False)
        app_module.scheduler._scheduler = None
