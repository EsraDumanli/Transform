"""Authentication: password hashing and the Flask-Login user object.

Passwords are hashed with Werkzeug's generate_password_hash (PBKDF2 by
default), which ships with Flask itself, so this adds no new dependency for
the hashing side. Session/cookie handling is Flask-Login.
"""
from __future__ import annotations

from flask_login import LoginManager, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from core import db

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "error"

MIN_PASSWORD_LENGTH = 8


class User(UserMixin):
    """Thin wrapper around a `users` row so Flask-Login can track it in the
    session. Only ever constructed from a row that's already in the DB."""

    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]

    @staticmethod
    def get(user_id) -> "User | None":
        row = db.get_user(int(user_id))
        return User(row) if row else None

    @staticmethod
    def get_by_email(email: str) -> "User | None":
        row = db.get_user_by_email(email)
        return User(row) if row else None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def password_error(password: str, confirm: str) -> str | None:
    """Return a human-readable error string, or None if the password is fine."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if password != confirm:
        return "Passwords don't match."
    return None
