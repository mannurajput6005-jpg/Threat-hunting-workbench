"""Authentication, sessions and role-based authorization.

Authorization is enforced in service functions via ``authorize(actor, permission)`` -
hiding a button in the UI is never the only control.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt

from core import database as db
from core.config import (LOCKOUT_MINUTES, MAX_FAILED_LOGINS, MIN_PASSWORD_LENGTH,
                         SESSION_TIMEOUT_MINUTES)
from core.logging_config import get_logger

log = get_logger(__name__)

ROLES = ("admin", "analyst", "viewer")

PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"read"},
    "analyst": {"read", "ingest", "detect", "case_write", "ioc_write"},
    "admin": {"read", "ingest", "detect", "case_write", "ioc_write", "rules_manage",
              "users_manage", "data_purge", "audit_read"},
}


class AuthError(Exception):
    pass


def authorize(actor: dict | None, permission: str) -> None:
    """Raise PermissionError unless ``actor`` holds ``permission``."""
    if not actor or permission not in PERMISSIONS.get(actor.get("role", ""), set()):
        raise PermissionError(f"Permission '{permission}' required")


def has_permission(actor: dict | None, permission: str) -> bool:
    try:
        authorize(actor, permission)
        return True
    except PermissionError:
        return False


# --------------------------------------------------------------------------- passwords
def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password.encode("utf-8")) > 72:
        raise AuthError("Password must be at most 72 bytes (bcrypt limit).")
    if password.lower() == password or password.upper() == password or not any(c.isdigit() for c in password):
        raise AuthError("Password needs upper-case, lower-case and a digit.")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:72], password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("Dummy-password-1")
    return _DUMMY_HASH


# --------------------------------------------------------------------------- users
def user_count(conn) -> int:
    return db.scalar(conn, "SELECT COUNT(*) FROM users") or 0


def create_user(conn, username: str, password: str, role: str, actor: dict | None = None,
                *, bootstrap: bool = False) -> int:
    """Create a user. ``bootstrap=True`` is allowed only while the users table is empty."""
    if bootstrap:
        if user_count(conn) != 0:
            raise PermissionError("Bootstrap is only allowed before any user exists.")
    else:
        authorize(actor, "users_manage")
    username = username.strip()
    if not (3 <= len(username) <= 64) or not all(c.isalnum() or c in "._-@" for c in username):
        raise AuthError("Username must be 3-64 characters (letters, digits, . _ - @).")
    if role not in ROLES:
        raise AuthError("Unknown role.")
    validate_password(password)
    if db.one(conn, "SELECT 1 FROM users WHERE username=?", (username,)):
        raise AuthError("Username already exists.")
    cur = conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                       (username, hash_password(password), role, db.now_iso()))
    db.audit(conn, actor, "user_create", "user", cur.lastrowid, f"{username} ({role})")
    return cur.lastrowid


def list_users(conn, actor: dict) -> list[dict]:
    authorize(actor, "users_manage")
    return db.rows(conn, "SELECT user_id, username, role, is_active, created_at FROM users ORDER BY username")


def set_user_role(conn, actor: dict, user_id: int, role: str) -> None:
    authorize(actor, "users_manage")
    if role not in ROLES:
        raise AuthError("Unknown role.")
    if user_id == actor["user_id"]:
        raise AuthError("You cannot change your own role.")
    conn.execute("UPDATE users SET role=? WHERE user_id=?", (role, user_id))
    db.audit(conn, actor, "user_role_change", "user", user_id, role)


def set_user_active(conn, actor: dict, user_id: int, active: bool) -> None:
    authorize(actor, "users_manage")
    if user_id == actor["user_id"]:
        raise AuthError("You cannot deactivate your own account.")
    conn.execute("UPDATE users SET is_active=? WHERE user_id=?", (1 if active else 0, user_id))
    db.audit(conn, actor, "user_activate" if active else "user_deactivate", "user", user_id)


def reset_password(conn, actor: dict, user_id: int, new_password: str) -> None:
    authorize(actor, "users_manage")
    validate_password(new_password)
    conn.execute("UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE user_id=?",
                 (hash_password(new_password), user_id))
    db.audit(conn, actor, "password_reset", "user", user_id)


# --------------------------------------------------------------------------- login
def authenticate(conn, username: str, password: str) -> dict:
    """Return the session user dict or raise AuthError. Applies lockout after repeated failures."""
    generic = AuthError("Invalid username or password.")
    user = db.one(conn, "SELECT * FROM users WHERE username=?", (username.strip(),))
    if not user:
        verify_password(password, _dummy_hash())  # similar work so unknown users are not obvious by timing
        db.audit(conn, None, "login_failed", "user", None, f"unknown user '{username[:64]}'")
        conn.commit()
        raise generic
    now = datetime.now(timezone.utc)
    if user["locked_until"] and datetime.fromisoformat(user["locked_until"].replace("Z", "+00:00")) > now:
        db.audit(conn, user, "login_blocked_locked", "user", user["user_id"])
        conn.commit()
        raise AuthError("Account temporarily locked. Try again later.")
    if not user["is_active"] or not verify_password(password, user["password_hash"]):
        attempts = user["failed_attempts"] + 1
        locked = None
        if attempts >= MAX_FAILED_LOGINS:
            locked = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec="seconds").replace("+00:00", "Z")
            attempts = 0
        conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE user_id=?",
                     (attempts, locked, user["user_id"]))
        db.audit(conn, user, "login_failed", "user", user["user_id"])
        conn.commit()  # persist the failure counter even though we raise
        raise generic
    conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE user_id=?", (user["user_id"],))
    db.audit(conn, user, "login_success", "user", user["user_id"])
    return {"user_id": user["user_id"], "username": user["username"], "role": user["role"]}


# --------------------------------------------------------------------------- Streamlit session helpers
def current_user() -> dict | None:
    """Session user, or None if not logged in / session expired."""
    import streamlit as st
    user = st.session_state.get("user")
    if not user:
        return None
    last = st.session_state.get("last_activity")
    if last and datetime.now(timezone.utc) - last > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        logout(reason="session_timeout")
        return None
    st.session_state["last_activity"] = datetime.now(timezone.utc)
    return user


def login_session(user: dict) -> None:
    import streamlit as st
    st.session_state["user"] = user
    st.session_state["last_activity"] = datetime.now(timezone.utc)


def logout(reason: str = "logout") -> None:
    import streamlit as st
    user = st.session_state.get("user")
    if user:
        with db.get_conn() as conn:
            db.audit(conn, user, reason, "user", user["user_id"])
    for key in ("user", "last_activity"):
        st.session_state.pop(key, None)


def require_login(permission: str = "read") -> dict:
    """Call at the top of every page. Stops rendering when unauthenticated or unauthorized."""
    import streamlit as st
    user = current_user()
    if not user:
        st.warning("Please log in to continue.")
        st.stop()
    if not has_permission(user, permission):
        st.error("You do not have permission to view this page.")
        st.stop()
    return user
