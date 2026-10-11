"""Users, password hashing and signed session cookies."""
from __future__ import annotations

import json
import logging
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import config, db, totp

log = logging.getLogger(__name__)
_hasher = PasswordHasher()
SESSION_MAX_AGE = 14 * 24 * 3600
COOKIE = "tm_session"
PENDING_COOKIE = "tm_pending"      # password accepted, second factor still outstanding
PENDING_MAX_AGE = 300


class UserError(ValueError):
    pass


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(hash_: str, password: str) -> bool:
    try:
        return _hasher.verify(hash_, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.boot().secret_key, salt="trashmail-session")


def make_session(user_id: int) -> str:
    return _serializer().dumps({"uid": user_id, "csrf": secrets.token_urlsafe(24)})


def read_session(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    try:
        return _serializer().loads(cookie, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None


def _pending_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.boot().secret_key, salt="trashmail-2fa-pending")


def make_pending(user_id: int) -> str:
    return _pending_serializer().dumps({"uid": user_id})


def read_pending(cookie: str | None) -> int | None:
    if not cookie:
        return None
    try:
        return int(_pending_serializer().loads(cookie, max_age=PENDING_MAX_AGE)["uid"])
    except (BadSignature, KeyError, ValueError):
        return None


# --- users ----------------------------------------------------------------- #
def get_user(user_id: int):
    return db.one("SELECT * FROM users WHERE id=?", (user_id,))


def list_users():
    return db.query("SELECT * FROM users ORDER BY username")


def count_admins() -> int:
    return db.one("SELECT COUNT(*) AS c FROM users WHERE is_admin=1")["c"]


def create_user(username: str, password: str, name: str = "", is_admin: bool = False) -> int:
    username = username.strip()
    if not username or any(c.isspace() for c in username):
        raise UserError("Username is required and must not contain spaces")
    if len(password) < 8:
        raise UserError("Password must be at least 8 characters")
    if db.one("SELECT 1 FROM users WHERE username=?", (username,)):
        raise UserError("Username already exists")
    return db.execute(
        "INSERT INTO users(username, password_hash, name, is_admin, created_at) VALUES(?,?,?,?,?)",
        (username, hash_password(password), name.strip(), 1 if is_admin else 0, int(time.time())))


def authenticate(username: str, password: str):
    user = db.one("SELECT * FROM users WHERE username=?", (username.strip(),))
    if user is None:
        hash_password(password)  # keep timing similar
        return None
    return user if verify_password(user["password_hash"], password) else None


def update_user(user_id: int, *, name: str, is_admin: bool, password: str = "") -> None:
    user = get_user(user_id)
    if user is None:
        raise UserError("User not found")
    if user["is_admin"] and not is_admin and count_admins() <= 1:
        raise UserError("Cannot remove admin status from the last admin")
    if password and len(password) < 8:
        raise UserError("Password must be at least 8 characters")
    db.execute("UPDATE users SET name=?, is_admin=? WHERE id=?", (name.strip(), 1 if is_admin else 0, user_id))
    if password:
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), user_id))


def delete_user(user_id: int, acting_user_id: int) -> None:
    user = get_user(user_id)
    if user is None:
        raise UserError("User not found")
    if user_id == acting_user_id:
        raise UserError("You cannot delete yourself")
    if user["is_admin"] and count_admins() <= 1:
        raise UserError("Cannot delete the last admin")
    db.execute("DELETE FROM users WHERE id=?", (user_id,))


def bootstrap_admin() -> None:
    """Create the initial admin from env when there are no users yet."""
    if db.one("SELECT 1 FROM users LIMIT 1"):
        return
    boot = config.boot()
    password = boot.admin_password
    generated = False
    if not password:
        password = secrets.token_urlsafe(12)
        generated = True
    create_user(boot.admin_username, password, boot.admin_name, is_admin=True)
    if generated:
        log.warning("Created initial admin '%s' with generated password: %s",
                    boot.admin_username, password)
    else:
        log.info("Created initial admin '%s'", boot.admin_username)


# --- two-factor authentication (TOTP) ------------------------------------------------------ #
def totp_start_setup(user_id: int) -> str:
    """Create (or replace) an unconfirmed secret. Returns it."""
    secret = totp.new_secret()
    db.execute("UPDATE users SET totp_secret=?, totp_enabled=0, totp_last_step=0, totp_recovery='[]' "
               "WHERE id=? AND totp_enabled=0", (secret, user_id))
    return secret


def totp_confirm(user_id: int, code: str) -> list[str] | None:
    """Activate 2FA if `code` matches the pending secret. Returns the one-time recovery codes."""
    user = get_user(user_id)
    if user is None or user["totp_enabled"] or not user["totp_secret"]:
        return None
    step = totp.verify(user["totp_secret"], code)
    if step is None:
        return None
    codes = totp.new_recovery_codes()
    db.execute("UPDATE users SET totp_enabled=1, totp_last_step=?, totp_recovery=? WHERE id=?",
               (step, json.dumps([totp.hash_recovery(c) for c in codes]), user_id))
    return codes


def totp_disable(user_id: int) -> None:
    db.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=0, totp_recovery='[]' "
               "WHERE id=?", (user_id,))


def check_second_factor(user, code: str) -> bool:
    """Accept a current TOTP code (once) or an unused recovery code (consumed)."""
    if not user["totp_enabled"] or not user["totp_secret"]:
        return False
    step = totp.verify(user["totp_secret"], code, user["totp_last_step"])
    if step is not None:
        db.execute("UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?",
                   (step, user["id"], step))
        return True
    hashes = json.loads(user["totp_recovery"] or "[]")
    candidate = totp.hash_recovery(code)
    for h in hashes:
        if secrets.compare_digest(h, candidate):
            hashes.remove(h)
            db.execute("UPDATE users SET totp_recovery=? WHERE id=?", (json.dumps(hashes), user["id"]))
            return True
    return False


def recovery_codes_left(user) -> int:
    return len(json.loads(user["totp_recovery"] or "[]"))
