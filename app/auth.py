"""Users, password hashing and signed session cookies."""
from __future__ import annotations

import logging
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import config, db

log = logging.getLogger(__name__)
_hasher = PasswordHasher()
SESSION_MAX_AGE = 14 * 24 * 3600
COOKIE = "tm_session"


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
