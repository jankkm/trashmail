"""Configuration.

Two kinds of values:

* Bootstrap values (``Boot``): read from the environment only, needed before the
  database exists (data dir, ports, secret key, initial admin, TLS paths).
* Runtime settings (``SETTINGS``): seeded from the environment on first start
  and stored in SQLite. Once a value is in the DB it always beats the env.

Every variable ``FOO`` can alternatively be supplied as ``FOO_FILE`` (path to a
file containing the value, e.g. a Docker secret). ``FOO_FILE`` wins over ``FOO``.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

TRUE_VALUES = {"1", "true", "yes", "on", "y"}


def env(name: str, default: str | None = None) -> str | None:
    """Read ``NAME_FILE`` (file contents) or ``NAME`` from the environment."""
    path = os.environ.get(f"{name}_FILE")
    if path:
        try:
            return Path(path).read_text().strip()
        except OSError as exc:
            raise RuntimeError(f"{name}_FILE={path} cannot be read: {exc}") from exc
    value = os.environ.get(name)
    return value if value else default


def _bool(value: str | None) -> bool:
    return (value or "").strip().lower() in TRUE_VALUES


# --------------------------------------------------------------------------- #
# Bootstrap (env only)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Boot:
    data_dir: Path
    smtp_host: str
    smtp_port: int
    web_host: str
    web_port: int
    secret_key: str
    tls_cert: str | None
    tls_key: str | None
    admin_username: str
    admin_password: str | None
    admin_name: str
    cookie_secure: bool


_boot: Boot | None = None


def _load_boot() -> Boot:
    data_dir = Path(env("DATA_DIR", "/data")).resolve()
    (data_dir / "mail").mkdir(parents=True, exist_ok=True)

    secret = env("SECRET_KEY")
    if not secret:
        key_file = data_dir / "secret_key"
        if key_file.exists():
            secret = key_file.read_text().strip()
        else:
            secret = secrets.token_urlsafe(48)
            key_file.write_text(secret)
            key_file.chmod(0o600)

    return Boot(
        data_dir=data_dir,
        smtp_host=env("SMTP_LISTEN_HOST", "0.0.0.0"),
        smtp_port=int(env("SMTP_LISTEN_PORT", "25")),
        web_host=env("WEB_HOST", "0.0.0.0"),
        web_port=int(env("WEB_PORT", "8080")),
        secret_key=secret,
        tls_cert=env("TLS_CERT_PATH"),
        tls_key=env("TLS_KEY_PATH"),
        admin_username=env("ADMIN_USERNAME", "admin"),
        admin_password=env("ADMIN_PASSWORD"),
        admin_name=env("ADMIN_NAME", "Administrator"),
        cookie_secure=_bool(env("COOKIE_SECURE")),
    )


def boot() -> Boot:
    global _boot
    if _boot is None:
        _boot = _load_boot()
    return _boot


def reload() -> None:
    """Forget cached bootstrap values (used by tests)."""
    global _boot
    _boot = None


# --------------------------------------------------------------------------- #
# Runtime settings (env seeds DB, DB wins)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Setting:
    key: str
    default: str
    label: str
    help: str = ""
    kind: str = "str"  # str | int | bool | choice
    choices: tuple[str, ...] = ()
    secret: bool = False
    group: str = "General"


SETTING_LIST: tuple[Setting, ...] = (
    Setting("LOCAL_DOMAINS", "", "Local domains",
            "Comma separated domains this server accepts mail for. '*.example.com' matches subdomains. "
            "Empty = accept every domain (it never relays, but you will receive junk for any name).",
            group="Receiving"),
    Setting("SPF_REJECT", "false", "Reject on SPF fail",
            "Reject messages whose SPF result is 'fail' with a 550. SPF/DKIM/DMARC results are always shown.",
            "bool", group="Receiving"),

    Setting("MAX_MESSAGE_SIZE", "26214400", "Max message size",
            "Larger messages are rejected (552). Raising it needs an app restart.", "int", group="Limits"),
    Setting("MAX_RECIPIENTS", "10", "Max recipients per message",
            "Further RCPT TO commands get 452. Every recipient stores its own copy of the message.",
            "int", group="Limits"),
    Setting("RATE_LIMIT_PER_IP", "30", "Messages per IP per minute",
            "Further attempts get a temporary 450. 0 = unlimited.", "int", group="Limits"),
    Setting("MAX_CONNECTIONS", "50", "Max concurrent connections",
            "Further connections are refused with 421. 0 = unlimited.", "int", group="Limits"),
    Setting("MAX_CONNECTIONS_PER_IP", "5", "Max concurrent connections per IP",
            "0 = unlimited. Needs the real client IP (see README on Docker networking).", "int", group="Limits"),
    Setting("COMMAND_LIMIT", "50", "Max commands per session",
            "Each SMTP command (MAIL, RCPT, NOOP, ...) may be used this often per connection. "
            "0 = unlimited. Needs an app restart.", "int", group="Limits"),

    Setting("RETENTION_DAYS", "30", "Delete mail after",
            "Unflagged mail older than this is deleted. 0 = keep forever.", "int", group="Storage"),
    Setting("TRASH_DAYS", "30", "Empty recycle bin after",
            "Deleted messages stay in the recycle bin for this many days, then are removed for good. "
            "0 = keep until the bin is emptied by hand. They still count towards the storage cap.",
            "int", group="Storage"),
    Setting("MAX_STORAGE_MB", "5120", "Storage cap",
            "When stored mail reaches this size new mail is refused with 452 until space is freed. "
            "0 = unlimited.", "int", group="Storage"),

    Setting("FORWARD_SMTP_HOST", "", "Forwarding SMTP host",
            "Outbound SMTP account used for forwarding.", group="Forwarding"),
    Setting("FORWARD_SMTP_PORT", "587", "Forwarding SMTP port", kind="int", group="Forwarding"),
    Setting("FORWARD_SMTP_SECURITY", "starttls", "Forwarding SMTP security", kind="choice",
            choices=("starttls", "ssl", "none"), group="Forwarding"),
    Setting("FORWARD_SMTP_USER", "", "Forwarding SMTP user", group="Forwarding"),
    Setting("FORWARD_SMTP_PASSWORD", "", "Forwarding SMTP password",
            "Write-only; leave blank to keep the current value.", secret=True, group="Forwarding"),
    Setting("FORWARD_FROM", "", "Forwarding From address",
            "Defaults to the SMTP user if empty.", group="Forwarding"),
    Setting("FORWARD_LIMIT_PER_HOUR", "60", "Max rule forwards per hour",
            "Protects your SMTP account from being flooded through a forward rule. "
            "Beyond the limit the mail is still stored. 0 = unlimited.", "int", group="Forwarding"),
)
SETTINGS: dict[str, Setting] = {s.key: s for s in SETTING_LIST}


def _row(key: str):
    from . import db
    return db.one("SELECT value, source FROM settings WHERE key=?", (key,))


def get(key: str) -> str:
    """Effective value: DB beats env beats default."""
    row = _row(key)
    if row is not None:
        return row["value"]
    return env(key, SETTINGS[key].default)


def get_int(key: str) -> int:
    try:
        return int(get(key))
    except (TypeError, ValueError):
        return int(SETTINGS[key].default)


def get_bool(key: str) -> bool:
    return _bool(get(key))


def source(key: str) -> str:
    """Where the effective value comes from: 'ui', 'env' (seeded), 'env-live' or 'default'."""
    row = _row(key)
    if row is not None:
        return row["source"]
    return "env-live" if env(key) is not None else "default"


def set_value(key: str, value: str, src: str = "ui") -> None:
    from . import db
    if key not in SETTINGS:
        raise KeyError(key)
    db.execute(
        "INSERT INTO settings(key, value, source) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, source=excluded.source",
        (key, value, src),
    )


def reset(key: str) -> None:
    from . import db
    db.execute("DELETE FROM settings WHERE key=?", (key,))


def seed_from_env() -> None:
    """Copy env-provided values into the DB unless the DB already has them."""
    for key in SETTINGS:
        value = env(key)
        if value is not None and _row(key) is None:
            set_value(key, value, "env")


def local_domains() -> list[str]:
    return [d.strip().lower() for d in get("LOCAL_DOMAINS").replace(";", ",").split(",") if d.strip()]
