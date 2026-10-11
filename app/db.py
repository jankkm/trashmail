"""SQLite access. A fresh short-lived connection per call (WAL mode) keeps this
safe to use from the SMTP thread, the event loop and the web threadpool."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Sequence

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'ui'
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    uid TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    received_ts INTEGER NOT NULL,
    mail_from TEXT NOT NULL DEFAULT '',
    rcpt_to TEXT NOT NULL,
    from_header TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    snippet TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    has_html INTEGER NOT NULL DEFAULT 0,
    attachments INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    is_read INTEGER NOT NULL DEFAULT 0,
    remote_ip TEXT NOT NULL DEFAULT '',
    spf TEXT NOT NULL DEFAULT 'none',
    dkim TEXT NOT NULL DEFAULT 'none',
    dmarc TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(received_ts DESC);
CREATE INDEX IF NOT EXISTS idx_messages_rcpt ON messages(rcpt_to);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    subject, sender, recipient, body, tokenize = 'unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    scope TEXT,                       -- recipient address, NULL = global
    match_mode TEXT NOT NULL DEFAULT 'all',   -- all|any: how the conditions combine
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_conditions (      -- 0..n per rule ("when")
    id INTEGER PRIMARY KEY,
    rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    field TEXT NOT NULL,              -- sender|recipient|subject|body|any|header:<Name>
    op TEXT NOT NULL,                 -- contains|not_contains|equals|startswith|endswith|regex
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_actions (         -- 1..n per rule ("then")
    id INTEGER PRIMARY KEY,
    rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL,             -- flag|mark_read|forward|delete
    arg TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_rule_conditions ON rule_conditions(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_actions ON rule_actions(rule_id);
CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS favorite_addresses (
    favorite_id INTEGER NOT NULL REFERENCES favorites(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    PRIMARY KEY (favorite_id, address)
);
CREATE INDEX IF NOT EXISTS idx_favorite_addresses ON favorite_addresses(address);
CREATE TABLE IF NOT EXISTS rule_hits (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    rule_id INTEGER REFERENCES rules(id) ON DELETE SET NULL,
    message_id INTEGER,
    sender TEXT NOT NULL DEFAULT '',
    rcpt TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS message_tags (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    tag TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (message_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_message_tags_tag ON message_tags(tag);
CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,               -- sender_address|sender_domain|rcpt_address|rcpt_domain
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(kind, value)
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.boot().data_dir / "trashmail.db", timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# Columns added after the first release. CREATE TABLE IF NOT EXISTS never alters an existing table,
# so every addition must be listed here as (table, column, definition).
MIGRATIONS = [
    ("users", "totp_secret", "TEXT"),
    ("users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "totp_recovery", "TEXT NOT NULL DEFAULT '[]'"),
    ("users", "default_view", "TEXT NOT NULL DEFAULT 'all'"),     # inbox start view: all|unread|flagged
    ("users", "forward_email", "TEXT NOT NULL DEFAULT ''"),       # personal address for one-click forwarding
]


def _migrate(conn: sqlite3.Connection) -> None:
    for table, column, definition in MIGRATIONS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_rules_v2(conn: sqlite3.Connection) -> None:
    """Old rules had exactly one condition and one action in columns of `rules`.
    Rebuild the table (SQLite "create new, copy, drop, rename") and move them into
    rule_conditions / rule_actions. Foreign keys are off so rule_hits keeps its rule_id."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(rules)")}
    if "field" not in columns:
        return
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript("""
        BEGIN;
        CREATE TABLE rules_new (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', scope TEXT,
            match_mode TEXT NOT NULL DEFAULT 'all', priority INTEGER NOT NULL DEFAULT 100,
            enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
        INSERT INTO rules_new(id, scope, priority, enabled, created_at)
            SELECT id, scope, priority, enabled, created_at FROM rules;
        INSERT INTO rule_conditions(rule_id, position, field, op, value)
            SELECT id, 0, field, op, value FROM rules;
        INSERT INTO rule_actions(rule_id, position, action, arg)
            SELECT id, 0, action, action_arg FROM rules;
        DROP TABLE rules;
        ALTER TABLE rules_new RENAME TO rules;
        COMMIT;
    """)
    conn.execute("PRAGMA foreign_keys=ON")


def init() -> None:
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)
        _migrate_rules_v2(conn)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(sql: str, args: Sequence[Any] = ()) -> list[sqlite3.Row]:
    with tx() as conn:
        return conn.execute(sql, args).fetchall()


def one(sql: str, args: Sequence[Any] = ()) -> sqlite3.Row | None:
    with tx() as conn:
        return conn.execute(sql, args).fetchone()


def execute(sql: str, args: Sequence[Any] = ()) -> int:
    """Run a write statement; returns lastrowid."""
    with tx() as conn:
        return conn.execute(sql, args).lastrowid
