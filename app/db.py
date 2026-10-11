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
    scope TEXT,                       -- recipient address, NULL = global
    field TEXT NOT NULL,              -- sender|recipient|subject|body|any|header:<Name>
    op TEXT NOT NULL,                 -- contains|equals|startswith|endswith|regex
    value TEXT NOT NULL,
    action TEXT NOT NULL,             -- forward|delete|flag
    action_arg TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
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


def init() -> None:
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
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
