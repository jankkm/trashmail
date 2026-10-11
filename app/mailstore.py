"""Storing, indexing, searching and rendering of received mail.

The .eml file in DATA_DIR/mail/YYYY/MM/ is the source of truth; SQLite holds
metadata and an FTS5 index for searching.
"""
from __future__ import annotations

import base64
import email
import email.policy
import html as htmllib
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import formatdate
from html.parser import HTMLParser
from pathlib import Path

import nh3

from . import config, db
from .security_checks import AuthResult

POLICY = email.policy.default


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag in ("br", "p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\n\s*\n+", "\n\n", "".join(parser.parts)).strip()


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", "replace")


def bodies(msg) -> tuple[str, str]:
    """Return (plain_text, html) of a parsed message; either may be empty."""
    text = html = ""
    try:
        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
    except Exception:
        plain_part = html_part = None
    if plain_part is not None:
        text = _part_text(plain_part)
    if html_part is not None:
        html = _part_text(html_part)
    if not text and html:
        text = html_to_text(html)
    return text, html


def parse(raw: bytes):
    return email.message_from_bytes(raw, policy=POLICY)


def _header(msg, name: str) -> str:
    try:
        return str(msg.get(name, "") or "")
    except Exception:
        return ""


def attachment_parts(msg) -> list:
    out = []
    for part in msg.walk():
        if part.is_multipart() and part.get_content_type() != "message/rfc822":
            continue
        disp = part.get_content_disposition()
        if part.get_content_type() == "message/rfc822" or disp == "attachment" or (
            part.get_filename() and not part.get("Content-ID")
        ):
            out.append(part)
    return out


def _part_bytes(part) -> bytes:
    if part.get_content_type() == "message/rfc822":
        inner = part.get_payload(0)
        return inner.as_bytes() if inner is not None else b""
    return part.get_payload(decode=True) or b""


# --------------------------------------------------------------------------- #
# Storage accounting (cap enforced by the SMTP server)
# --------------------------------------------------------------------------- #
_usage = {"at": 0.0, "bytes": 0}


def storage_used(max_age: float = 5.0) -> int:
    """Bytes of stored mail (sum of message sizes), cached for a few seconds."""
    now = time.monotonic()
    if now - _usage["at"] > max_age:
        row = db.one("SELECT COALESCE(SUM(size), 0) AS s FROM messages")
        _usage.update(at=now, bytes=int(row["s"]))
    return _usage["bytes"]


def storage_cap() -> int:
    """Configured cap in bytes; 0 = unlimited."""
    return max(config.get_int("MAX_STORAGE_MB"), 0) * 1024 * 1024


def storage_full(extra: int = 0) -> bool:
    cap = storage_cap()
    return cap > 0 and storage_used() + extra > cap


def _usage_changed() -> None:
    _usage["at"] = 0.0


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
def _clean_token(value: str) -> str:
    return re.sub(r"[^\w.\-\[\]:]", "?", value or "unknown")[:255]


def store(raw: bytes, *, mail_from: str, rcpt: str, remote_ip: str = "", helo: str = "",
          auth: AuthResult | None = None, flagged: bool = False) -> int:
    """Write one copy of the message for one recipient. Returns the message id."""
    auth = auth or AuthResult()
    now = time.time()
    stamp = datetime.fromtimestamp(now)
    uid = uuid.uuid4().hex
    folder = config.boot().data_dir / "mail" / f"{stamp:%Y}" / f"{stamp:%m}"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{uid}.eml"

    trace = (
        f"Received: from {_clean_token(helo)} ([{_clean_token(remote_ip)}]) by trashmail "
        f"with ESMTP for <{_clean_token(rcpt)}>; {formatdate(now, localtime=True)}\r\n"
        f"X-Trashmail-Auth: spf={auth.spf}; dkim={auth.dkim}; dmarc={auth.dmarc}\r\n"
    ).encode("ascii", "replace")
    full = trace + raw
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(full)
    tmp.replace(path)

    msg = parse(raw)
    text, html = bodies(msg)
    subject = _header(msg, "subject")
    from_header = _header(msg, "from")
    snippet = re.sub(r"\s+", " ", text).strip()[:200]
    rel = str(path.relative_to(config.boot().data_dir))

    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO messages(uid, path, received_ts, mail_from, rcpt_to, from_header, subject, snippet,"
            " size, has_html, attachments, flagged, remote_ip, spf, dkim, dmarc)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (uid, rel, int(now), mail_from, rcpt.lower(), from_header, subject, snippet, len(full),
             1 if html else 0, len(attachment_parts(msg)), 1 if flagged else 0, remote_ip,
             auth.spf, auth.dkim, auth.dmarc),
        )
        mid = cur.lastrowid
        conn.execute(
            "INSERT INTO messages_fts(rowid, subject, sender, recipient, body) VALUES(?,?,?,?,?)",
            (mid, subject, f"{from_header} {mail_from}", rcpt, text[:200_000]),
        )
    _usage_changed()
    return mid


# --------------------------------------------------------------------------- #
# Query
# --------------------------------------------------------------------------- #
def get(mid: int) -> sqlite3.Row | None:
    return db.one("SELECT * FROM messages WHERE id=?", (mid,))


def read_raw(row) -> bytes:
    return (config.boot().data_dir / row["path"]).read_bytes()


def _fts_query(q: str) -> str:
    tokens = re.findall(r"[\w.@+\-]+", q)
    return " ".join('"' + t.replace('"', '""') + '"*' for t in tokens)


def list_messages(*, q: str = "", rcpt: str = "", flagged: bool = False, unread: bool = False,
                  limit: int = 50, offset: int = 0) -> tuple[list[sqlite3.Row], int]:
    where, args = [], []
    if q.strip():
        fts = _fts_query(q)
        if not fts:
            return [], 0
        where.append("m.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)")
        args.append(fts)
    if rcpt:
        where.append("m.rcpt_to = ?")
        args.append(rcpt.lower())
    if flagged:
        where.append("m.flagged = 1")
    if unread:
        where.append("m.is_read = 0")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    try:
        total = db.one(f"SELECT COUNT(*) AS c FROM messages m {clause}", args)["c"]
        rows = db.query(
            f"SELECT m.* FROM messages m {clause} ORDER BY m.received_ts DESC, m.id DESC LIMIT ? OFFSET ?",
            [*args, limit, offset],
        )
    except sqlite3.OperationalError:  # malformed FTS expression
        return [], 0
    return rows, total


def recipients() -> list[sqlite3.Row]:
    return db.query("SELECT rcpt_to, COUNT(*) AS c FROM messages GROUP BY rcpt_to ORDER BY c DESC LIMIT 300")


def stats() -> dict:
    day = int(time.time()) - 86400
    row = db.one(
        "SELECT COUNT(*) AS total, SUM(is_read=0) AS unread, SUM(flagged=1) AS flagged,"
        " SUM(received_ts>=?) AS today FROM messages", (day,))
    return {k: row[k] or 0 for k in ("total", "unread", "flagged", "today")}


def hourly_histogram() -> list[dict]:
    """Messages per hour for the last 24 hours, oldest first."""
    now = int(time.time())
    start = now - 24 * 3600
    counts = [0] * 24
    for r in db.query("SELECT received_ts FROM messages WHERE received_ts>=?", (start,)):
        counts[min(23, (r["received_ts"] - start) // 3600)] += 1
    peak = max(counts) or 1
    out = []
    for i, c in enumerate(counts):
        label = datetime.fromtimestamp(start + (i + 1) * 3600).strftime("%H:00")
        out.append({"label": label, "count": c, "pct": round(100 * c / peak)})
    return out


def set_flag(ids: list[int], value: bool) -> None:
    with db.tx() as conn:
        conn.executemany("UPDATE messages SET flagged=? WHERE id=?", [(1 if value else 0, i) for i in ids])


def set_read(ids: list[int], value: bool) -> None:
    with db.tx() as conn:
        conn.executemany("UPDATE messages SET is_read=? WHERE id=?", [(1 if value else 0, i) for i in ids])


def delete(ids: list[int]) -> int:
    count = 0
    for mid in ids:
        row = get(mid)
        if row is None:
            continue
        with db.tx() as conn:
            conn.execute("DELETE FROM messages WHERE id=?", (mid,))
            conn.execute("DELETE FROM messages_fts WHERE rowid=?", (mid,))
        try:
            (config.boot().data_dir / row["path"]).unlink()
        except FileNotFoundError:
            pass
        count += 1
    _usage_changed()
    return count


def purge_expired() -> int:
    days = config.get_int("RETENTION_DAYS")
    if days <= 0:
        return 0
    cutoff = int(time.time()) - days * 86400
    ids = [r["id"] for r in db.query(
        "SELECT id FROM messages WHERE received_ts < ? AND flagged = 0", (cutoff,))]
    return delete(ids)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
_ATTRS = {tag: set(attrs) for tag, attrs in nh3.ALLOWED_ATTRIBUTES.items()}
_ATTRS["*"] = {"style", "class", "align", "valign", "bgcolor", "width", "height", "dir", "lang",
               "colspan", "rowspan", "cellpadding", "cellspacing", "border"}
_ATTRS["font"] = {"color", "size", "face"}
_TAGS = set(nh3.ALLOWED_TAGS) | {"style", "center", "font"}
_SCHEMES = set(nh3.ALLOWED_URL_SCHEMES) | {"data"}


def _attr_filter(tag: str, attr: str, value: str):
    if attr in ("href", "xlink:href") and value.strip().lower().startswith("data:"):
        return None
    return value


def _embed_cids(html: str, msg) -> str:
    cids = {}
    for part in msg.walk():
        cid = part.get("Content-ID")
        if cid and part.get_content_maintype() == "image":
            data = part.get_payload(decode=True) or b""
            cids[str(cid).strip("<> ")] = (
                f"data:{part.get_content_type()};base64,{base64.b64encode(data).decode()}")

    def sub(match):
        return cids.get(match.group(1), match.group(0))

    return re.sub(r"cid:([^\"'\s)>]+)", sub, html)


def sanitize_html(html: str, msg=None) -> str:
    if msg is not None:
        html = _embed_cids(html, msg)
    return nh3.clean(
        html, tags=_TAGS, clean_content_tags={"script"}, attributes=_ATTRS,
        url_schemes=_SCHEMES, attribute_filter=_attr_filter, link_rel="noopener noreferrer",
    )


_REMOTE_RE = re.compile(
    r"""(?:\bsrc|\bbackground|\bposter)\s*=\s*["']?\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//|@import""",
    re.I)


@dataclass
class View:
    headers: list[tuple[str, str]] = field(default_factory=list)
    text: str = ""
    html: str = ""             # sanitised
    has_remote: bool = False
    attachments: list[dict] = field(default_factory=list)


def build_view(raw: bytes) -> View:
    msg = parse(raw)
    text, html = bodies(msg)
    view = View(text=text)
    if html:
        view.html = sanitize_html(html, msg)
        view.has_remote = bool(_REMOTE_RE.search(view.html))
    for name in ("From", "To", "Cc", "Reply-To", "Date", "Subject", "Message-ID"):
        value = _header(msg, name)
        if value:
            view.headers.append((name, value))
    for idx, part in enumerate(attachment_parts(msg)):
        view.attachments.append({
            "idx": idx,
            "filename": part.get_filename() or f"attachment-{idx + 1}",
            "type": part.get_content_type(),
            "size": len(_part_bytes(part)),
        })
    return view


def attachment(raw: bytes, idx: int) -> tuple[str, str, bytes] | None:
    parts = attachment_parts(parse(raw))
    if not 0 <= idx < len(parts):
        return None
    part = parts[idx]
    return part.get_filename() or f"attachment-{idx + 1}", part.get_content_type(), _part_bytes(part)


def body_document(view: View, external: bool) -> str:
    """Standalone HTML document for the sandboxed iframe."""
    if view.html:
        inner = view.html
    else:
        inner = f'<pre style="white-space:pre-wrap;font:14px/1.5 ui-monospace,monospace">{htmllib.escape(view.text)}</pre>'
    return (
        '<!doctype html><html><head><meta charset="utf-8"><base target="_blank">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<style>body{margin:16px;font:14px/1.5 system-ui,sans-serif;color:#1c2230;background:#fff;word-wrap:break-word}'
        'img{max-width:100%;height:auto}</style></head><body>' + inner + "</body></html>"
    )


def csp(external: bool) -> str:
    if external:
        return ("default-src 'none'; img-src * data:; style-src * 'unsafe-inline'; font-src *; "
                "media-src *; base-uri 'none'; form-action 'none'")
    return "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
