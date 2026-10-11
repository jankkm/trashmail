"""Rule evaluation and blacklist / local-domain policy."""
from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass

from . import config, db

FIELDS = ("sender", "recipient", "subject", "body", "any", "header")
OPS = ("contains", "equals", "startswith", "endswith", "regex")
ACTIONS = ("forward", "delete", "flag")
BLACKLIST_KINDS = {
    "sender_address": "Sender address",
    "sender_domain": "Sender domain",
    "rcpt_address": "Recipient address",
    "rcpt_domain": "Recipient domain",
}


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# Local domains + blacklist (checked during the SMTP dialogue)
# --------------------------------------------------------------------------- #
def domain_allowed(domain: str) -> bool:
    domains = config.local_domains()
    if not domains:
        return True
    domain = domain.lower().strip(".")
    for pattern in domains:
        if pattern.startswith("*."):
            if domain.endswith(pattern[1:]):
                return True
        elif domain == pattern:
            return True
    return False


def _domain_chain(domain: str) -> list[str]:
    parts = domain.lower().strip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def blacklisted(address: str, *, sender: bool) -> str | None:
    """Return the matching blacklist entry description, or None. Subdomains of a
    blacklisted domain match too."""
    address = (address or "").strip().lower()
    if not address:
        return None
    prefix = "sender" if sender else "rcpt"
    domain = address.rpartition("@")[2]
    chain = _domain_chain(domain) if domain else []
    marks = ",".join("?" * len(chain)) or "''"
    row = db.one(
        f"SELECT kind, value FROM blacklist WHERE "
        f"(kind=? AND value=?) OR (kind=? AND value IN ({marks}))",
        [f"{prefix}_address", address, f"{prefix}_domain", *chain],
    )
    return f"{row['kind']}:{row['value']}" if row else None


def add_blacklist(kind: str, value: str) -> None:
    if kind not in BLACKLIST_KINDS:
        raise RuleError("Unknown blacklist type")
    value = value.strip().lower().lstrip("@")
    if not value or any(c.isspace() for c in value):
        raise RuleError("Value is empty or contains whitespace")
    if kind.endswith("_address") and "@" not in value:
        raise RuleError("Address must contain @")
    db.execute("INSERT OR IGNORE INTO blacklist(kind, value, created_at) VALUES(?,?,?)",
               (kind, value, int(time.time())))


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@dataclass
class Context:
    sender: str       # envelope sender and From header, joined
    recipient: str
    subject: str
    body: str
    msg: object       # parsed email message (for header lookups)


def _text_for(field: str, ctx: Context) -> str:
    if field == "sender":
        return ctx.sender
    if field == "recipient":
        return ctx.recipient
    if field == "subject":
        return ctx.subject
    if field == "body":
        return ctx.body
    if field.startswith("header:"):
        name = field.split(":", 1)[1].strip()
        try:
            values = ctx.msg.get_all(name) or []
        except Exception:
            values = []
        return "\n".join(str(v) for v in values)
    # "any": all headers + body
    try:
        headers = "\n".join(f"{k}: {v}" for k, v in ctx.msg.items())
    except Exception:
        headers = ""
    return f"{headers}\n{ctx.body}"


def _matches(op: str, needle: str, haystack: str) -> bool:
    if op == "regex":
        try:
            return re.search(needle, haystack, re.I | re.M) is not None
        except re.error:
            return False
    needle, haystack = needle.lower(), haystack.lower()
    if op == "equals":
        return haystack.strip() == needle.strip() or needle.strip() in {
            a.strip() for a in re.findall(r"[^<>\s,;]+@[^<>\s,;]+", haystack)}
    if op == "startswith":
        return haystack.startswith(needle)
    if op == "endswith":
        return haystack.endswith(needle)
    return needle in haystack


def matching_rules(ctx: Context) -> list[sqlite3.Row]:
    rows = db.query(
        "SELECT * FROM rules WHERE enabled=1 AND (scope IS NULL OR lower(scope)=lower(?)) "
        "ORDER BY priority, id", (ctx.recipient,))
    return [r for r in rows if _matches(r["op"], r["value"], _text_for(r["field"], ctx))]


def validate_rule(field: str, header_name: str, op: str, value: str, action: str, arg: str) -> str:
    """Validate form input; returns the stored field string."""
    if field not in FIELDS:
        raise RuleError("Unknown field")
    if op not in OPS:
        raise RuleError("Unknown operator")
    if action not in ACTIONS:
        raise RuleError("Unknown action")
    if not value.strip():
        raise RuleError("Match value is required")
    if op == "regex":
        try:
            re.compile(value)
        except re.error as exc:
            raise RuleError(f"Invalid regex: {exc}") from exc
    if action == "forward" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", arg.strip()):
        raise RuleError("Forward action needs a valid email address")
    if field == "header":
        if not re.fullmatch(r"[A-Za-z0-9-]+", header_name.strip()):
            raise RuleError("Header name is required (letters, digits, dashes)")
        return f"header:{header_name.strip()}"
    return field


def describe(rule) -> str:
    field = rule["field"]
    if field.startswith("header:"):
        field = f"header {field.split(':', 1)[1]}"
    text = f"{field} {rule['op']} “{rule['value']}”"
    if rule["action"] == "forward":
        return f"{text} → forward to {rule['action_arg']}"
    return f"{text} → {rule['action']}"


def log_hit(rule, *, message_id: int | None, ctx: Context, detail: str = "", ok: bool = True) -> None:
    db.execute(
        "INSERT INTO rule_hits(at, rule_id, message_id, sender, rcpt, subject, action, detail, ok)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (int(time.time()), rule["id"], message_id, ctx.sender[:200], ctx.recipient, ctx.subject[:200],
         rule["action"], detail[:300], 1 if ok else 0),
    )
