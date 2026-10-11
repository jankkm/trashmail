"""Rules (0..n conditions, 1..n actions), blacklist and local-domain policy.

A rule applies to one recipient address (scope) or to everything (scope NULL). Its conditions are
combined with AND (match_mode "all") or OR ("any"); a rule without conditions matches every message
in its scope. When it matches, all of its actions run, in order.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from . import config, db, mailstore

FIELDS = ("sender", "recipient", "subject", "body", "any", "header")
OPS = ("contains", "not_contains", "equals", "startswith", "endswith", "regex")
ACTIONS = ("flag", "mark_read", "tag", "forward", "delete")
MATCH_MODES = ("all", "any")

FIELD_LABELS = {"sender": "Sender", "recipient": "Recipient", "subject": "Subject", "body": "Body",
                "any": "Any header or body", "header": "Specific header…"}
OP_LABELS = {"contains": "contains", "not_contains": "does not contain", "equals": "equals",
             "startswith": "starts with", "endswith": "ends with", "regex": "matches regex"}
ACTION_LABELS = {"flag": "Flag", "mark_read": "Mark as read", "tag": "Add tag", "forward": "Forward to",
                 "delete": "Delete"}
BLACKLIST_KINDS = {
    "sender_address": "Sender address",
    "sender_domain": "Sender domain",
    "rcpt_address": "Recipient address",
    "rcpt_domain": "Recipient domain",
}
ADDRESS_RE = re.compile(r"[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+")


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
# Evaluation
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
    if op == "not_contains":
        return needle not in haystack
    return needle in haystack


def rule_matches(rule: dict, ctx: Context) -> bool:
    conditions = rule["conditions"]
    if not conditions:
        return True
    results = (_matches(c["op"], c["value"], _text_for(c["field"], ctx)) for c in conditions)
    return any(results) if rule["match_mode"] == "any" else all(results)


def matching_rules(ctx: Context) -> list[dict]:
    rules = _load("WHERE r.enabled=1 AND (r.scope IS NULL OR lower(r.scope)=lower(?))", (ctx.recipient,))
    return [r for r in rules if rule_matches(r, ctx)]


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def _load(where: str = "", args: tuple | list = ()) -> list[dict]:
    """Rules with their conditions and actions, ordered by priority."""
    rules = [dict(r, conditions=[], actions=[]) for r in db.query(
        f"SELECT r.* FROM rules r {where} ORDER BY r.priority, r.id", args)]
    if not rules:
        return rules
    by_id = {r["id"]: r for r in rules}
    marks = ",".join("?" * len(by_id))
    for c in db.query(f"SELECT * FROM rule_conditions WHERE rule_id IN ({marks}) ORDER BY position, id",
                      list(by_id)):
        by_id[c["rule_id"]]["conditions"].append(dict(c))
    for a in db.query(f"SELECT * FROM rule_actions WHERE rule_id IN ({marks}) ORDER BY position, id",
                      list(by_id)):
        by_id[a["rule_id"]]["actions"].append(dict(a))
    return rules


def list_rules() -> list[dict]:
    return _load()


def rules_for_scopes(scopes: list[str]) -> list[dict]:
    if not scopes:
        return []
    marks = ",".join("?" * len(scopes))
    return _load(f"WHERE lower(r.scope) IN ({marks})", [s.lower() for s in scopes])


def get_rule(rule_id: int) -> dict | None:
    found = _load("WHERE r.id=?", (rule_id,))
    return found[0] if found else None


def normalize(conditions: list[dict], actions: list[dict], match_mode: str = "all") -> tuple[list, list, str]:
    """Validate form input. Blank conditions are dropped; at least one action is required."""
    if match_mode not in MATCH_MODES:
        raise RuleError("Unknown match mode")
    clean_conditions = []
    for c in conditions:
        field, op = (c.get("field") or "").strip(), (c.get("op") or "").strip()
        value = (c.get("value") or "").strip()
        if not value and not (c.get("header") or "").strip() and field in ("", "sender"):
            continue            # an untouched blank row
        if not value:
            raise RuleError("Every condition needs a value")
        if field not in FIELDS:
            raise RuleError("Unknown field")
        if op not in OPS:
            raise RuleError("Unknown operator")
        if op == "regex":
            try:
                re.compile(value)
            except re.error as exc:
                raise RuleError(f"Invalid regex: {exc}") from exc
        if field == "header":
            header = (c.get("header") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9-]+", header):
                raise RuleError("Header name is required (letters, digits, dashes)")
            field = f"header:{header}"
        clean_conditions.append({"field": field, "op": op, "value": value})

    clean_actions = []
    for a in actions:
        action, arg = (a.get("action") or "").strip(), (a.get("arg") or "").strip()
        if action not in ACTIONS:
            raise RuleError("Unknown action")
        if action == "forward" and not ADDRESS_RE.fullmatch(arg):
            raise RuleError("The forward action needs a valid email address")
        if action == "tag":
            arg = mailstore.normalize_tag(arg)
            if not arg:
                raise RuleError("The tag action needs a tag name")
        clean_actions.append({"action": action, "arg": arg if action in ("forward", "tag") else ""})
    if not clean_actions:
        raise RuleError("Add at least one action")
    return clean_conditions, clean_actions, match_mode


def _write_children(conn, rule_id: int, conditions: list[dict], actions: list[dict]) -> None:
    conn.execute("DELETE FROM rule_conditions WHERE rule_id=?", (rule_id,))
    conn.execute("DELETE FROM rule_actions WHERE rule_id=?", (rule_id,))
    conn.executemany(
        "INSERT INTO rule_conditions(rule_id, position, field, op, value) VALUES(?,?,?,?,?)",
        [(rule_id, i, c["field"], c["op"], c["value"]) for i, c in enumerate(conditions)])
    conn.executemany(
        "INSERT INTO rule_actions(rule_id, position, action, arg) VALUES(?,?,?,?)",
        [(rule_id, i, a["action"], a["arg"]) for i, a in enumerate(actions)])


def create_rule(*, conditions: list[dict], actions: list[dict], scope: str | None = None, name: str = "",
                match_mode: str = "all", priority: int = 100, enabled: bool = True) -> int:
    """`conditions`/`actions` are validated (see normalize); field "header" needs a "header" key."""
    conditions, actions, match_mode = normalize(conditions, actions, match_mode)
    with db.tx() as conn:
        cur = conn.execute(
            "INSERT INTO rules(name, scope, match_mode, priority, enabled, created_at) VALUES(?,?,?,?,?,?)",
            (name.strip()[:80], (scope or "").strip().lower() or None, match_mode, priority,
             1 if enabled else 0, int(time.time())))
        _write_children(conn, cur.lastrowid, conditions, actions)
        return cur.lastrowid


def update_rule(rule_id: int, *, conditions: list[dict], actions: list[dict], scope: str | None = None,
                name: str = "", match_mode: str = "all", priority: int = 100) -> None:
    conditions, actions, match_mode = normalize(conditions, actions, match_mode)
    with db.tx() as conn:
        conn.execute("UPDATE rules SET name=?, scope=?, match_mode=?, priority=? WHERE id=?",
                     (name.strip()[:80], (scope or "").strip().lower() or None, match_mode, priority, rule_id))
        _write_children(conn, rule_id, conditions, actions)


def delete_rule(rule_id: int) -> None:
    db.execute("DELETE FROM rules WHERE id=?", (rule_id,))


def rule_for_editor(rule: dict) -> dict[str, Any]:
    """JSON-friendly shape consumed by the rule editor dialog (static/app.js)."""
    conditions = []
    for c in rule["conditions"]:
        field, header = c["field"], ""
        if field.startswith("header:"):
            field, header = "header", c["field"].split(":", 1)[1]
        conditions.append({"field": field, "header": header, "op": c["op"], "value": c["value"]})
    return {"id": rule["id"], "name": rule["name"], "scope": rule["scope"] or "",
            "match_mode": rule["match_mode"], "priority": rule["priority"], "conditions": conditions,
            "actions": [{"action": a["action"], "arg": a["arg"]} for a in rule["actions"]]}


# --------------------------------------------------------------------------- #
# Hit log
# --------------------------------------------------------------------------- #
def log_hit(rule: dict, action: str, *, message_id: int | None, ctx: Context, detail: str = "",
            ok: bool = True) -> None:
    db.execute(
        "INSERT INTO rule_hits(at, rule_id, message_id, sender, rcpt, subject, action, detail, ok)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (int(time.time()), rule["id"], message_id, ctx.sender[:200], ctx.recipient, ctx.subject[:200],
         action, detail[:300], 1 if ok else 0),
    )


def forwards_last_hour() -> int:
    """Successful rule-triggered forwards in the last hour (used for the hourly cap)."""
    row = db.one("SELECT COUNT(*) AS c FROM rule_hits WHERE action='forward' AND ok=1 AND at > ?",
                 (int(time.time()) - 3600,))
    return row["c"]
