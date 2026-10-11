"""Favorites: a named group of recipient addresses with notes. The favorite page shows every
message sent to any of its addresses and every rule scoped to one of them."""
from __future__ import annotations

import re
import time

from . import db, rules

ADDRESS_RE = re.compile(r"[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+")


class FavoriteError(ValueError):
    pass


def parse_addresses(text: str) -> list[str]:
    """Split on whitespace/commas/semicolons, lowercase, de-duplicate (order kept) and validate."""
    seen: list[str] = []
    invalid: list[str] = []
    for token in re.split(r"[\s,;]+", text or ""):
        token = token.strip().strip("<>").lower()
        if not token:
            continue
        if not ADDRESS_RE.fullmatch(token):
            invalid.append(token)
        elif token not in seen:
            seen.append(token)
    if invalid:
        raise FavoriteError("Not a valid email address: " + ", ".join(invalid[:3]))
    if not seen:
        raise FavoriteError("Add at least one recipient address")
    return seen


def _clean(name: str, notes: str) -> tuple[str, str]:
    name = (name or "").strip()
    if not name:
        raise FavoriteError("Give the favorite a name")
    return name[:80], (notes or "").strip()[:4000]


def create(name: str, addresses: str, notes: str = "") -> int:
    name, notes = _clean(name, notes)
    addrs = parse_addresses(addresses)
    with db.tx() as conn:
        fid = conn.execute("INSERT INTO favorites(name, notes, created_at) VALUES(?,?,?)",
                           (name, notes, int(time.time()))).lastrowid
        conn.executemany("INSERT INTO favorite_addresses(favorite_id, address) VALUES(?,?)",
                         [(fid, a) for a in addrs])
    return fid


def update(fid: int, name: str, addresses: str, notes: str = "") -> None:
    name, notes = _clean(name, notes)
    addrs = parse_addresses(addresses)
    with db.tx() as conn:
        conn.execute("UPDATE favorites SET name=?, notes=? WHERE id=?", (name, notes, fid))
        conn.execute("DELETE FROM favorite_addresses WHERE favorite_id=?", (fid,))
        conn.executemany("INSERT INTO favorite_addresses(favorite_id, address) VALUES(?,?)",
                         [(fid, a) for a in addrs])


def delete(fid: int) -> None:
    db.execute("DELETE FROM favorites WHERE id=?", (fid,))


def _addresses_by_favorite() -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for r in db.query("SELECT favorite_id, address FROM favorite_addresses ORDER BY rowid"):
        out.setdefault(r["favorite_id"], []).append(r["address"])
    return out


def get_favorite(fid: int) -> dict | None:
    row = db.one("SELECT * FROM favorites WHERE id=?", (fid,))
    if row is None:
        return None
    addresses = [r["address"] for r in db.query(
        "SELECT address FROM favorite_addresses WHERE favorite_id=? ORDER BY rowid", (fid,))]
    return {**dict(row), "addresses": addresses}


def list_favorites() -> list[dict]:
    """All favorites with message / unread / rule counts, sorted by name."""
    addresses = _addresses_by_favorite()
    per_rcpt = {r["rcpt_to"]: (r["c"], r["u"] or 0) for r in db.query(
        "SELECT rcpt_to, COUNT(*) AS c, SUM(is_read=0) AS u FROM messages GROUP BY rcpt_to")}
    rule_counts = {r["scope"]: r["c"] for r in db.query(
        "SELECT lower(scope) AS scope, COUNT(*) AS c FROM rules WHERE scope IS NOT NULL GROUP BY lower(scope)")}
    result = []
    for row in db.query("SELECT * FROM favorites ORDER BY lower(name)"):
        addrs = addresses.get(row["id"], [])
        result.append({
            **dict(row), "addresses": addrs,
            "messages": sum(per_rcpt.get(a, (0, 0))[0] for a in addrs),
            "unread": sum(per_rcpt.get(a, (0, 0))[1] for a in addrs),
            "rules": sum(rule_counts.get(a, 0) for a in addrs),
        })
    return result


def favorites_containing(address: str) -> list[dict]:
    return [dict(r) for r in db.query(
        "SELECT f.* FROM favorites f JOIN favorite_addresses a ON a.favorite_id=f.id WHERE a.address=?",
        (address.lower(),))]


def rules_for(addresses: list[str]) -> list[dict]:
    return rules.rules_for_scopes(addresses)
