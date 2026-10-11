"""Shared helpers for pages that embed the rule editor (rules page, favorite page)."""
from __future__ import annotations

from .. import rules


def safe_next(value: str, default: str) -> str:
    """Only allow local paths as redirect target."""
    return value if value.startswith("/") and not value.startswith("//") else default


def parse_rule_form(form) -> dict:
    """Read the editor form: parallel arrays cond_* (0..n rows) and act_* (1..n rows)."""
    def many(name: str) -> list[str]:
        return [str(v) for v in form.getlist(name)]

    fields, headers, ops, values = many("cond_field"), many("cond_header"), many("cond_op"), many("cond_value")
    types, args = many("act_type"), many("act_arg")

    def at(seq: list[str], i: int) -> str:
        return seq[i] if i < len(seq) else ""

    conditions = [{"field": at(fields, i), "header": at(headers, i), "op": at(ops, i), "value": at(values, i)}
                  for i in range(max(len(fields), len(ops), len(values)))]
    actions = [{"action": t, "arg": at(args, i)} for i, t in enumerate(types)]
    try:
        priority = int(str(form.get("priority", "100")) or 100)
    except ValueError:
        priority = 100
    return {
        "conditions": conditions, "actions": actions, "priority": priority,
        "scope": str(form.get("scope", "")).strip(), "name": str(form.get("name", "")),
        "match_mode": str(form.get("match_mode", "all")), "next": str(form.get("next", "")),
    }


def editor_context(scope_options: list[str], next_url: str) -> dict:
    return {
        "editor_fields": [(f, rules.FIELD_LABELS[f]) for f in rules.FIELDS],
        "editor_ops": [(o, rules.OP_LABELS[o]) for o in rules.OPS],
        "editor_actions": [(a, rules.ACTION_LABELS[a]) for a in rules.ACTIONS],
        "scope_options": scope_options,
        "editor_next": next_url,
    }
