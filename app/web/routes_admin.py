"""Rules, blacklist, users and settings pages."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from .. import auth, config, db, forwarder, mailstore, rules
from . import ruleui
from .deps import admin_user, back, current_user, render, verify_csrf

router = APIRouter()
CSRF = [Depends(verify_csrf)]


# --- rules ----------------------------------------------------------------- #
@router.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request, user=Depends(current_user)):
    rows = rules.list_rules()
    hits = db.query("SELECT h.*, r.name AS rule_name FROM rule_hits h LEFT JOIN rules r ON r.id=h.rule_id "
                    "ORDER BY h.id DESC LIMIT 100")
    recipients = [r["rcpt_to"] for r in mailstore.recipients()]
    return render(request, "rules.html", nav="rules", rules=rows, hits=hits, labels=rules,
                  editor_json={r["id"]: rules.rule_for_editor(r) for r in rows},
                  **ruleui.editor_context(recipients, "/rules"))


@router.post("/rules", dependencies=CSRF)
async def rules_add(request: Request, user=Depends(current_user)):
    data = ruleui.parse_rule_form(await request.form())
    target = ruleui.safe_next(data["next"], "/rules")
    try:
        rules.create_rule(conditions=data["conditions"], actions=data["actions"], scope=data["scope"],
                          name=data["name"], match_mode=data["match_mode"], priority=data["priority"])
    except rules.RuleError as exc:
        return back(target, err=str(exc))
    return back(target, ok="Rule added")


@router.post("/rules/{rid}/update", dependencies=CSRF)
async def rules_update(rid: int, request: Request, user=Depends(current_user)):
    data = ruleui.parse_rule_form(await request.form())
    target = ruleui.safe_next(data["next"], "/rules")
    if rules.get_rule(rid) is None:
        return back(target, err="Rule not found")
    try:
        rules.update_rule(rid, conditions=data["conditions"], actions=data["actions"], scope=data["scope"],
                          name=data["name"], match_mode=data["match_mode"], priority=data["priority"])
    except rules.RuleError as exc:
        return back(target, err=str(exc))
    return back(target, ok="Rule saved")


@router.post("/rules/{rid}/toggle", dependencies=CSRF)
def rules_toggle(rid: int, next: str = Form(""), user=Depends(current_user)):
    db.execute("UPDATE rules SET enabled = 1 - enabled WHERE id=?", (rid,))
    return back(ruleui.safe_next(next, "/rules"))


@router.post("/rules/{rid}/delete", dependencies=CSRF)
def rules_delete(rid: int, next: str = Form(""), user=Depends(current_user)):
    rules.delete_rule(rid)
    return back(ruleui.safe_next(next, "/rules"), ok="Rule deleted")


# --- blacklist ------------------------------------------------------------- #
@router.get("/blacklist", response_class=HTMLResponse)
def blacklist_page(request: Request, admin=Depends(admin_user)):
    rows = db.query("SELECT * FROM blacklist ORDER BY kind, value")
    return render(request, "blacklist.html", nav="blacklist", entries=rows, kinds=rules.BLACKLIST_KINDS)


@router.post("/blacklist", dependencies=CSRF)
def blacklist_add(kind: str = Form(...), value: str = Form(""), admin=Depends(admin_user)):
    try:
        rules.add_blacklist(kind, value)
    except rules.RuleError as exc:
        return back("/blacklist", err=str(exc))
    return back("/blacklist", ok="Added")


@router.post("/blacklist/{bid}/delete", dependencies=CSRF)
def blacklist_delete(bid: int, admin=Depends(admin_user)):
    db.execute("DELETE FROM blacklist WHERE id=?", (bid,))
    return back("/blacklist", ok="Removed")


# --- users ----------------------------------------------------------------- #
@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, admin=Depends(admin_user)):
    return render(request, "users.html", nav="users", users=auth.list_users())


@router.post("/users", dependencies=CSRF)
def users_add(username: str = Form(""), password: str = Form(""), name: str = Form(""),
              is_admin: str = Form(""), admin=Depends(admin_user)):
    try:
        auth.create_user(username, password, name, bool(is_admin))
    except auth.UserError as exc:
        return back("/users", err=str(exc))
    return back("/users", ok=f"User {username.strip()} created")


@router.post("/users/{uid}/update", dependencies=CSRF)
def users_update(uid: int, name: str = Form(""), is_admin: str = Form(""), password: str = Form(""),
                 admin=Depends(admin_user)):
    try:
        auth.update_user(uid, name=name, is_admin=bool(is_admin), password=password)
    except auth.UserError as exc:
        return back("/users", err=str(exc))
    return back("/users", ok="User updated")


@router.post("/users/{uid}/reset-2fa", dependencies=CSRF)
def users_reset_2fa(uid: int, admin=Depends(admin_user)):
    if auth.get_user(uid) is None:
        return back("/users", err="User not found")
    auth.totp_disable(uid)
    return back("/users", ok="Two-factor authentication reset")


@router.post("/users/{uid}/delete", dependencies=CSRF)
def users_delete(uid: int, admin=Depends(admin_user)):
    try:
        auth.delete_user(uid, admin["id"])
    except auth.UserError as exc:
        return back("/users", err=str(exc))
    return back("/users", ok="User deleted")


# --- settings -------------------------------------------------------------- #
@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, admin=Depends(admin_user)):
    items = []
    for s in config.SETTING_LIST:
        if s.secret:
            shown = ""
        elif s.kind == "bool":
            shown = "true" if config.get_bool(s.key) else "false"
        else:
            shown = config.get(s.key)
        items.append({
            "s": s, "source": config.source(s.key),
            "value": shown,
            "is_set": bool(config.get(s.key)),
        })
    groups: dict[str, list] = {}
    for item in items:
        groups.setdefault(item["s"].group, []).append(item)
    from .deps import _size
    used, cap = mailstore.storage_used(0), mailstore.storage_cap()
    return render(request, "settings.html", nav="settings", groups=groups,
                  used_human=_size(used), cap_human=_size(cap) if cap else "",
                  usage_pct=round(100 * used / cap) if cap else None,
                  tls=bool(config.boot().tls_cert and config.boot().tls_key),
                  smtp_port=config.boot().smtp_port)


@router.post("/settings", dependencies=CSRF)
async def settings_save(request: Request, admin=Depends(admin_user)):
    form = await request.form()
    for s in config.SETTING_LIST:
        if s.key not in form:
            continue
        value = str(form[s.key]).strip()
        if s.secret and not value:
            continue  # blank = keep current
        if s.kind == "int":
            try:
                int(value)
            except ValueError:
                return back("/settings", err=f"{s.label} must be a number")
        if s.kind == "choice" and value not in s.choices:
            return back("/settings", err=f"Invalid value for {s.label}")
        current = config.get(s.key)
        if s.kind == "bool":
            value = "true" if value.lower() in config.TRUE_VALUES else "false"
            current = "true" if config.get_bool(s.key) else "false"
        elif s.kind == "int":
            value, current = str(int(value)), str(config.get_int(s.key))
        if value != current:
            config.set_value(s.key, value, "ui")
    return back("/settings", ok="Settings saved")


@router.post("/settings/reset/{key}", dependencies=CSRF)
def settings_reset(key: str, admin=Depends(admin_user)):
    if key in config.SETTINGS:
        config.reset(key)
    return back("/settings", ok=f"{key} reset to environment/default")


@router.post("/settings/test-forward", dependencies=CSRF)
async def settings_test(to: str = Form(""), admin=Depends(admin_user)):
    try:
        await forwarder.send_test(to)
    except forwarder.ForwardError as exc:
        return back("/settings", err=str(exc))
    return back("/settings", ok=f"Test mail sent to {to.strip()}")
