"""Inbox list, message view, download, forward, flag, delete."""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlencode, quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .. import favorites, forwarder, mailstore, rules
from .deps import admin_user, back, current_user, render, to_int, verify_csrf

router = APIRouter()
PER_PAGE = 50
VIEWS = ("all", "unread", "flagged")


def _row_or_404(mid: int):
    row = mailstore.get(mid)
    if row is None:
        raise HTTPException(404, "Message not found")
    return row


@router.get("/", response_class=HTMLResponse)
def inbox(request: Request, q: str = "", rcpt: str = "", fav: str = "", tag: str = "", view: str = "",
          flagged: str = "", unread: str = "", page: str = "1", user=Depends(current_user)):
    fav, page = to_int(fav), max(to_int(page, 1), 1)
    default_view = user["default_view"] if user["default_view"] in VIEWS else "all"
    if view not in VIEWS:                        # no explicit choice: legacy params, else the user's default
        view = "unread" if to_int(unread) else "flagged" if to_int(flagged) else default_view
    favs = favorites.list_favorites()
    selected = next((f for f in favs if f["id"] == fav), None)
    rows, total = mailstore.list_messages(
        q=q, rcpt=rcpt, rcpts=selected["addresses"] if selected else None, tag=tag,
        flagged=view == "flagged", unread=view == "unread", limit=PER_PAGE, offset=(page - 1) * PER_PAGE)
    search = {k: v for k, v in {"q": q, "rcpt": rcpt, "fav": selected["id"] if selected else "",
                                "tag": tag}.items() if v}
    base = {**search, "view": view}
    return render(
        request, "inbox.html", nav="inbox", rows=rows, total=total, page=page,
        pages=max(1, -(-total // PER_PAGE)), q=q, rcpt=rcpt, fav=selected["id"] if selected else 0, tag=tag,
        favs=favs, view=view, default_view=default_view, msg_tags=mailstore.tags_for([r["id"] for r in rows]),
        all_tags=mailstore.all_tags(), recipients=mailstore.recipients(), stats=mailstore.stats(),
        histogram=mailstore.hourly_histogram(), base_qs=urlencode(base), qs_search=urlencode(search),
        now=datetime.now().strftime("%H:%M"), full_qs=urlencode({**base, "page": page}))


@router.get("/messages/{mid}", response_class=HTMLResponse)
def message(request: Request, mid: int, user=Depends(current_user)):
    row = _row_or_404(mid)
    if not row["is_read"]:
        mailstore.set_read([mid], True)
    view = mailstore.build_view(mailstore.read_raw(row))
    prefill = ""
    return render(request, "message.html", nav="inbox", m=row, view=view,
                  forward_ok=forwarder.configured(), prefill=prefill,
                  sender_addr=row["mail_from"], sender_domain=row["mail_from"].rpartition("@")[2],
                  rcpt_domain=row["rcpt_to"].rpartition("@")[2],
                  tags=mailstore.tags_for([mid]).get(mid, []), all_tags=mailstore.all_tags(),
                  back_qs=request.query_params.get("from", ""))


@router.get("/messages/{mid}/body", response_class=HTMLResponse)
def message_body(mid: int, external: int = 0, user=Depends(current_user)):
    row = _row_or_404(mid)
    view = mailstore.build_view(mailstore.read_raw(row))
    return HTMLResponse(
        mailstore.body_document(view, bool(external)),
        headers={"Content-Security-Policy": mailstore.csp(bool(external)),
                 "Cache-Control": "no-store"})


@router.get("/messages/{mid}/download")
def download(mid: int, user=Depends(current_user)):
    row = _row_or_404(mid)
    name = re.sub(r"[^\w.\-]+", "_", row["subject"] or "message")[:60] or "message"
    return Response(
        mailstore.read_raw(row), media_type="message/rfc822",
        headers={"Content-Disposition": f"attachment; filename=\"{name}.eml\""})


@router.get("/messages/{mid}/attachment/{idx}")
def attachment(mid: int, idx: int, user=Depends(current_user)):
    row = _row_or_404(mid)
    found = mailstore.attachment(mailstore.read_raw(row), idx)
    if found is None:
        raise HTTPException(404, "Attachment not found")
    filename, ctype, data = found
    return Response(
        data, media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
                 "X-Content-Type-Options": "nosniff"})


@router.post("/messages/{mid}/forward", dependencies=[Depends(verify_csrf)])
async def forward(request: Request, mid: int, to: str = Form(""), mode: str = Form(""),
                  user=Depends(current_user)):
    """Forward (attachment) or redirect (unchanged) to `to`, or to the address in the user's profile when
    `to` is empty. `mode` defaults to the user's profile choice.
    With `X-Requested-With: fetch` the answer is JSON so the page can stay where it is."""
    row = _row_or_404(mid)
    to = to.strip() or (user["forward_email"] or "")
    if mode not in rules.OUTBOUND:
        mode = user["forward_mode"] if user["forward_mode"] in rules.OUTBOUND else "forward"
    wants_json = request.headers.get("x-requested-with") == "fetch"
    try:
        if not to:
            raise forwarder.ForwardError("No forwarding address: enter one or add it to your account")
        if mode == "redirect":
            await forwarder.redirect_raw(to, mailstore.read_raw(row))
        else:
            await forwarder.forward_raw(
                to, mailstore.read_raw(row), subject=row["subject"],
                summary=(f"Forwarded from Trashmail\nOriginal sender: {row['from_header'] or row['mail_from']}\n"
                         f"Received for: {row['rcpt_to']}\nSubject: {row['subject']}\n"))
    except forwarder.ForwardError as exc:
        if wants_json:
            return JSONResponse({"ok": False, "message": str(exc)}, status_code=422)
        return back(f"/messages/{mid}", err=str(exc))
    done = f"{'Redirected' if mode == 'redirect' else 'Forwarded'} to {to}"
    if wants_json:
        return JSONResponse({"ok": True, "message": done})
    return back(f"/messages/{mid}", ok=done)


@router.post("/messages/{mid}/action", dependencies=[Depends(verify_csrf)])
def single_action(mid: int, action: str = Form(...), user=Depends(current_user)):
    _row_or_404(mid)
    if action == "delete":
        mailstore.delete([mid])
        return back("/", ok="Message deleted")
    if action in ("flag", "unflag"):
        mailstore.set_flag([mid], action == "flag")
    elif action in ("read", "unread"):
        mailstore.set_read([mid], action == "read")
    return back(f"/messages/{mid}")


@router.post("/messages/{mid}/star", dependencies=[Depends(verify_csrf)])
def toggle_star(request: Request, mid: int, next: str = Form("/"), user=Depends(current_user)):
    """Flag/unflag from the star in the list. The script enhancement calls it with fetch and gets 204."""
    row = _row_or_404(mid)
    mailstore.set_flag([mid], not row["flagged"])
    if request.headers.get("x-requested-with") == "fetch":
        return Response(status_code=204)
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    return back(target)


@router.post("/messages/{mid}/tags", dependencies=[Depends(verify_csrf)])
def add_message_tags(mid: int, tag: str = Form(""), user=Depends(current_user)):
    _row_or_404(mid)
    tags = mailstore.parse_tags(tag)
    if not tags:
        return back(f"/messages/{mid}", err="Enter a tag name")
    mailstore.add_tags([mid], tags)
    return back(f"/messages/{mid}")


@router.post("/messages/{mid}/tags/remove", dependencies=[Depends(verify_csrf)])
def remove_message_tag(mid: int, tag: str = Form(""), user=Depends(current_user)):
    _row_or_404(mid)
    mailstore.remove_tag(mid, tag)
    return back(f"/messages/{mid}")


@router.post("/messages/{mid}/blacklist", dependencies=[Depends(verify_csrf)])
def blacklist_from_message(mid: int, kind: str = Form(...), admin=Depends(admin_user)):
    row = _row_or_404(mid)
    value = {
        "sender_address": row["mail_from"], "sender_domain": row["mail_from"].rpartition("@")[2],
        "rcpt_address": row["rcpt_to"], "rcpt_domain": row["rcpt_to"].rpartition("@")[2],
    }.get(kind, "")
    try:
        rules.add_blacklist(kind, value)
    except rules.RuleError as exc:
        return back(f"/messages/{mid}", err=str(exc))
    return back(f"/messages/{mid}", ok=f"Blacklisted {value}")


@router.post("/messages/bulk", dependencies=[Depends(verify_csrf)])
def bulk(action: str = Form(...), ids: list[int] = Form([]), next: str = Form("/"), tag: str = Form(""),
         user=Depends(current_user)):
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    if not ids:
        return back(target, err="Nothing selected")
    if action == "delete":
        count = mailstore.delete(ids)
        return back(target, ok=f"Deleted {count} message(s)")
    if action == "tag":
        tags = mailstore.parse_tags(tag)
        if not tags:
            return back(target, err="Enter a tag name")
        mailstore.add_tags(ids, tags)
        return back(target, ok=f"Tagged {len(ids)} message(s)")
    if action in ("flag", "unflag"):
        mailstore.set_flag(ids, action == "flag")
    elif action in ("read", "unread"):
        mailstore.set_read(ids, action == "read")
    return back(target)
