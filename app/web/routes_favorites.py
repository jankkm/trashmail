"""Favorites: named groups of recipient addresses with notes, their emails and their rules."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import favorites, mailstore, rules
from . import ruleui
from .deps import back, current_user, render, to_int, verify_csrf

router = APIRouter()
PER_PAGE = 25


def _get(fid: int) -> dict:
    fav = favorites.get_favorite(fid)
    if fav is None:
        raise HTTPException(404, "Favorite not found")
    return fav


@router.get("/favorites", response_class=HTMLResponse)
def favorites_page(request: Request, user=Depends(current_user)):
    favs = favorites.list_favorites()
    used = {a for f in favs for a in f["addresses"]}
    suggestions = [r["rcpt_to"] for r in mailstore.recipients() if r["rcpt_to"] not in used][:10]
    return render(request, "favorites.html", nav="favorites", favs=favs, suggestions=suggestions)


@router.post("/favorites", dependencies=[Depends(verify_csrf)])
def favorites_create(name: str = Form(""), addresses: str = Form(""), notes: str = Form(""),
                     user=Depends(current_user)):
    try:
        fid = favorites.create(name, addresses, notes)
    except favorites.FavoriteError as exc:
        return back("/favorites", err=str(exc))
    return back(f"/favorites/{fid}", ok="Favorite created")


@router.get("/favorites/{fid}", response_class=HTMLResponse)
def favorite_page(request: Request, fid: int, q: str = "", unread: str = "", flagged: str = "",
                  page: str = "1", user=Depends(current_user)):
    fav = _get(fid)
    unread, flagged, page = to_int(unread), to_int(flagged), max(to_int(page, 1), 1)
    rows, total = mailstore.list_messages(
        q=q, rcpts=fav["addresses"], flagged=bool(flagged), unread=bool(unread),
        limit=PER_PAGE, offset=(page - 1) * PER_PAGE)
    scoped = favorites.rules_for(fav["addresses"])
    everyone = [r for r in rules.list_rules() if not r["scope"]]
    stats = favorites.list_favorites()
    mine = next((f for f in stats if f["id"] == fid), {"messages": 0, "unread": 0, "trashed": 0})
    base = {k: v for k, v in {"q": q, "flagged": flagged or "", "unread": unread or ""}.items() if v}
    path = f"/favorites/{fid}"
    here = path + ("?" + urlencode({**base, "page": page}) if page > 1 or base else "")
    return render(
        request, "favorite.html", nav="favorites", fav=fav, rows=rows, total=total, page=page,
        pages=max(1, -(-total // PER_PAGE)), q=q, unread=bool(unread), flagged=bool(flagged),
        scoped_rules=scoped, global_rules=everyone, counts=mine, labels=rules,
        pager_url=path + "?" + (urlencode(base) + "&" if base else ""), next_url=here,
        editor_json={r["id"]: rules.rule_for_editor(r) for r in scoped + everyone},
        suggestions=[], msg_tags=mailstore.tags_for([r["id"] for r in rows]),
        **ruleui.editor_context(fav["addresses"], path))


@router.post("/favorites/{fid}/update", dependencies=[Depends(verify_csrf)])
def favorite_update(fid: int, name: str = Form(""), addresses: str = Form(""), notes: str = Form(""),
                    user=Depends(current_user)):
    _get(fid)
    try:
        favorites.update(fid, name, addresses, notes)
    except favorites.FavoriteError as exc:
        return back(f"/favorites/{fid}", err=str(exc))
    return back(f"/favorites/{fid}", ok="Favorite saved")


@router.post("/favorites/{fid}/delete", dependencies=[Depends(verify_csrf)])
def favorite_delete(fid: int, user=Depends(current_user)):
    _get(fid)
    favorites.delete(fid)
    return back("/favorites", ok="Favorite deleted. Emails and rules are untouched.")
