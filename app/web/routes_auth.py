"""Login, logout and the user's own account page."""
from __future__ import annotations

import time
from collections import defaultdict

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth, db
from .deps import back, current_user, render, session, verify_csrf

router = APIRouter()
_failures: dict[str, list[float]] = defaultdict(list)
MAX_FAILURES, WINDOW = 8, 300


def _throttled(ip: str) -> bool:
    now = time.time()
    _failures[ip] = [t for t in _failures[ip] if now - t < WINDOW]
    return len(_failures[ip]) >= MAX_FAILURES


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if session(request).get("uid") and auth.get_user(session(request)["uid"]):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html")


@router.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = request.client.host if request.client else "?"
    if _throttled(ip):
        return render(request, "login.html", status_code=429, err="Too many attempts, try again in a few minutes")
    user = auth.authenticate(username, password)
    if user is None:
        _failures[ip].append(time.time())
        return render(request, "login.html", status_code=401, err="Wrong username or password", username=username)
    from .. import config
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        auth.COOKIE, auth.make_session(user["id"]), max_age=auth.SESSION_MAX_AGE,
        httponly=True, samesite="lax", secure=config.boot().cookie_secure)
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.COOKIE)
    return response


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, user=Depends(current_user)):
    return render(request, "account.html", nav="account")


@router.post("/account", dependencies=[Depends(verify_csrf)])
def account_save(name: str = Form(""), current: str = Form(""), new_password: str = Form(""),
                 user=Depends(current_user)):
    if new_password:
        if not auth.verify_password(user["password_hash"], current):
            return back("/account", err="Current password is wrong")
        if len(new_password) < 8:
            return back("/account", err="Password must be at least 8 characters")
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (auth.hash_password(new_password), user["id"]))
    db.execute("UPDATE users SET name=? WHERE id=?", (name.strip(), user["id"]))
    return back("/account", ok="Saved")
