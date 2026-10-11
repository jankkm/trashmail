"""Login, logout and the user's own account page."""
from __future__ import annotations

import time
from collections import defaultdict

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth, config, db, forwarder, totp
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
    if user["totp_enabled"]:
        response = RedirectResponse("/login/2fa", status_code=303)
        response.set_cookie(
            auth.PENDING_COOKIE, auth.make_pending(user["id"]), max_age=auth.PENDING_MAX_AGE,
            httponly=True, samesite="lax", secure=config.boot().cookie_secure)
        return response
    return _finish_login(user["id"])


def _finish_login(user_id: int) -> RedirectResponse:
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        auth.COOKIE, auth.make_session(user_id), max_age=auth.SESSION_MAX_AGE,
        httponly=True, samesite="lax", secure=config.boot().cookie_secure)
    response.delete_cookie(auth.PENDING_COOKIE)
    return response


# Second login step: only reachable with the short-lived pending cookie set after the password.
_2fa_failures: dict[int, list[float]] = defaultdict(list)
MAX_2FA_FAILURES, WINDOW_2FA = 5, 900


def _2fa_locked(uid: int) -> bool:
    now = time.time()
    _2fa_failures[uid] = [t for t in _2fa_failures[uid] if now - t < WINDOW_2FA]
    return len(_2fa_failures[uid]) >= MAX_2FA_FAILURES


@router.get("/login/2fa", response_class=HTMLResponse)
def login_2fa_form(request: Request):
    uid = auth.read_pending(request.cookies.get(auth.PENDING_COOKIE))
    if uid is None:
        return RedirectResponse("/login", status_code=303)
    return render(request, "login_2fa.html")


@router.post("/login/2fa")
def login_2fa(request: Request, code: str = Form("")):
    uid = auth.read_pending(request.cookies.get(auth.PENDING_COOKIE))
    user = auth.get_user(uid) if uid else None
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ip = request.client.host if request.client else "?"
    if _throttled(ip) or _2fa_locked(uid):
        return render(request, "login_2fa.html", status_code=429,
                      err="Too many attempts. Wait a few minutes and sign in again.")
    if not auth.check_second_factor(user, code):
        _failures[ip].append(time.time())
        _2fa_failures[uid].append(time.time())
        return render(request, "login_2fa.html", status_code=401, err="That code is not valid")
    _2fa_failures.pop(uid, None)
    return _finish_login(uid)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.COOKIE)
    return response


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, user=Depends(current_user)):
    return render(request, "account.html", nav="account")


@router.post("/account", dependencies=[Depends(verify_csrf)])
def account_save(name: str = Form(""), default_view: str = Form(""), forward_email: str = Form(""),
                 forward_mode: str = Form(""), user=Depends(current_user)):
    forward_email = forward_email.strip()
    if forward_email and not forwarder.ADDRESS_RE.fullmatch(forward_email):
        return back("/account", err="Forwarding address is not a valid email address")
    db.execute("UPDATE users SET name=?, forward_email=? WHERE id=?", (name.strip(), forward_email, user["id"]))
    if default_view in ("all", "unread", "flagged"):
        db.execute("UPDATE users SET default_view=? WHERE id=?", (default_view, user["id"]))
    if forward_mode in ("forward", "redirect"):
        db.execute("UPDATE users SET forward_mode=? WHERE id=?", (forward_mode, user["id"]))
    return back("/account", ok="Saved")


@router.post("/account/password", dependencies=[Depends(verify_csrf)])
def account_password(current: str = Form(""), new_password: str = Form(""), user=Depends(current_user)):
    if not auth.verify_password(user["password_hash"], current):
        return back("/account", err="Current password is wrong")
    if len(new_password) < 8:
        return back("/account", err="Password must be at least 8 characters")
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (auth.hash_password(new_password), user["id"]))
    return back("/account", ok="Password changed")


@router.post("/account/default-view", dependencies=[Depends(verify_csrf)])
def set_default_view(view: str = Form(""), next: str = Form("/"), user=Depends(current_user)):
    """The "make default" pin next to the inbox view switch."""
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    if view not in ("all", "unread", "flagged"):
        return back(target, err="Unknown view")
    db.execute("UPDATE users SET default_view=? WHERE id=?", (view, user["id"]))
    return back(target, ok=f"“{view.capitalize()}” is now your default inbox view")


# --- two-factor authentication management ---------------------------------------------------- #
@router.get("/account/2fa", response_class=HTMLResponse)
def twofa_page(request: Request, user=Depends(current_user)):
    ctx: dict = {"nav": "account", "enabled": bool(user["totp_enabled"]),
                 "codes_left": auth.recovery_codes_left(user)}
    if not user["totp_enabled"] and user["totp_secret"]:
        uri = totp.provisioning_uri(user["totp_secret"], user["username"])
        ctx.update(pending=True, qr=totp.qr_svg(uri), secret=totp.format_secret(user["totp_secret"]))
    return render(request, "twofa.html", **ctx)


@router.post("/account/2fa/start", dependencies=[Depends(verify_csrf)])
def twofa_start(user=Depends(current_user)):
    if not user["totp_enabled"]:
        auth.totp_start_setup(user["id"])
    return back("/account/2fa")


@router.post("/account/2fa/enable", dependencies=[Depends(verify_csrf)])
def twofa_enable(request: Request, code: str = Form(""), user=Depends(current_user)):
    codes = auth.totp_confirm(user["id"], code)
    if codes is None:
        return back("/account/2fa", err="That code is not valid. Check the time on your phone and try again.")
    return render(request, "twofa.html", nav="account", enabled=True, new_codes=codes,
                  codes_left=len(codes))


@router.post("/account/2fa/disable", dependencies=[Depends(verify_csrf)])
def twofa_disable(password: str = Form(""), user=Depends(current_user)):
    if not auth.verify_password(user["password_hash"], password):
        return back("/account/2fa", err="Wrong password")
    auth.totp_disable(user["id"])
    return back("/account/2fa", ok="Two-factor authentication disabled")
