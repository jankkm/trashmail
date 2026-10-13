"""Shared web helpers: templates, session/auth dependencies, CSRF, redirects."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

import zlib
from email.utils import parseaddr

from .. import auth, config, forwarder, mailstore
from .icons import icon

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))


def _dt_text(ts) -> str:
    return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M")


def _short_text(ts) -> str:
    d = datetime.fromtimestamp(int(ts))
    now = datetime.now()
    if d.date() == now.date():
        return d.strftime("%H:%M")
    if d.year == now.year:
        return d.strftime("%d.%m. %H:%M")
    return d.strftime("%d.%m.%Y")


def _time(ts, fmt: str, text: str) -> Markup:
    """<time> in server time; app.js rewrites it into the browser's local time zone (the server usually runs in UTC)."""
    iso = datetime.fromtimestamp(int(ts), timezone.utc).isoformat()
    return Markup('<time datetime="{}" data-ts="{}" data-fmt="{}">{}</time>').format(iso, int(ts), fmt, text)


def _dt(ts) -> Markup:
    return _time(ts, "dt", _dt_text(ts))


def _short(ts) -> Markup:
    return _time(ts, "short", _short_text(ts))


def _hm(ts) -> Markup:
    return _time(ts, "hm", datetime.fromtimestamp(int(ts)).strftime("%H:%M"))


def _size(n) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _parts(value) -> tuple[str, str]:
    name, addr = parseaddr(str(value or ""))
    return name.strip(), addr.strip()


def _sname(value) -> str:
    name, addr = _parts(value)
    return name or addr or "(unknown sender)"


def _saddr(value) -> str:
    return _parts(value)[1]


def _initials(value) -> str:
    text = _sname(value)
    words = [w for w in text.replace("@", " ").replace(".", " ").replace("-", " ").split() if w[:1].isalnum()]
    if not words:
        return "?"
    return (words[0][0] + (words[1][0] if len(words) > 1 else "")).upper()


def _hue(value) -> int:
    return zlib.crc32(_saddr(value).lower().encode() or b"?") % 360


def _taghue(tag) -> int:
    return zlib.crc32(str(tag).lower().encode()) % 360


templates.env.filters.update({"dt": _dt, "short": _short, "hm": _hm, "size": _size, "sname": _sname,
                              "saddr": _saddr, "initials": _initials, "hue": _hue, "taghue": _taghue})
templates.env.globals["icon"] = icon


def to_int(value, default: int = 0) -> int:
    """Query parameters from HTML forms may be empty ("?fav=") or junk; never fail the request."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class LoginRequired(Exception):
    pass


def session(request: Request) -> dict:
    cached = getattr(request.state, "session", None)
    if cached is None:
        cached = auth.read_session(request.cookies.get(auth.COOKIE)) or {}
        request.state.session = cached
    return cached


def current_user(request: Request):
    sess = session(request)
    user = auth.get_user(sess["uid"]) if sess.get("uid") else None
    if user is None:
        raise LoginRequired()
    return user


def admin_user(user=Depends(current_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "Admin only")
    return user


async def verify_csrf(request: Request, csrf: str = Form("")) -> None:
    expected = session(request).get("csrf")
    if not expected or csrf != expected:
        raise HTTPException(403, "Invalid CSRF token")


def render(request: Request, name: str, status_code: int = 200, **ctx):
    sess = session(request)
    user = auth.get_user(sess["uid"]) if sess.get("uid") else None
    ctx.setdefault("user", user)
    ctx.setdefault("csrf", sess.get("csrf", ""))
    ctx.setdefault("ok", request.query_params.get("ok"))
    ctx.setdefault("err", request.query_params.get("err"))
    ctx.setdefault("domains", ", ".join(config.local_domains()))
    ctx.setdefault("forward_ok", forwarder.configured())
    ctx.setdefault("unread_count", mailstore.stats()["unread"] if user else 0)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def back(url: str, ok: str | None = None, err: str | None = None) -> RedirectResponse:
    params = {}
    if ok:
        params["ok"] = ok
    if err:
        params["err"] = err
    if params:
        url += ("&" if "?" in url else "?") + urlencode(params)
    return RedirectResponse(url, status_code=303)
