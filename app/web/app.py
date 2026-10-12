"""FastAPI application factory."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .. import auth, config, db, mailstore, smtp_server
from . import routes_admin, routes_auth, routes_favorites, routes_mail
from .deps import BASE, LoginRequired, render

log = logging.getLogger(__name__)


async def _retention_loop() -> None:
    while True:
        try:
            removed = await asyncio.to_thread(mailstore.purge_expired)
            if removed:
                log.info("retention: removed %s messages", removed)
            emptied = await asyncio.to_thread(mailstore.purge_trash)
            if emptied:
                log.info("recycle bin: removed %s messages", emptied)
        except Exception:
            log.exception("retention run failed")
        await asyncio.sleep(3600)


def create_app(start_smtp: bool = True) -> FastAPI:
    db.init()
    config.seed_from_env()
    auth.bootstrap_admin()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        controller = smtp_server.start() if start_smtp else None
        task = asyncio.create_task(_retention_loop())
        try:
            yield
        finally:
            task.cancel()
            if controller is not None:
                controller.stop()

    app = FastAPI(title="Trashmail", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
    app.include_router(routes_auth.router)
    app.include_router(routes_mail.router)
    app.include_router(routes_favorites.router)
    app.include_router(routes_admin.router)

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        return render(request, "error.html", status_code=exc.status_code,
                      code=exc.status_code, message=exc.detail)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        return response

    return app
