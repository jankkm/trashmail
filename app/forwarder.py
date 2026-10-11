"""Outbound mail via the configured (UI > env) SMTP account."""
from __future__ import annotations

import logging
import re
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import aiosmtplib

from . import config

log = logging.getLogger(__name__)
FORWARD_MARKER = "X-Trashmail-Forwarded"
ADDRESS_RE = re.compile(r"[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+")


class ForwardError(Exception):
    pass


def configured() -> bool:
    return bool(config.get("FORWARD_SMTP_HOST"))


def _from_address() -> str:
    from_addr = config.get("FORWARD_FROM") or config.get("FORWARD_SMTP_USER")
    if not from_addr or "@" not in from_addr:
        raise ForwardError("Set 'Forwarding From address' (or an SMTP user that is an email address)")
    return from_addr


async def _send(msg: EmailMessage) -> None:
    host = config.get("FORWARD_SMTP_HOST")
    if not host:
        raise ForwardError("No forwarding SMTP server configured (Settings → Forwarding)")
    security = config.get("FORWARD_SMTP_SECURITY")
    user = config.get("FORWARD_SMTP_USER") or None
    password = config.get("FORWARD_SMTP_PASSWORD") or None
    try:
        await aiosmtplib.send(
            msg, hostname=host, port=config.get_int("FORWARD_SMTP_PORT"),
            username=user, password=password,
            use_tls=(security == "ssl"), start_tls=(security == "starttls"),
            timeout=30,
        )
    except Exception as exc:
        raise ForwardError(f"SMTP error: {exc}") from exc


async def forward_raw(to: str, raw: bytes, *, subject: str, summary: str) -> None:
    """Forward a stored message as an .eml attachment (keeps SPF/DKIM of the
    forwarding account valid; the original stays intact)."""
    if not ADDRESS_RE.fullmatch(to.strip()):
        raise ForwardError("Invalid destination address")
    msg = EmailMessage()
    msg["From"] = _from_address()
    msg["To"] = to.strip()
    msg["Subject"] = f"Fwd: {subject}"[:250]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="trashmail.local")
    msg[FORWARD_MARKER] = "1"
    msg.set_content(summary)
    msg.add_attachment(raw, maintype="application", subtype="octet-stream", filename="original.eml")
    await _send(msg)


async def send_test(to: str) -> None:
    if not ADDRESS_RE.fullmatch(to.strip()):
        raise ForwardError("Invalid destination address")
    msg = EmailMessage()
    msg["From"] = _from_address()
    msg["To"] = to.strip()
    msg["Subject"] = "Trashmail forwarding test"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="trashmail.local")
    msg.set_content("If you can read this, forwarding from Trashmail works.")
    await _send(msg)
