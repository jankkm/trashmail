"""Receiving SMTP server (aiosmtpd).

Policy is enforced during the dialogue so rejected mail gets a real 4xx/5xx:
  connect   : global and per-IP concurrent connection limits (421)
  commands  : per-session command limit (aiosmtpd command_call_limit)
  MAIL FROM : storage cap (452), sender blacklist, per-IP rate limit
  RCPT TO   : local-domain allow list, recipient blacklist, recipient limit (452)
  DATA      : size limit, storage cap, SPF reject (optional), then rules and storage
This server never relays; accepted mail is only stored locally.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
from collections import defaultdict, deque

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP

from . import config, forwarder, mailstore, rules, security_checks

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Connection limits
# --------------------------------------------------------------------------- #
class ConnectionTracker:
    """Counts open connections. Only touched from the SMTP event-loop thread."""

    def __init__(self) -> None:
        self.total = 0
        self.per_ip: dict[str, int] = defaultdict(int)

    def acquire(self, ip: str) -> bool:
        max_total = config.get_int("MAX_CONNECTIONS")
        max_ip = config.get_int("MAX_CONNECTIONS_PER_IP")
        if max_total > 0 and self.total >= max_total:
            return False
        if max_ip > 0 and self.per_ip[ip] >= max_ip:
            return False
        self.total += 1
        self.per_ip[ip] += 1
        return True

    def release(self, ip: str) -> None:
        self.total = max(self.total - 1, 0)
        self.per_ip[ip] -= 1
        if self.per_ip[ip] <= 0:
            self.per_ip.pop(ip, None)


class LimitedSMTP(SMTP):
    """SMTP protocol that refuses connections beyond the configured limits."""

    tracker: ConnectionTracker

    def connection_made(self, transport) -> None:
        peer = transport.get_extra_info("peername")
        self._tm_ip = peer[0] if peer else ""
        self._tm_counted = self.tracker.acquire(self._tm_ip)
        if not self._tm_counted:
            log.info("connection from %s refused (limit reached)", self._tm_ip)
            transport.write(b"421 4.7.0 Too many connections, try again later\r\n")
            transport.close()
            return
        super().connection_made(transport)

    def connection_lost(self, error) -> None:
        if not getattr(self, "_tm_counted", False):
            return
        self.tracker.release(self._tm_ip)
        super().connection_lost(error)


class LimitedController(Controller):
    tracker = ConnectionTracker()

    def factory(self):
        smtp = LimitedSMTP(self.handler, **self.SMTP_kwargs)
        smtp.tracker = self.tracker
        return smtp


# --------------------------------------------------------------------------- #
# Policy handler
# --------------------------------------------------------------------------- #
class Handler:
    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)

    def _rate_limited(self, ip: str) -> bool:
        limit = config.get_int("RATE_LIMIT_PER_IP")
        if limit <= 0:
            return False
        now = time.monotonic()
        q = self._hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(self._hits) > 10_000:
            for key in [k for k, v in self._hits.items() if not v]:
                del self._hits[key]
        if len(q) >= limit:
            return True
        q.append(now)
        return False

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        ip = session.peer[0] if session.peer else ""
        if mailstore.storage_full():
            log.warning("storage cap reached, refusing mail from %s", ip)
            return "452 4.3.1 Insufficient system storage, try again later"
        if self._rate_limited(ip):
            return "450 4.7.1 Too many messages from your address, try again later"
        hit = rules.blacklisted(address, sender=True)
        if hit:
            log.info("rejected sender %s from %s (%s)", address, ip, hit)
            return "550 5.7.1 Sender rejected by policy"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        domain = address.rpartition("@")[2]
        if not domain or not rules.domain_allowed(domain):
            return "550 5.7.1 Relay access denied"
        hit = rules.blacklisted(address, sender=False)
        if hit:
            log.info("rejected recipient %s (%s)", address, hit)
            return "550 5.1.1 Recipient rejected by policy"
        limit = config.get_int("MAX_RECIPIENTS")
        if limit > 0 and len(envelope.rcpt_tos) >= limit:
            return "452 4.5.3 Too many recipients"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        raw: bytes = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()
        if len(raw) > config.get_int("MAX_MESSAGE_SIZE"):
            return "552 5.3.4 Message too big"
        # every recipient gets its own stored copy
        if mailstore.storage_full(len(raw) * max(len(envelope.rcpt_tos), 1)):
            return "452 4.3.1 Insufficient system storage, try again later"
        ip = session.peer[0] if session.peer else ""
        mail_from = envelope.mail_from or ""
        auth = await asyncio.to_thread(
            security_checks.check, raw, ip, mail_from, session.host_name or "")
        if auth.spf == "fail" and config.get_bool("SPF_REJECT"):
            return "550 5.7.23 SPF validation failed"
        for rcpt in envelope.rcpt_tos:
            try:
                await deliver(raw, mail_from=mail_from, rcpt=rcpt, ip=ip,
                              helo=session.host_name or "", auth=auth)
            except Exception:
                log.exception("delivery failed for %s", rcpt)
                return "451 4.3.0 Local error, try again later"
        return "250 OK queued"


async def deliver(raw: bytes, *, mail_from: str, rcpt: str, ip: str = "", helo: str = "",
                  auth: security_checks.AuthResult | None = None) -> int | None:
    """Apply rules, then store. Returns the message id, or None if deleted by a rule."""
    msg = mailstore.parse(raw)
    text, _ = mailstore.bodies(msg)
    from_header = str(msg.get("from", "") or "")
    ctx = rules.Context(
        sender=f"{from_header} {mail_from}".strip(), recipient=rcpt.lower(),
        subject=str(msg.get("subject", "") or ""), body=text, msg=msg)

    already_forwarded = bool(msg.get(forwarder.FORWARD_MARKER))
    matched = rules.matching_rules(ctx)
    actions = [(rule, act) for rule in matched for act in rule["actions"]]
    kinds = {act["action"] for _, act in actions}

    mid = None
    if "delete" not in kinds:
        mid = mailstore.store(raw, mail_from=mail_from, rcpt=rcpt, remote_ip=ip, helo=helo, auth=auth,
                              flagged="flag" in kinds, read="mark_read" in kinds,
                              tags=[act["arg"] for _, act in actions if act["action"] == "tag"])

    for rule, act in actions:
        if act["action"] != "forward":
            rules.log_hit(rule, act["action"], message_id=mid, ctx=ctx,
                          detail=act["arg"] if act["action"] == "tag" else "")
            continue
        if already_forwarded:
            rules.log_hit(rule, "forward", message_id=mid, ctx=ctx, detail="skipped: loop protection", ok=False)
            continue
        limit = config.get_int("FORWARD_LIMIT_PER_HOUR")
        if limit > 0 and rules.forwards_last_hour() >= limit:
            log.warning("forward limit of %s/hour reached, not forwarding", limit)
            rules.log_hit(rule, "forward", message_id=mid, ctx=ctx, ok=False,
                          detail=f"skipped: hourly forward limit ({limit}) reached")
            continue
        try:
            await forwarder.forward_raw(
                act["arg"], raw, subject=ctx.subject,
                summary=(f"Forwarded from Trashmail\nOriginal sender: {from_header or mail_from}\n"
                         f"Received for: {rcpt}\nSubject: {ctx.subject}\n"))
            rules.log_hit(rule, "forward", message_id=mid, ctx=ctx, detail=f"forwarded to {act['arg']}")
        except forwarder.ForwardError as exc:
            log.warning("rule %s forward failed: %s", rule["id"], exc)
            rules.log_hit(rule, "forward", message_id=mid, ctx=ctx, detail=str(exc), ok=False)
    return mid


def _tls_context() -> ssl.SSLContext | None:
    boot = config.boot()
    if boot.tls_cert and boot.tls_key:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(boot.tls_cert, boot.tls_key)
        return ctx
    return None


def start(host: str | None = None, port: int | None = None) -> Controller:
    boot = config.boot()
    tls = _tls_context()
    command_limit = config.get_int("COMMAND_LIMIT")
    controller = LimitedController(
        Handler(),
        hostname=host or boot.smtp_host,
        port=port if port is not None else boot.smtp_port,
        tls_context=tls,
        require_starttls=False,
        data_size_limit=config.get_int("MAX_MESSAGE_SIZE") + 4096,
        command_call_limit=command_limit if command_limit > 0 else None,
        ident="Trashmail ESMTP",
    )
    controller.tracker = ConnectionTracker()  # fresh counters per server instance
    controller.start()
    log.info("SMTP listening on %s:%s (STARTTLS %s)", controller.hostname, controller.port,
             "on" if tls else "off")
    return controller
