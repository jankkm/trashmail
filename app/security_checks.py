"""SPF / DKIM / DMARC evaluation. Results are informational badges, except that
SPF 'fail' can optionally reject (see SPF_REJECT setting)."""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from email.utils import parseaddr

log = logging.getLogger(__name__)


@dataclass
class AuthResult:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


def _aligned(a: str, b: str) -> bool:
    a, b = a.lower().strip("."), b.lower().strip(".")
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def _from_domain(raw: bytes) -> str:
    import email
    import email.policy
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        return parseaddr(str(msg.get("from", "")))[1].rpartition("@")[2].lower()
    except Exception:
        return ""


def check(raw: bytes, ip: str, mail_from: str, helo: str) -> AuthResult:
    """Blocking (DNS lookups); call via asyncio.to_thread."""
    result = AuthResult()
    try:
        addr = ipaddress.ip_address(ip)
        public = not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        public = False

    if public:
        try:
            import spf
            result.spf = spf.check2(i=ip, s=mail_from or f"postmaster@{helo}", h=helo or "unknown")[0]
        except Exception as exc:  # DNS problems etc.
            log.debug("spf check failed: %s", exc)
            result.spf = "temperror"

    dkim_domain = ""
    sig = re.search(rb"(?im)^DKIM-Signature:.*?\bd=([^;\s]+)", raw[:65536], re.S)
    if sig:
        dkim_domain = sig.group(1).decode("ascii", "ignore")
        try:
            import dkim
            result.dkim = "pass" if dkim.verify(raw) else "fail"
        except Exception as exc:
            log.debug("dkim check failed: %s", exc)
            result.dkim = "temperror"

    from_domain = _from_domain(raw)
    if from_domain and public:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"_dmarc.{from_domain}", "TXT", lifetime=3)
            has_policy = any(b"v=DMARC1" in b"".join(r.strings) for r in answers)
        except Exception:
            has_policy = False
        if has_policy:
            spf_ok = result.spf == "pass" and _aligned(mail_from.rpartition("@")[2], from_domain)
            dkim_ok = result.dkim == "pass" and _aligned(dkim_domain, from_domain)
            result.dmarc = "pass" if (spf_ok or dkim_ok) else "fail"
    return result
