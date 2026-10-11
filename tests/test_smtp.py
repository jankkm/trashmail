import smtplib
import socket

import pytest

from app import config, db, mailstore, rules, smtp_server
from .conftest import SAMPLE


@pytest.fixture
def server():
    config.set_value("LOCAL_DOMAINS", "example.test")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
    controller = smtp_server.start("127.0.0.1", free_port)
    yield controller
    controller.stop()


def send(server, mail_from, rcpt, data=SAMPLE):
    with smtplib.SMTP("127.0.0.1", server.port) as s:
        return s.sendmail(mail_from, [rcpt], data)


def test_accepts_and_stores(server):
    send(server, "alice@sender.test", "bob@example.test")
    rows, total = mailstore.list_messages()
    assert total == 1 and rows[0]["rcpt_to"] == "bob@example.test"
    assert b"X-Trashmail-Auth" in mailstore.read_raw(rows[0])


def test_unknown_domain_rejected_at_rcpt(server):
    with pytest.raises(smtplib.SMTPRecipientsRefused) as exc:
        send(server, "alice@sender.test", "bob@elsewhere.test")
    assert list(exc.value.recipients.values())[0][0] == 550


def test_blacklists_reject(server):
    rules.add_blacklist("sender_domain", "sender.test")
    with pytest.raises(smtplib.SMTPSenderRefused) as exc:
        send(server, "alice@sender.test", "bob@example.test")
    assert exc.value.smtp_code == 550
    rules.add_blacklist("rcpt_address", "dead@example.test")
    with pytest.raises(smtplib.SMTPRecipientsRefused):
        send(server, "someone@fine.test", "dead@example.test")
    assert mailstore.list_messages()[1] == 0


def test_rule_delete_and_flag(server):
    rules.create_rule(conditions=[{"field": "subject", "op": "contains", "value": "invoice"}],
                      actions=[{"action": "flag"}])
    rules.create_rule(conditions=[{"field": "sender", "op": "contains", "value": "junk.test"}],
                      actions=[{"action": "delete"}], scope="bob@example.test")
    send(server, "alice@sender.test", "bob@example.test")
    rows, _ = mailstore.list_messages()
    assert rows[0]["flagged"] == 1
    send(server, "x@junk.test", "bob@example.test", SAMPLE.replace(b"alice@sender.test", b"x@junk.test"))
    assert mailstore.list_messages()[1] == 1  # deleted one never stored
    assert db.one("SELECT COUNT(*) c FROM rule_hits WHERE action='delete'")["c"] == 1


def test_message_size_limit(server):
    config.set_value("MAX_MESSAGE_SIZE", "100")
    with pytest.raises(smtplib.SMTPDataError) as exc:
        send(server, "alice@sender.test", "bob@example.test")
    assert exc.value.smtp_code == 552


# --- abuse limits -------------------------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_recipient_limit(server):
    config.set_value("MAX_RECIPIENTS", "3")
    rcpts = [f"user{i}@example.test" for i in range(5)]
    with smtplib.SMTP("127.0.0.1", server.port) as s:
        refused = s.sendmail("alice@sender.test", rcpts, SAMPLE)
    assert sorted(refused) == rcpts[3:] and all(v[0] == 452 for v in refused.values())
    assert mailstore.list_messages()[1] == 3          # only accepted recipients were stored


def test_storage_cap_refuses_new_mail(server):
    config.set_value("MAX_STORAGE_MB", "1")
    big = SAMPLE + b"x" * 1_300_000 + b"\r\n"
    mailstore.store(big, mail_from="a@b.test", rcpt="bob@example.test")
    with pytest.raises(smtplib.SMTPSenderRefused) as exc:
        send(server, "alice@sender.test", "bob@example.test")
    assert exc.value.smtp_code == 452
    # freeing space (e.g. retention) makes the server accept mail again
    mailstore.delete([r["id"] for r in mailstore.list_messages()[0]])
    send(server, "alice@sender.test", "bob@example.test")
    assert mailstore.list_messages()[1] == 1


def test_storage_cap_considers_incoming_size_times_recipients(server):
    config.set_value("MAX_STORAGE_MB", "1")
    config.set_value("MAX_MESSAGE_SIZE", "5000000")
    payload = SAMPLE + (b"y" * 78 + b"\r\n") * 5_000     # ~395 KB; 3 copies would be ~1.2 MB
    with pytest.raises(smtplib.SMTPDataError) as exc:
        with smtplib.SMTP("127.0.0.1", server.port) as s:
            s.sendmail("a@sender.test", [f"u{i}@example.test" for i in range(3)], payload)
    assert exc.value.smtp_code == 452


def test_connection_limit_per_ip(server):
    config.set_value("MAX_CONNECTIONS_PER_IP", "2")
    a = smtplib.SMTP("127.0.0.1", server.port)
    b = smtplib.SMTP("127.0.0.1", server.port)
    with pytest.raises(smtplib.SMTPConnectError) as exc:
        smtplib.SMTP("127.0.0.1", server.port)
    assert exc.value.smtp_code == 421
    a.quit()                                           # releasing a slot makes room again
    import time; time.sleep(0.2)
    c = smtplib.SMTP("127.0.0.1", server.port)
    for conn in (b, c):
        conn.quit()


def test_global_connection_limit(server):
    config.set_value("MAX_CONNECTIONS", "1")
    config.set_value("MAX_CONNECTIONS_PER_IP", "0")
    a = smtplib.SMTP("127.0.0.1", server.port)
    with pytest.raises(smtplib.SMTPConnectError) as exc:
        smtplib.SMTP("127.0.0.1", server.port)
    assert exc.value.smtp_code == 421
    a.quit()


def test_command_limit_per_session():
    config.set_value("LOCAL_DOMAINS", "example.test")
    config.set_value("COMMAND_LIMIT", "3")
    controller = smtp_server.start("127.0.0.1", _free_port())
    try:
        s = smtplib.SMTP("127.0.0.1", controller.port)
        codes = []
        with pytest.raises(smtplib.SMTPServerDisconnected):   # server drops abusive sessions
            for _ in range(10):
                codes.append(s.noop()[0])
        assert codes[:3] == [250, 250, 250] and len(codes) < 10, codes
    finally:
        controller.stop()


async def test_forward_cap_per_hour():
    import time
    from app import rules
    config.set_value("FORWARD_LIMIT_PER_HOUR", "2")
    rid = rules.create_rule(conditions=[{"field": "subject", "op": "contains", "value": "invoice"}],
                            actions=[{"action": "forward", "arg": "me@x.test"}])
    for _ in range(2):
        db.execute("INSERT INTO rule_hits(at,rule_id,action,ok) VALUES(?,?,?,1)", (int(time.time()), rid, "forward"))
    assert rules.forwards_last_hour() == 2
    mid = await smtp_server.deliver(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    assert mid is not None                                  # mail is still stored
    hit = db.one("SELECT * FROM rule_hits ORDER BY id DESC LIMIT 1")
    assert hit["ok"] == 0 and "limit" in hit["detail"]


async def test_one_rule_runs_several_actions_in_one_delivery():
    rules.create_rule(
        conditions=[{"field": "subject", "op": "contains", "value": "invoice"},
                    {"field": "sender", "op": "contains", "value": "sender.test"}],
        actions=[{"action": "flag"}, {"action": "mark_read"}], name="Invoices")
    rules.create_rule(conditions=[], actions=[{"action": "flag"}], scope="someone-else@example.test")
    mid = await smtp_server.deliver(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    row = mailstore.get(mid)
    assert row["flagged"] == 1 and row["is_read"] == 1
    assert [h["action"] for h in db.query("SELECT action FROM rule_hits ORDER BY id")] == ["flag", "mark_read"]


async def test_redirect_rule_sends_message_unchanged(monkeypatch):
    from app import forwarder, rules
    sent = []

    async def fake_send_bytes(raw, *, sender, recipient):
        sent.append((raw, sender, recipient))
    monkeypatch.setattr(forwarder, "_send_bytes", fake_send_bytes)
    config.set_value("FORWARD_SMTP_HOST", "smtp.test")
    config.set_value("FORWARD_FROM", "trash@example.test")
    rules.create_rule(conditions=[{"field": "subject", "op": "contains", "value": "invoice"}],
                      actions=[{"action": "redirect", "arg": "me@x.test"}])
    await smtp_server.deliver(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    (raw, sender, recipient), = sent
    assert raw.endswith(SAMPLE)                              # original bytes untouched, only headers prepended
    assert raw.startswith(b"Resent-Date: ") and b"Resent-To: me@x.test" in raw.split(SAMPLE[:20])[0]
    assert (sender, recipient) == ("trash@example.test", "me@x.test")
    assert db.one("SELECT * FROM rule_hits ORDER BY id DESC LIMIT 1")["detail"] == "redirected to me@x.test"
    # redirected mail is marked: a second hop is never redirected again
    sent.clear()
    await smtp_server.deliver(raw, mail_from="alice@sender.test", rcpt="bob@example.test")
    assert sent == []
    assert "loop" in db.one("SELECT * FROM rule_hits ORDER BY id DESC LIMIT 1")["detail"]


async def test_redirect_counts_against_forward_cap():
    import time
    from app import rules
    rid = rules.create_rule(conditions=[], actions=[{"action": "redirect", "arg": "me@x.test"}])
    db.execute("INSERT INTO rule_hits(at,rule_id,action,ok) VALUES(?,?,?,1)", (int(time.time()), rid, "redirect"))
    assert rules.forwards_last_hour() == 1
