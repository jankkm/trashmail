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
    db.execute("INSERT INTO rules(scope,field,op,value,action,created_at) VALUES(NULL,'subject','contains','invoice','flag',0)")
    db.execute("INSERT INTO rules(scope,field,op,value,action,created_at) VALUES('bob@example.test','sender','contains','junk.test','delete',0)")
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
