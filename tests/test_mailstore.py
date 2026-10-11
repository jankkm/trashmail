import time

from app import config, db, mailstore
from .conftest import SAMPLE

HTML_MAIL = (
    b"From: News <news@shop.test>\r\nTo: bob@example.test\r\nSubject: Sale\r\n"
    b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    b'<p onclick="x()">Hi <script>alert(1)</script><img src="https://tracker.test/p.gif"></p>'
)


def test_store_creates_eml_and_index():
    mid = mailstore.store(SAMPLE, mail_from="alice@sender.test", rcpt="Bob@Example.test")
    row = mailstore.get(mid)
    assert row["rcpt_to"] == "bob@example.test"
    path = config.boot().data_dir / row["path"]
    assert path.suffix == ".eml" and path.exists()
    assert b"Subject: Hello Wolrd invoice" in path.read_bytes()
    rows, total = mailstore.list_messages(q="quarterly invoice")
    assert total == 1 and rows[0]["id"] == mid
    assert mailstore.list_messages(q="nonexistent")[1] == 0
    assert mailstore.list_messages(q="alice@sender.test")[1] == 1
    assert mailstore.list_messages(rcpt="bob@example.test")[1] == 1
    assert mailstore.list_messages(rcpt="nobody@example.test")[1] == 0


def test_search_survives_garbage_query():
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    assert mailstore.list_messages(q='"" OR (*')[1] in (0, 1)  # must not raise


def test_flag_read_delete_removes_file():
    mid = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    path = config.boot().data_dir / mailstore.get(mid)["path"]
    mailstore.set_flag([mid], True)
    mailstore.set_read([mid], True)
    assert mailstore.list_messages(flagged=True)[1] == 1
    assert mailstore.list_messages(unread=True)[1] == 0
    mailstore.delete([mid])
    assert not path.exists() and mailstore.get(mid) is None
    assert mailstore.list_messages(q="invoice")[1] == 0


def test_html_is_sanitised_and_remote_detected():
    mid = mailstore.store(HTML_MAIL, mail_from="n@shop.test", rcpt="bob@example.test")
    view = mailstore.build_view(mailstore.read_raw(mailstore.get(mid)))
    assert "<script" not in view.html and "onclick" not in view.html
    assert view.has_remote
    assert "default-src 'none'" in mailstore.csp(False) and "img-src data:;" in mailstore.csp(False)
    assert "img-src * data:" in mailstore.csp(True)


def test_retention_keeps_flagged():
    old = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    keep = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test", flagged=True)
    db.execute("UPDATE messages SET received_ts=? ", (int(time.time()) - 40 * 86400,))
    config.set_value("RETENTION_DAYS", "30")
    assert mailstore.purge_expired() == 1
    assert mailstore.get(old) is None and mailstore.get(keep) is not None
