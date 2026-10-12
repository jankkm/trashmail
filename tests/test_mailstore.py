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


def _store(**kw):
    return mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test", **kw)


def test_trash_hides_message_but_keeps_file_and_counts_storage():
    mid = _store(tags=["work"])
    path = config.boot().data_dir / mailstore.get(mid)["path"]
    assert mailstore.trash([mid]) == 1 and mailstore.trash([mid]) == 0   # idempotent
    assert path.exists() and mailstore.get(mid) is not None
    assert mailstore.list_messages()[1] == 0 and mailstore.list_messages(q="invoice")[1] == 0
    assert mailstore.list_messages(trashed=True)[1] == 1 and mailstore.list_messages(q="invoice", trashed=True)[1] == 1
    assert mailstore.stats() == {"total": 0, "unread": 0, "flagged": 0, "today": 0}
    assert not mailstore.recipients() and not mailstore.all_tags()
    assert mailstore.storage_used(0) > 0                                  # still on disk, still counted
    assert mailstore.restore([mid]) == 1
    assert mailstore.list_messages()[1] == 1 and mailstore.all_tags()[0]["tag"] == "work"


def test_purge_trash_uses_deletion_time_and_setting():
    old, fresh, live = _store(), _store(), _store()
    mailstore.trash([old, fresh])
    db.execute("UPDATE messages SET deleted_ts=? WHERE id=?", (int(time.time()) - 40 * 86400, old))
    config.set_value("TRASH_DAYS", "0")
    assert mailstore.purge_trash() == 0                                   # 0 = keep until emptied by hand
    config.set_value("TRASH_DAYS", "30")
    assert mailstore.trash_expiry(mailstore.get(fresh)) > time.time() and mailstore.trash_expiry(mailstore.get(live)) is None
    assert mailstore.purge_trash() == 1
    assert mailstore.get(old) is None and mailstore.get(fresh) is not None and mailstore.get(live) is not None


def test_retention_does_not_purge_trashed_mail_early():
    mid = _store(flagged=False)
    db.execute("UPDATE messages SET received_ts=?", (int(time.time()) - 40 * 86400,))
    mailstore.trash([mid])                                                # old mail, deleted just now
    config.set_value("RETENTION_DAYS", "30")
    assert mailstore.purge_expired() == 0 and mailstore.get(mid) is not None


def test_empty_trash_leaves_live_mail():
    live, dead = _store(), _store()
    mailstore.trash([dead])
    assert mailstore.empty_trash() == 1
    assert mailstore.get(dead) is None and mailstore.get(live) is not None


def test_migration_adds_deleted_ts_to_old_messages_table(tmp_path, monkeypatch):
    import sqlite3
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "old"))
    config.reload()
    config.boot().data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.boot().data_dir / "trashmail.db")
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, path TEXT NOT NULL,"
                 " received_ts INTEGER NOT NULL, rcpt_to TEXT NOT NULL)")
    conn.execute("INSERT INTO messages(uid, path, received_ts, rcpt_to) VALUES('u','p',1,'a@b.test')")
    conn.commit(); conn.close()
    db.init()
    assert db.one("SELECT deleted_ts FROM messages")["deleted_ts"] is None     # existing mail stays live
    assert db.one("SELECT COUNT(*) AS c FROM messages WHERE deleted_ts IS NULL")["c"] == 1
