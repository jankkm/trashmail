import json

from app import auth, db, totp

# RFC 6238 appendix B secret ("12345678901234567890"), SHA-1
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc6238_vectors():
    # the RFC lists 8-digit codes; our 6-digit codes are their last six digits
    assert totp.code_at(RFC_SECRET, 59 // 30) == "287082"
    assert totp.code_at(RFC_SECRET, 1111111109 // 30) == "081804"
    assert totp.code_at(RFC_SECRET, 2000000000 // 30) == "279037"


def test_verify_window_and_replay():
    now = 1_700_000_000
    step = now // 30
    good = totp.code_at(RFC_SECRET, step)
    assert totp.verify(RFC_SECRET, good, now=now) == step
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), now=now) == step - 1   # drift
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 5), now=now) is None       # too far
    assert totp.verify(RFC_SECRET, good, last_step=step, now=now) is None                     # replay
    assert totp.verify(RFC_SECRET, "12345", now=now) is None
    assert totp.verify(RFC_SECRET, " ".join([good[:3], good[3:]]), now=now) == step           # "123 456"


def test_provisioning_uri_and_qr():
    uri = totp.provisioning_uri("ABC234", "alice")
    assert uri.startswith("otpauth://totp/Trashmail%3Aalice?secret=ABC234&issuer=Trashmail")
    assert totp.qr_svg(uri).lstrip().startswith("<svg")


def test_enable_confirm_recovery_and_disable():
    uid = auth.create_user("carol", "password123")
    secret = auth.totp_start_setup(uid)
    assert auth.totp_confirm(uid, "000000") is None          # wrong code does not enable
    codes = auth.totp_confirm(uid, totp.code_at(secret, totp.current_step()))
    assert codes and len(codes) == 8
    user = auth.get_user(uid)
    assert user["totp_enabled"] == 1
    assert codes[0] not in user["totp_recovery"]             # only hashes are stored
    assert len(json.loads(user["totp_recovery"])) == 8

    # a recovery code works exactly once
    assert auth.check_second_factor(user, codes[0]) is True
    assert auth.check_second_factor(auth.get_user(uid), codes[0]) is False
    assert auth.recovery_codes_left(auth.get_user(uid)) == 7

    auth.totp_disable(uid)
    assert auth.get_user(uid)["totp_enabled"] == 0 and auth.get_user(uid)["totp_secret"] is None


def test_migration_adds_columns_to_old_database(tmp_path, monkeypatch):
    import sqlite3
    from app import config
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "old"))
    config.reload()
    (config.boot().data_dir).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.boot().data_dir / "trashmail.db")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
                 " password_hash TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', is_admin INTEGER NOT NULL DEFAULT 0,"
                 " created_at INTEGER NOT NULL)")
    conn.execute("INSERT INTO users(username,password_hash,created_at) VALUES('old','x',0)")
    conn.commit(); conn.close()
    db.init()
    db.init()  # idempotent
    row = db.one("SELECT * FROM users WHERE username='old'")
    assert row["totp_enabled"] == 0 and row["totp_recovery"] == "[]"
    assert row["default_view"] == "all"
