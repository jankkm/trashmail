import pytest

from app import config, db


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    for key in list(__import__("os").environ):
        if key.endswith("_FILE") or key in config.SETTINGS or key.startswith(("ADMIN_", "SMTP_", "WEB_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "adminpass1")
    config.reload()
    db.init()
    yield
    config.reload()


SAMPLE = (
    b"From: Alice <alice@sender.test>\r\nTo: bob@example.test\r\nSubject: Hello Wolrd invoice\r\n"
    b"Message-ID: <1@sender.test>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Please find the quarterly invoice attached.\r\n"
)
