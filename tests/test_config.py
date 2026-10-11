from app import config


def test_file_beats_plain_env(tmp_path, monkeypatch):
    secret = tmp_path / "pw"
    secret.write_text("from-file\n")
    monkeypatch.setenv("FORWARD_SMTP_PASSWORD", "from-env")
    assert config.env("FORWARD_SMTP_PASSWORD") == "from-env"
    monkeypatch.setenv("FORWARD_SMTP_PASSWORD_FILE", str(secret))
    assert config.env("FORWARD_SMTP_PASSWORD") == "from-file"


def test_db_beats_env_after_seed(monkeypatch):
    monkeypatch.setenv("FORWARD_SMTP_HOST", "env.example")
    assert config.get("FORWARD_SMTP_HOST") == "env.example"
    assert config.source("FORWARD_SMTP_HOST") == "env-live"
    config.seed_from_env()
    assert config.source("FORWARD_SMTP_HOST") == "env"
    config.set_value("FORWARD_SMTP_HOST", "ui.example")
    monkeypatch.setenv("FORWARD_SMTP_HOST", "changed-env.example")
    config.seed_from_env()  # must not overwrite
    assert config.get("FORWARD_SMTP_HOST") == "ui.example"
    assert config.source("FORWARD_SMTP_HOST") == "ui"
    config.reset("FORWARD_SMTP_HOST")
    assert config.get("FORWARD_SMTP_HOST") == "changed-env.example"


def test_typed_getters(monkeypatch):
    monkeypatch.setenv("RETENTION_DAYS", "14")
    monkeypatch.setenv("SPF_REJECT", "yes")
    assert config.get_int("RETENTION_DAYS") == 14
    assert config.get_bool("SPF_REJECT") is True
    monkeypatch.setenv("RETENTION_DAYS", "nope")
    assert config.get_int("RETENTION_DAYS") == 0
