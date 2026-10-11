import re

import pytest
from fastapi.testclient import TestClient

from app import auth, mailstore
from app.web.app import create_app
from .conftest import SAMPLE


@pytest.fixture
def client():
    with TestClient(create_app(start_smtp=False), follow_redirects=False) as c:
        yield c


def login(client, user="admin", password="adminpass1"):
    r = client.post("/login", data={"username": user, "password": password})
    assert r.status_code == 303
    return csrf(client)


def csrf(client):
    token = auth.read_session(client.cookies.get(auth.COOKIE))["csrf"]
    return token


def test_requires_login(client):
    assert client.get("/").headers["location"] == "/login"
    assert client.post("/login", data={"username": "admin", "password": "bad"}).status_code == 401


def test_inbox_message_flow(client):
    token = login(client)
    mid = mailstore.store(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    r = client.get("/")
    assert r.status_code == 200 and "Hello Wolrd invoice" in r.text
    assert "Hello Wolrd" in client.get("/?q=quarterly").text
    assert "No messages" in client.get("/?q=zzzzz").text
    r = client.get(f"/messages/{mid}")
    assert r.status_code == 200 and "bob@example.test" in r.text
    body = client.get(f"/messages/{mid}/body")
    assert "default-src 'none'" in body.headers["content-security-policy"]
    dl = client.get(f"/messages/{mid}/download")
    assert dl.headers["content-type"] == "message/rfc822" and dl.content.endswith(SAMPLE)
    # CSRF required
    assert client.post(f"/messages/{mid}/action", data={"action": "flag"}).status_code == 403
    r = client.post(f"/messages/{mid}/action", data={"action": "flag", "csrf": token})
    assert r.status_code == 303 and mailstore.get(mid)["flagged"] == 1
    r = client.post("/messages/bulk", data={"action": "delete", "ids": [mid], "csrf": token})
    assert mailstore.get(mid) is None


def test_forward_without_smtp_shows_error(client):
    token = login(client)
    mid = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    r = client.post(f"/messages/{mid}/forward", data={"to": "me@x.test", "csrf": token})
    assert r.status_code == 303 and "err=" in r.headers["location"]


def test_user_management_and_permissions(client):
    token = login(client)
    r = client.post("/users", data={"username": "eve", "password": "longpassword", "name": "Eve", "csrf": token})
    assert r.status_code == 303 and "ok=" in r.headers["location"]
    assert "eve" in client.get("/users").text
    # cannot delete self / last admin
    me = auth.authenticate("admin", "adminpass1")
    r = client.post(f"/users/{me['id']}/delete", data={"csrf": token})
    assert "err=" in r.headers["location"]
    # non-admin is locked out of admin pages
    client.cookies.clear()
    login(client, "eve", "longpassword")
    assert client.get("/users").status_code == 403
    assert client.get("/settings").status_code == 403
    assert client.get("/").status_code == 200


def test_settings_roundtrip_and_secret_not_rendered(client):
    token = login(client)
    r = client.post("/settings", data={
        "csrf": token, "FORWARD_SMTP_HOST": "smtp.test", "FORWARD_SMTP_PASSWORD": "s3cret",
        "RETENTION_DAYS": "7", "SPF_REJECT": "true"})
    assert r.status_code == 303
    page = client.get("/settings").text
    assert "smtp.test" in page and "s3cret" not in page
    from app import config
    assert config.get("FORWARD_SMTP_PASSWORD") == "s3cret" and config.get_int("RETENTION_DAYS") == 7
    # blank secret keeps value
    client.post("/settings", data={"csrf": token, "FORWARD_SMTP_PASSWORD": ""})
    assert config.get("FORWARD_SMTP_PASSWORD") == "s3cret"


def test_rules_and_blacklist_pages(client):
    token = login(client)
    r = client.post("/rules", data={"csrf": token, "scope": "bob@example.test", "field": "subject",
                                    "op": "contains", "value": "invoice", "action": "flag"})
    assert "ok=" in r.headers["location"]
    r = client.post("/rules", data={"csrf": token, "field": "subject", "op": "regex", "value": "([",
                                    "action": "flag"})
    assert "err=" in r.headers["location"]
    assert "invoice" in client.get("/rules").text
    client.post("/blacklist", data={"csrf": token, "kind": "sender_domain", "value": "spam.test"})
    assert "spam.test" in client.get("/blacklist").text


def test_block_from_message_and_rule_with_next(client):
    from app import db, rules
    token = login(client)
    mid = mailstore.store(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    for kind in ("sender_address", "sender_domain", "rcpt_address", "rcpt_domain"):
        r = client.post(f"/messages/{mid}/blacklist", data={"csrf": token, "kind": kind})
        assert "ok=" in r.headers["location"], kind
    kinds = {(r["kind"], r["value"]) for r in db.query("SELECT kind, value FROM blacklist")}
    assert kinds == {("sender_address", "alice@sender.test"), ("sender_domain", "sender.test"),
                     ("rcpt_address", "bob@example.test"), ("rcpt_domain", "example.test")}
    # rule created from the message page returns to it; open redirects are ignored
    r = client.post("/rules", data={"csrf": token, "scope": "bob@example.test", "field": "sender", "op": "contains",
                                    "value": "alice@sender.test", "action": "flag", "next": f"/messages/{mid}"})
    assert r.headers["location"].startswith(f"/messages/{mid}?ok=")
    r = client.post("/rules", data={"csrf": token, "field": "subject", "op": "contains", "value": "x",
                                    "action": "flag", "next": "//evil.test"})
    assert r.headers["location"].startswith("/rules?ok=")
    assert db.one("SELECT scope FROM rules WHERE value='alice@sender.test'")["scope"] == "bob@example.test"
