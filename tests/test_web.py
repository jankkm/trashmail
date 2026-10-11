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
    from app import rules
    token = login(client)
    # two conditions + two actions in one rule, via the editor's repeated form fields
    r = client.post("/rules", data={
        "csrf": token, "name": "Invoices", "scope": "bob@example.test", "match_mode": "any", "priority": "10",
        "cond_field": ["subject", "sender"], "cond_header": ["", ""], "cond_op": ["contains", "endswith"],
        "cond_value": ["invoice", "@shop.test"], "act_type": ["flag", "mark_read"], "act_arg": ["", ""]})
    assert "ok=" in r.headers["location"]
    rule = rules.list_rules()[0]
    assert rule["name"] == "Invoices" and rule["match_mode"] == "any"
    assert [c["value"] for c in rule["conditions"]] == ["invoice", "@shop.test"]
    assert [a["action"] for a in rule["actions"]] == ["flag", "mark_read"]
    page = client.get("/rules").text
    assert "Invoices" in page and "invoice" in page and "bob@example.test" in page
    assert 'data-rule-edit=' in page

    # editing replaces conditions and actions
    r = client.post(f"/rules/{rule['id']}/update", data={
        "csrf": token, "name": "Only flag", "scope": "", "match_mode": "all", "priority": "50",
        "cond_field": ["subject"], "cond_header": [""], "cond_op": ["not_contains"], "cond_value": ["spam"],
        "act_type": ["delete"], "act_arg": [""]})
    assert "ok=" in r.headers["location"]
    edited = rules.get_rule(rule["id"])
    assert edited["scope"] is None and edited["conditions"][0]["op"] == "not_contains"
    assert [a["action"] for a in edited["actions"]] == ["delete"]

    # no action / invalid regex are rejected with a message
    for bad in ({"act_type": []}, {"cond_field": ["subject"], "cond_op": ["regex"], "cond_value": ["(["],
                                   "act_type": ["flag"]}):
        r = client.post("/rules", data={"csrf": token, **bad})
        assert "err=" in r.headers["location"]
    assert len(rules.list_rules()) == 1

    client.post("/blacklist", data={"csrf": token, "kind": "sender_domain", "value": "spam.test"})
    assert "spam.test" in client.get("/blacklist").text


def test_favorites_pages(client):
    from app import favorites, rules
    token = login(client)
    r = client.post("/favorites", data={"csrf": token, "name": "Shopping",
                                        "addresses": "shop@example.test\norders@example.test", "notes": "My stuff"})
    assert r.status_code == 303 and "ok=" in r.headers["location"]
    fid = favorites.list_favorites()[0]["id"]
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="shop@example.test")
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="elsewhere@example.test")
    rules.create_rule(name="Scoped rule", conditions=[], actions=[{"action": "flag"}], scope="orders@example.test")
    rules.create_rule(name="Global rule", conditions=[], actions=[{"action": "mark_read"}])
    rules.create_rule(name="Foreign rule", conditions=[], actions=[{"action": "flag"}], scope="elsewhere@example.test")

    listing = client.get("/favorites").text
    assert "Shopping" in listing and "My stuff" in listing and "shop@example.test" in listing
    page = client.get(f"/favorites/{fid}").text
    assert "Hello Wolrd invoice" in page                       # the favorite's email
    assert "Scoped rule" in page and "Global rule" in page     # its rule + global rules
    assert "Foreign rule" not in page                          # other recipients' rules are not shown
    assert "elsewhere@example.test" not in page                # nor their mail
    assert "shop@example.test" in page
    empty = client.get(f"/favorites/{fid}?q=zzzzzz").text
    assert "No emails found" in empty and "Hello Wolrd invoice" not in empty

    # inbox can filter by favorite
    filtered = client.get(f"/?fav={fid}").text
    assert "shop@example.test" in filtered and "elsewhere@example.test</span>" not in filtered

    # validation + edit + delete
    r = client.post("/favorites", data={"csrf": token, "name": "Bad", "addresses": "nope"})
    assert "err=" in r.headers["location"]
    r = client.post(f"/favorites/{fid}/update", data={"csrf": token, "name": "Shops", "addresses": "shop@example.test"})
    assert "ok=" in r.headers["location"] and favorites.get_favorite(fid)["name"] == "Shops"
    assert client.post(f"/favorites/{fid}/delete").status_code == 403           # CSRF required
    client.post(f"/favorites/{fid}/delete", data={"csrf": token})
    assert favorites.get_favorite(fid) is None
    assert client.get(f"/favorites/{fid}").status_code == 404


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
    # a rule created from the message page returns to it; open redirects are ignored
    r = client.post("/rules", data={"csrf": token, "scope": "bob@example.test", "cond_field": "sender",
                                    "cond_op": "contains", "cond_value": "alice@sender.test",
                                    "act_type": "flag", "act_arg": "", "next": f"/messages/{mid}"})
    assert r.headers["location"].startswith(f"/messages/{mid}?ok=")
    r = client.post("/rules", data={"csrf": token, "cond_field": "subject", "cond_op": "contains",
                                    "cond_value": "x", "act_type": "flag", "next": "//evil.test"})
    assert r.headers["location"].startswith("/rules?ok=")
    first = rules.list_rules()[0]
    assert first["scope"] == "bob@example.test" and first["conditions"][0]["value"] == "alice@sender.test"


def test_two_factor_login_flow(client):
    import re
    from app import config, totp
    token = login(client)
    client.post("/account/2fa/start", data={"csrf": token})
    me = auth.authenticate("admin", "adminpass1")
    secret = auth.get_user(me["id"])["totp_secret"]
    assert secret and "Verify and enable" in client.get("/account/2fa").text
    # wrong code keeps it off, right code enables and shows recovery codes once
    r = client.post("/account/2fa/enable", data={"csrf": token, "code": "000000"})
    assert r.status_code == 303 and "err=" in r.headers["location"]
    r = client.post("/account/2fa/enable", data={"csrf": token, "code": totp.code_at(secret, totp.current_step())})
    assert r.status_code == 200
    recovery = re.findall(r"\b[a-z2-9]{5}-[a-z2-9]{5}\b", r.text)
    assert len(recovery) == 8
    assert secret not in client.get("/account/2fa").text            # secret is no longer displayed

    # password alone no longer gives a session
    client.cookies.clear()
    r = client.post("/login", data={"username": "admin", "password": "adminpass1"})
    assert r.headers["location"] == "/login/2fa"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    r = client.post("/login/2fa", data={"code": "123456"})
    assert r.status_code == 401
    code = totp.code_at(secret, totp.current_step() + 1)
    r = client.post("/login/2fa", data={"code": code})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/").status_code == 200

    # the same TOTP code cannot be replayed; a recovery code works once
    client.cookies.clear()
    client.post("/login", data={"username": "admin", "password": "adminpass1"})
    assert client.post("/login/2fa", data={"code": code}).status_code == 401
    assert client.post("/login/2fa", data={"code": recovery[0]}).status_code == 303
    client.cookies.clear()
    client.post("/login", data={"username": "admin", "password": "adminpass1"})
    assert client.post("/login/2fa", data={"code": recovery[0]}).status_code == 401


def test_two_factor_pending_cookie_required_and_lockout(client):
    from app import totp
    from app.web import routes_auth
    routes_auth._failures.clear(); routes_auth._2fa_failures.clear()
    uid = auth.create_user("dave", "password123")
    secret = auth.totp_start_setup(uid)
    auth.totp_confirm(uid, totp.code_at(secret, totp.current_step()))
    assert client.get("/login/2fa").headers["location"] == "/login"              # no pending cookie
    assert client.post("/login/2fa", data={"code": "123456"}).headers["location"] == "/login"
    client.post("/login", data={"username": "dave", "password": "password123"})
    for _ in range(5):
        assert client.post("/login/2fa", data={"code": "000000"}).status_code == 401
    assert client.post("/login/2fa", data={"code": totp.code_at(secret, totp.current_step() + 1)}).status_code == 429


def test_admin_can_reset_two_factor(client):
    from app import totp
    token = login(client)
    uid = auth.create_user("erin", "password123")
    secret = auth.totp_start_setup(uid)
    auth.totp_confirm(uid, totp.code_at(secret, totp.current_step()))
    assert "2FA" in client.get("/users").text
    r = client.post(f"/users/{uid}/reset-2fa", data={"csrf": token})
    assert "ok=" in r.headers["location"]
    assert auth.get_user(uid)["totp_enabled"] == 0


def test_filter_forms_survive_empty_and_junk_numeric_params(client):
    """The inbox filter form submits fav= (and friends) empty when nothing is selected."""
    login(client)
    mailstore.store(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    url = "/?q=&rcpt=bob%40example.test&fav=&flagged=&unread=&page="
    r = client.get(url)
    assert r.status_code == 200 and "Hello Wolrd invoice" in r.text
    assert client.get("/?fav=abc&page=-3&unread=x").status_code == 200
    from app import favorites
    fid = favorites.create("Mine", "bob@example.test")
    assert client.get(f"/favorites/{fid}?q=&unread=&flagged=&page=").status_code == 200
    assert client.get(f"/?fav={fid}&rcpt=").status_code == 200


def test_tags_on_message_page_filter_and_bulk(client):
    token = login(client)
    a = mailstore.store(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    b = mailstore.store(SAMPLE.replace(b"invoice", b"offer"), mail_from="alice@sender.test", rcpt="carol@example.test")
    r = client.post(f"/messages/{a}/tags", data={"csrf": token, "tag": "Invoices, Work"})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    assert "err=" in client.post(f"/messages/{a}/tags", data={"csrf": token, "tag": " , "}).headers["location"]
    page = client.get(f"/messages/{a}").text
    assert "Invoices" in page and "Work" in page
    inbox = client.get("/?view=all").text
    assert 'href="/?tag=Invoices"' in inbox                              # chip on the list row
    only = client.get("/?view=all&tag=invoices").text
    assert "<b>Hello Wolrd offer</b>" not in only and "<b>Hello Wolrd invoice</b>" in only
    # bulk tagging
    client.post("/messages/bulk", data={"csrf": token, "action": "tag", "tag": "Later", "ids": [a, b]})
    assert mailstore.tags_for([a, b]) == {a: ["Invoices", "Later", "Work"], b: ["Later"]}
    assert "err=" in client.post("/messages/bulk", data={"csrf": token, "action": "tag", "tag": "", "ids": [a]}).headers["location"]
    # removing a tag
    client.post(f"/messages/{a}/tags/remove", data={"csrf": token, "tag": "work"})
    assert mailstore.tags_for([a])[a] == ["Invoices", "Later"]
    assert client.post(f"/messages/{a}/tags", data={"tag": "x"}).status_code == 403   # CSRF


def test_default_inbox_view(client):
    token = login(client)
    unread = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    read = mailstore.store(SAMPLE.replace(b"invoice", b"report"), mail_from="a@b.test", rcpt="bob@example.test", read=True)
    flagged = mailstore.store(SAMPLE.replace(b"invoice", b"urgent"), mail_from="a@b.test", rcpt="bob@example.test",
                              flagged=True, read=True)

    def subjects(url):
        text = client.get(url).text
        return {w for w in ("invoice", "report", "urgent") if f"<b>Hello Wolrd {w}</b>" in text}

    assert subjects("/") == {"invoice", "report", "urgent"}              # default: all
    # pin "Unread" as the default from the inbox
    r = client.post("/account/default-view", data={"csrf": token, "view": "unread", "next": "/?view=unread"})
    assert r.status_code == 303 and "ok=" in r.headers["location"]
    assert subjects("/") == {"invoice"}                                  # plain "/" now starts on unread
    assert subjects("/?view=all") == {"invoice", "report", "urgent"}     # explicit choice still wins
    assert subjects("/?view=flagged") == {"urgent"}
    assert subjects("/?unread=1") == {"invoice"}                         # legacy links keep working
    assert "all caught up" in (mailstore.set_read([unread], True) or client.get("/").text)
    # the account page sets it too; junk values are ignored
    client.post("/account", data={"csrf": token, "name": "Admin", "default_view": "flagged"})
    assert subjects("/") == {"urgent"}
    client.post("/account", data={"csrf": token, "name": "Admin", "default_view": "bogus"})
    assert subjects("/") == {"urgent"}
    assert "err=" in client.post("/account/default-view", data={"csrf": token, "view": "x"}).headers["location"]
    # open redirect target is rejected
    r = client.post("/account/default-view", data={"csrf": token, "view": "all", "next": "//evil.test"})
    assert r.headers["location"].startswith("/?")


def test_star_toggles_flag_from_the_list(client):
    token = login(client)
    mid = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    page = client.get("/?view=all").text
    assert f'formaction="/messages/{mid}/star"' in page and 'aria-pressed="false"' in page
    r = client.post(f"/messages/{mid}/star", data={"csrf": token, "next": "/?view=all"})
    assert r.status_code == 303 and r.headers["location"] == "/?view=all"
    assert mailstore.get(mid)["flagged"] == 1 and 'aria-pressed="true"' in client.get("/?view=all").text
    # in-place variant used by the script: no redirect, no body
    r = client.post(f"/messages/{mid}/star", data={"csrf": token}, headers={"X-Requested-With": "fetch"})
    assert r.status_code == 204 and mailstore.get(mid)["flagged"] == 0
    # CSRF and redirect target are enforced
    assert client.post(f"/messages/{mid}/star", data={"next": "/"}).status_code == 403
    r = client.post(f"/messages/{mid}/star", data={"csrf": token, "next": "//evil.test"})
    assert r.headers["location"] == "/"                          # off-site target replaced by the inbox
    assert client.post("/messages/99999/star", data={"csrf": token}).status_code == 404
