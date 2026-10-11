import pytest

from app import config, db, mailstore, rules
from .conftest import SAMPLE


def ctx(recipient="bob@example.test"):
    msg = mailstore.parse(SAMPLE)
    text, _ = mailstore.bodies(msg)
    return rules.Context(sender="Alice <alice@sender.test> alice@sender.test", recipient=recipient,
                         subject=str(msg["subject"]), body=text, msg=msg)


def add(scope, field, op, value, action="flag", arg="", prio=100):
    db.execute("INSERT INTO rules(scope,field,op,value,action,action_arg,priority,created_at)"
               " VALUES(?,?,?,?,?,?,?,0)", (scope, field, op, value, action, arg, prio))


def test_global_and_scoped_rules():
    add(None, "subject", "contains", "invoice")
    add("other@example.test", "subject", "contains", "invoice")
    add("bob@example.test", "sender", "endswith", "sender.test>", action="delete")
    matched = rules.matching_rules(ctx())
    assert [r["action"] for r in matched] == ["flag"]  # endswith fails because sender has trailing address
    add("bob@example.test", "sender", "contains", "@sender.test", action="delete")
    assert {r["action"] for r in rules.matching_rules(ctx())} == {"flag", "delete"}


def test_regex_header_and_body():
    add(None, "body", "regex", r"quarterly\s+invoice")
    add(None, "header:Message-ID", "contains", "1@sender.test", action="forward", arg="x@y.test")
    assert len(rules.matching_rules(ctx())) == 2


def test_disabled_and_invalid_regex_do_not_match():
    add(None, "subject", "regex", "([")
    db.execute("INSERT INTO rules(scope,field,op,value,action,created_at,enabled) VALUES(NULL,'subject','contains','invoice','flag',0,0)")
    assert rules.matching_rules(ctx()) == []


def test_validation():
    with pytest.raises(rules.RuleError):
        rules.validate_rule("subject", "", "regex", "([", "flag", "")
    with pytest.raises(rules.RuleError):
        rules.validate_rule("subject", "", "contains", "x", "forward", "not-an-address")
    assert rules.validate_rule("header", "List-Id", "contains", "x", "flag", "") == "header:List-Id"


def test_blacklist_matching_includes_subdomains():
    rules.add_blacklist("sender_domain", "@Spam.example")
    rules.add_blacklist("rcpt_address", "dead@example.test")
    assert rules.blacklisted("x@spam.example", sender=True)
    assert rules.blacklisted("x@news.spam.example", sender=True)
    assert not rules.blacklisted("x@notspam.example", sender=True)
    assert rules.blacklisted("DEAD@example.test", sender=False)
    assert not rules.blacklisted("x@spam.example", sender=False)
    assert rules.blacklisted("", sender=True) is None


def test_domain_allowed(monkeypatch):
    assert rules.domain_allowed("anything.test")  # empty list = accept all
    config.set_value("LOCAL_DOMAINS", "example.test, *.lists.test")
    assert rules.domain_allowed("example.test")
    assert rules.domain_allowed("a.lists.test")
    assert not rules.domain_allowed("lists.test")
    assert not rules.domain_allowed("other.test")
