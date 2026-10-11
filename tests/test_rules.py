import pytest

from app import config, db, mailstore, rules
from .conftest import SAMPLE


def ctx(recipient="bob@example.test"):
    msg = mailstore.parse(SAMPLE)
    text, _ = mailstore.bodies(msg)
    return rules.Context(sender="Alice <alice@sender.test> alice@sender.test", recipient=recipient,
                         subject=str(msg["subject"]), body=text, msg=msg)


def cond(field, op, value, header=""):
    return {"field": field, "op": op, "value": value, "header": header}


def add(conditions, actions=("flag",), scope=None, **kw):
    acts = [{"action": a, "arg": "me@x.test" if a == "forward" else ""} for a in actions]
    return rules.create_rule(conditions=conditions, actions=acts, scope=scope, **kw)


def matched_ids(recipient="bob@example.test"):
    return [r["id"] for r in rules.matching_rules(ctx(recipient))]


def test_zero_conditions_matches_everything_in_scope():
    everyone = add([])
    only_bob = add([], scope="bob@example.test")
    other = add([], scope="other@example.test")
    assert set(matched_ids()) == {everyone, only_bob}
    assert other not in matched_ids()


def test_conditions_combine_with_all_or_any():
    both = [cond("subject", "contains", "invoice"), cond("sender", "contains", "nobody@")]
    r_all = add(both, match_mode="all")
    r_any = add(both, match_mode="any")
    assert matched_ids() == [r_any]                       # second condition is false
    add_third = add([cond("subject", "contains", "invoice"), cond("body", "regex", r"quarterly\s+invoice")])
    assert add_third in matched_ids() and r_all not in matched_ids()


def test_negative_operator_and_header_field():
    r1 = add([cond("subject", "not_contains", "newsletter")])
    r2 = add([cond("subject", "not_contains", "invoice")])
    r3 = add([cond("header", "contains", "1@sender.test", header="Message-ID")])
    assert r1 in matched_ids() and r2 not in matched_ids() and r3 in matched_ids()


def test_rule_with_several_actions_roundtrip_and_order():
    rid = add([cond("subject", "contains", "invoice")], actions=("flag", "mark_read", "forward"),
              name="Invoices", priority=10)
    rule = rules.get_rule(rid)
    assert [a["action"] for a in rule["actions"]] == ["flag", "mark_read", "forward"]
    assert rule["actions"][2]["arg"] == "me@x.test" and rule["name"] == "Invoices"
    rules.update_rule(rid, conditions=[], actions=[{"action": "delete", "arg": ""}], scope="bob@example.test",
                      name="Drop", match_mode="any", priority=5)
    rule = rules.get_rule(rid)
    assert rule["conditions"] == [] and [a["action"] for a in rule["actions"]] == ["delete"]
    assert rule["scope"] == "bob@example.test" and rule["priority"] == 5
    rules.delete_rule(rid)
    assert rules.get_rule(rid) is None
    assert db.one("SELECT COUNT(*) c FROM rule_actions")["c"] == 0      # children cascade


def test_disabled_rules_and_invalid_regex_do_not_match():
    rid = add([cond("subject", "contains", "invoice")])
    db.execute("UPDATE rules SET enabled=0 WHERE id=?", (rid,))
    assert rid not in matched_ids()
    # a regex that no longer compiles must not raise at match time
    db.execute("INSERT INTO rules(scope, created_at) VALUES(NULL, 0)")
    broken = db.one("SELECT MAX(id) m FROM rules")["m"]
    db.execute("INSERT INTO rule_conditions(rule_id, field, op, value) VALUES(?,?,?,?)", (broken, "subject", "regex", "(["))
    db.execute("INSERT INTO rule_actions(rule_id, action) VALUES(?, 'flag')", (broken,))
    assert broken not in matched_ids()


def test_validation():
    with pytest.raises(rules.RuleError):
        add([cond("subject", "regex", "([")])
    with pytest.raises(rules.RuleError):
        add([cond("subject", "contains", "")])               # half-filled condition
    with pytest.raises(rules.RuleError):
        add([], actions=())                                  # at least one action
    with pytest.raises(rules.RuleError):
        rules.create_rule(conditions=[], actions=[{"action": "forward", "arg": "nope"}])
    with pytest.raises(rules.RuleError):
        add([cond("header", "contains", "x", header="bad header")])
    # an untouched blank row is simply ignored
    rid = add([cond("sender", "contains", ""), cond("subject", "contains", "invoice")])
    assert len(rules.get_rule(rid)["conditions"]) == 1


def test_old_single_condition_rules_are_migrated(tmp_path, monkeypatch):
    import sqlite3
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "old"))
    config.reload()
    config.boot().data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.boot().data_dir / "trashmail.db")
    conn.executescript("""
        CREATE TABLE rules (id INTEGER PRIMARY KEY, scope TEXT, field TEXT NOT NULL, op TEXT NOT NULL,
            value TEXT NOT NULL, action TEXT NOT NULL, action_arg TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 100, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
        CREATE TABLE rule_hits (id INTEGER PRIMARY KEY, at INTEGER NOT NULL,
            rule_id INTEGER REFERENCES rules(id) ON DELETE SET NULL, message_id INTEGER,
            sender TEXT NOT NULL DEFAULT '', rcpt TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 1);
        INSERT INTO rules VALUES (7, 'bob@example.test', 'subject', 'contains', 'invoice', 'forward', 'me@x.test', 20, 1, 1);
        INSERT INTO rules VALUES (9, NULL, 'sender', 'endswith', 'shop.test', 'delete', '', 200, 0, 2);
        INSERT INTO rule_hits(at, rule_id, action) VALUES (5, 7, 'forward');
    """)
    conn.commit(); conn.close()

    db.init()
    db.init()                                                # idempotent
    migrated = {r["id"]: r for r in rules.list_rules()}
    assert set(migrated) == {7, 9}
    assert migrated[7]["conditions"][0]["value"] == "invoice" and migrated[7]["actions"][0]["arg"] == "me@x.test"
    assert migrated[7]["priority"] == 20 and migrated[7]["scope"] == "bob@example.test"
    assert migrated[9]["enabled"] == 0 and migrated[9]["actions"][0]["action"] == "delete"
    assert db.one("SELECT rule_id FROM rule_hits")["rule_id"] == 7        # history keeps its link
    new_id = add([cond("subject", "contains", "x")])                      # new schema is fully usable
    assert new_id > 9
    rules.delete_rule(7)
    assert db.one("SELECT rule_id FROM rule_hits")["rule_id"] is None     # FK still ON DELETE SET NULL


def test_blacklist_matching_includes_subdomains():
    rules.add_blacklist("sender_domain", "@Spam.example")
    rules.add_blacklist("rcpt_address", "dead@example.test")
    assert rules.blacklisted("x@spam.example", sender=True)
    assert rules.blacklisted("x@news.spam.example", sender=True)
    assert not rules.blacklisted("x@notspam.example", sender=True)
    assert rules.blacklisted("DEAD@example.test", sender=False)
    assert not rules.blacklisted("x@spam.example", sender=False)
    assert rules.blacklisted("", sender=True) is None


def test_domain_allowed():
    assert rules.domain_allowed("anything.test")  # empty list = accept all
    config.set_value("LOCAL_DOMAINS", "example.test, *.lists.test")
    assert rules.domain_allowed("example.test")
    assert rules.domain_allowed("a.lists.test")
    assert not rules.domain_allowed("lists.test")
    assert not rules.domain_allowed("other.test")
