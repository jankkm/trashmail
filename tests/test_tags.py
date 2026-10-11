from app import mailstore, rules, smtp_server
from .conftest import SAMPLE


def store(rcpt="bob@example.test", **kw):
    return mailstore.store(SAMPLE, mail_from="alice@sender.test", rcpt=rcpt, **kw)


def test_normalize_and_parse():
    assert mailstore.normalize_tag("  Big   Invoice, ") == "Big Invoice"
    assert len(mailstore.normalize_tag("x" * 100)) == mailstore.TAG_MAX
    assert mailstore.parse_tags("Work, work; Invoices\nINVOICES ,, ") == ["Work", "Invoices"]


def test_add_remove_case_insensitive_and_listing():
    a, b = store(), store()
    mailstore.add_tags([a, b], ["Invoices", "Work"])
    mailstore.add_tags([a], ["invoices"])                     # same tag, other case: no duplicate
    assert mailstore.tags_for([a, b]) == {a: ["Invoices", "Work"], b: ["Invoices", "Work"]}
    assert [(t["tag"].lower(), t["c"]) for t in mailstore.all_tags()] == [("invoices", 2), ("work", 2)]
    mailstore.remove_tag(a, "WORK")                           # removal ignores case too
    assert mailstore.tags_for([a])[a] == ["Invoices"]


def test_filter_by_tag_and_cascade_on_delete():
    a, b = store(tags=["Receipts"]), store()
    rows, total = mailstore.list_messages(tag="receipts")
    assert total == 1 and rows[0]["id"] == a
    mailstore.delete([a])
    assert mailstore.all_tags() == [] and mailstore.tags_for([a]) == {}
    assert mailstore.get(b) is not None


def test_tag_rule_action_validation_and_roundtrip():
    rid = rules.create_rule(conditions=[], actions=[{"action": "tag", "arg": "  Big   Invoice "},
                                                    {"action": "flag", "arg": "ignored"}])
    acts = rules.get_rule(rid)["actions"]
    assert acts[0] == {**acts[0], "action": "tag", "arg": "Big Invoice"} and acts[1]["arg"] == ""
    import pytest
    with pytest.raises(rules.RuleError):
        rules.create_rule(conditions=[], actions=[{"action": "tag", "arg": "  ,; "}])


async def test_rules_add_tags_on_delivery():
    rules.create_rule(conditions=[{"field": "subject", "op": "contains", "value": "invoice"}],
                      actions=[{"action": "tag", "arg": "Invoices"}, {"action": "tag", "arg": "Finance"},
                               {"action": "flag"}], name="Tag invoices")
    rules.create_rule(conditions=[{"field": "subject", "op": "contains", "value": "nothing-like-this"}],
                      actions=[{"action": "tag", "arg": "Other"}])
    mid = await smtp_server.deliver(SAMPLE, mail_from="alice@sender.test", rcpt="bob@example.test")
    assert mailstore.tags_for([mid])[mid] == ["Finance", "Invoices"]
    assert mailstore.get(mid)["flagged"] == 1
