import pytest

from app import favorites, mailstore, rules
from .conftest import SAMPLE


def test_parse_addresses_normalises_and_validates():
    assert favorites.parse_addresses("Bob@Example.test, alice@example.test;\nbob@example.test <carol@example.test>") \
        == ["bob@example.test", "alice@example.test", "carol@example.test"]
    with pytest.raises(favorites.FavoriteError):
        favorites.parse_addresses("not-an-address")
    with pytest.raises(favorites.FavoriteError):
        favorites.parse_addresses("  ")


def test_create_update_delete_and_counts():
    fid = favorites.create("Shopping", "shop@example.test\norders@example.test", "Everything I buy")
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="shop@example.test")
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="orders@example.test", read=True)
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="unrelated@example.test")
    rules.create_rule(conditions=[], actions=[{"action": "flag", "arg": ""}], scope="orders@example.test")
    rules.create_rule(conditions=[], actions=[{"action": "flag", "arg": ""}], scope="unrelated@example.test")

    fav = favorites.list_favorites()[0]
    assert (fav["name"], fav["messages"], fav["unread"], fav["rules"]) == ("Shopping", 2, 1, 1)
    rows, total = mailstore.list_messages(rcpts=fav["addresses"])
    assert total == 2 and {r["rcpt_to"] for r in rows} == {"shop@example.test", "orders@example.test"}
    assert [r["scope"] for r in favorites.rules_for(fav["addresses"])] == ["orders@example.test"]
    assert mailstore.list_messages(rcpts=[])[1] == 0

    favorites.update(fid, "Shops", "shop@example.test", "")
    assert favorites.get_favorite(fid)["addresses"] == ["shop@example.test"]
    assert favorites.favorites_containing("SHOP@example.test")[0]["name"] == "Shops"

    favorites.delete(fid)
    assert favorites.get_favorite(fid) is None
    assert mailstore.list_messages()[1] == 3                       # emails and rules untouched
    assert len(rules.list_rules()) == 2


def test_favorite_counts_trashed_mail_separately():
    fid = favorites.create("Shops", "bob@example.test", "")
    a = mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="bob@example.test")
    mailstore.store(SAMPLE, mail_from="a@b.test", rcpt="other@example.test")
    mailstore.trash([a])
    mine = next(f for f in favorites.list_favorites() if f["id"] == fid)
    assert (mine["messages"], mine["trashed"]) == (1, 1)
