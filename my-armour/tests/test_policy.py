import pytest

from armour_config import PolicySettings
from app.policy import apply_policy, request_action

POLICY = PolicySettings(default_action="block", types={"EMAIL": "tokenize", "PAN": "block",
                                                       "NOTE": "allow"})


def findings(*types):
    return apply_policy([{"type": t} for t in types], POLICY)


def test_each_finding_gets_its_type_action():
    assert [f["action"] for f in findings("EMAIL", "PAN", "NOTE")] == ["tokenize", "block", "allow"]


def test_unlisted_type_falls_back_to_default():
    assert findings("SOMETHING_NEW")[0]["action"] == "block"


@pytest.mark.parametrize("types,expected", [
    ((), "allow"),
    (("NOTE",), "allow"),
    (("EMAIL", "NOTE"), "tokenize"),
    (("EMAIL", "EMAIL", "PAN"), "block"),       # one block finding blocks the request
    (("SOMETHING_NEW", "EMAIL"), "block"),
])
def test_request_action_is_the_strictest(types, expected):
    assert request_action(findings(*types)) == expected
