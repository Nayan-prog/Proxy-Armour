import pytest

from app.detectors.checksums import luhn_valid, verhoeff_check_digit, verhoeff_valid


def test_verhoeff_published_example():
    # Wikipedia's worked example: check digit of 236 is 3
    assert verhoeff_check_digit("236") == "3"
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


@pytest.mark.parametrize("base", ["23456789012", "98765432101", "49182736450"])
def test_generated_check_digit_validates(base):
    assert verhoeff_valid(base + verhoeff_check_digit(base))


def test_verhoeff_catches_every_single_digit_typo_and_adjacent_swap():
    good = "234567890124"
    assert verhoeff_valid(good)
    for i in range(len(good)):
        for d in "0123456789":
            if d != good[i]:
                assert not verhoeff_valid(good[:i] + d + good[i + 1:])
        if i + 1 < len(good) and good[i] != good[i + 1]:
            swapped = good[:i] + good[i + 1] + good[i] + good[i + 2:]
            assert not verhoeff_valid(swapped)


def test_verhoeff_ignores_separators_and_rejects_non_digits():
    assert verhoeff_valid("2345 6789 0124") and verhoeff_valid("2345-6789-0124")
    assert not verhoeff_valid("") and not verhoeff_valid("abcd")


@pytest.mark.parametrize("number", ["79927398713", "4111111111111111", "4111 1111 1111 1111",
                                    "5555555555554444", "378282246310005"])
def test_luhn_valid(number):
    assert luhn_valid(number)


@pytest.mark.parametrize("number", ["79927398710", "4111111111111112", "1234567812345678", ""])
def test_luhn_invalid(number):
    assert not luhn_valid(number)
