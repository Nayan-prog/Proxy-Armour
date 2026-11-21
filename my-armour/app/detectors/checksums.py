"""Check-digit algorithms used to cut false positives in the regex detector."""

# --- Verhoeff (used by Aadhaar) ---------------------------------------------
# _D: multiplication table of the dihedral group D5 (non-commutative: a*b != b*a)
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
# _P: permutation applied to a digit depending on its position (repeats every 8)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
# _INV: inverse of each element in D5
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def _only_digits(number: str) -> str:
    digits = "".join(ch for ch in number if ch.isdigit())
    if not digits or not digits.isascii():
        raise ValueError("number must contain ASCII digits")
    return digits


def verhoeff_check_digit(number: str) -> str:
    """Digit to append to number so the result passes verhoeff_valid."""
    c = 0
    for i, ch in enumerate(reversed(_only_digits(number))):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]   # +1: positions shift once the check digit is appended
    return str(_INV[c])


def verhoeff_valid(number: str) -> bool:
    """True if number (spaces/dashes ignored) ends in a correct Verhoeff check digit."""
    try:
        digits = _only_digits(number)
    except ValueError:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


# --- Luhn (used by payment cards) --------------------------------------------

def luhn_valid(number: str) -> bool:
    """True if number (spaces/dashes ignored) passes the Luhn mod-10 check."""
    try:
        digits = _only_digits(number)
    except ValueError:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:          # every second digit from the right is doubled
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
