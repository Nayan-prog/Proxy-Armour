"""app.seed: password hashing over stdin and default-policy seeding."""
import io

import bcrypt
import pytest

import armour_config
from app import db, seed
from app.models import Policy
from tests.conftest import make_env


def test_hash_reads_stdin_and_prints_a_bcrypt_hash(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("a-long-demo-password\n"))
    assert seed.main(["hash"]) == 0
    hashed = capsys.readouterr().out.strip()
    assert bcrypt.checkpw(b"a-long-demo-password", hashed.encode())


@pytest.mark.parametrize("password", ["short", "x" * 80])
def test_hash_rejects_bad_passwords(monkeypatch, password):
    monkeypatch.setattr("sys.stdin", io.StringIO(password + "\n"))
    assert seed.main(["hash"]) == 1


def test_seed_inserts_missing_and_reset_restores_defaults(api, monkeypatch, database_url):
    monkeypatch.setattr(armour_config, "env", make_env(database_url=database_url))
    with db.session_factory()() as session:          # api fixture already seeded; break two rows
        session.delete(session.get(Policy, "EMAIL"))
        session.get(Policy, "AADHAAR").action = "allow"
        session.commit()
    assert seed.seed_policies() == (1, 0)              # EMAIL back, AADHAAR left as the admin set it
    assert seed.seed_policies(reset=True) == (0, 1)   # AADHAAR restored
    with db.session_factory()() as session:
        assert session.get(Policy, "AADHAAR").action == "block"
        assert session.get(Policy, "EMAIL").updated_by == "seed"
