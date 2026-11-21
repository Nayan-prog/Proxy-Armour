"""Seeding helpers, run inside the scanner container by `scripts/stack.py seed`.

    python -m app.seed hash               # reads a password on stdin, prints its bcrypt hash
    python -m app.seed policies           # insert default policies for types not in the table
    python -m app.seed policies --reset   # put every policy back to the config.yaml default

The password arrives on stdin, never as a command-line argument (argv is
visible to other processes).
"""
import argparse
import sys

from sqlalchemy import select

from app import db
from app.auth import BCRYPT_MAX_BYTES, hash_password
from app.detectors.engine import default_severities
from app.models import Policy, utcnow
from app.policy_store import STORE


def seed_policies(reset: bool = False) -> tuple[int, int]:
    """Returns (inserted, reset) row counts."""
    db.configure_from_env()
    factory = db.session_factory()
    if factory is None:
        raise SystemExit("DATABASE_URL is not set")
    severities = default_severities()
    inserted = changed = 0
    with factory() as session:
        existing = {p.type: p for p in session.scalars(select(Policy))}
        for type_, action in sorted(STORE.base.types.items()):
            row = existing.get(type_)
            if row is None:
                session.add(Policy(type=type_, action=action, severity=severities.get(type_, "high"),
                                   updated_at=utcnow(), updated_by="seed"))
                inserted += 1
            elif reset and (row.action, row.severity) != (action, severities.get(type_, "high")):
                row.action, row.severity = action, severities.get(type_, "high")
                row.updated_at, row.updated_by = utcnow(), "seed --reset"
                changed += 1
        session.commit()
    return inserted, changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.seed")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hash", help="bcrypt-hash a password read from stdin")
    policies = sub.add_parser("policies", help="seed default policies")
    policies.add_argument("--reset", action="store_true", help="restore config.yaml defaults")
    args = parser.parse_args(argv)

    if args.command == "hash":
        password = sys.stdin.readline().rstrip("\r\n")
        if len(password) < 12:
            print("password must be at least 12 characters", file=sys.stderr)
            return 1
        if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
            print(f"password must be at most {BCRYPT_MAX_BYTES} bytes", file=sys.stderr)
            return 1
        print(hash_password(password))
        return 0

    inserted, changed = seed_policies(reset=args.reset)
    print(f"policies: {inserted} inserted, {changed} reset to defaults")
    return 0


if __name__ == "__main__":
    sys.exit(main())
