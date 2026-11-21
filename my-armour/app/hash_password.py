"""Print a bcrypt hash for ADMIN_PASSWORD_HASH in .env.

    python -m app.hash_password

The password is read without echo and never printed or stored.
"""
import getpass
import sys

from app.auth import BCRYPT_MAX_BYTES, hash_password


def main() -> int:
    password = getpass.getpass("Admin password: ")
    if len(password) < 12:
        print("Use at least 12 characters.", file=sys.stderr)
        return 1
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        print(f"bcrypt uses at most {BCRYPT_MAX_BYTES} bytes - choose a shorter password.", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    print(f"ADMIN_PASSWORD_HASH='{hash_password(password)}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
