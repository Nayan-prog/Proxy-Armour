"""Admin authentication: bcrypt password check -> HS256 JWT bearer token.

Credentials come from .env: ADMIN_USERNAME, ADMIN_PASSWORD_HASH (bcrypt hash,
never the password) and JWT_SECRET (>= 32 chars). If any is missing the admin
API answers 503 instead of running with an insecure default.
"""
import hmac
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import armour_config
from armour_config import settings

ALGORITHM = "HS256"
ISSUER = "proxy-armour"
MIN_SECRET_LENGTH = 32
BCRYPT_MAX_BYTES = 72          # bcrypt ignores the rest; bcrypt >= 5 raises instead


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    raw = password.encode("utf-8")
    if len(raw) > BCRYPT_MAX_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, hashed.encode())
    except ValueError:                         # malformed hash in .env
        return False


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    # same cost as a real hash, so a wrong username takes as long as a wrong password
    return hash_password("not-the-password")


def admin_env():
    """The admin settings, or 503 if the admin API isn't configured safely."""
    e = armour_config.env
    if not (e.admin_username and e.admin_password_hash and e.jwt_secret):
        raise HTTPException(503, "admin login not configured (see .env.example)")
    if len(e.jwt_secret.get_secret_value()) < MIN_SECRET_LENGTH:
        raise HTTPException(503, f"JWT_SECRET must be at least {MIN_SECRET_LENGTH} characters")
    return e


def authenticate(username: str, password: str) -> bool:
    e = admin_env()
    user_ok = hmac.compare_digest(username.encode(), e.admin_username.encode())
    hashed = e.admin_password_hash.get_secret_value() if user_ok else _dummy_hash()
    password_ok = verify_password(password, hashed)    # always runs: no timing hint
    return user_ok and password_ok


def create_token(username: str) -> tuple[str, datetime]:
    e = admin_env()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=settings.admin.jwt_expiry_hours)
    token = jwt.encode({"sub": username, "iat": now, "exp": expires, "iss": ISSUER},
                       e.jwt_secret.get_secret_value(), algorithm=ALGORITHM)
    return token, expires


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})


def decode_token(token: str) -> str:
    e = admin_env()
    try:
        claims = jwt.decode(token, e.jwt_secret.get_secret_value(),
                            algorithms=[ALGORITHM],          # never trust the token's own "alg"
                            issuer=ISSUER, options={"require": ["exp", "iat", "sub", "iss"]})
    except jwt.ExpiredSignatureError:
        raise _unauthorized("token expired")
    except jwt.PyJWTError:
        raise _unauthorized("invalid token")
    if not hmac.compare_digest(str(claims["sub"]).encode(), e.admin_username.encode()):
        raise _unauthorized("invalid token")                 # admin was renamed
    return claims["sub"]


_bearer = HTTPBearer(auto_error=False)


def require_admin(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    """FastAPI dependency: the admin username, or 401/503."""
    admin_env()
    if credentials is None:
        raise _unauthorized("missing bearer token")
    return decode_token(credentials.credentials)


class LoginThrottle:
    """At most max_failures failed logins per client within window_seconds."""

    def __init__(self, max_failures: int, window_seconds: float, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window_seconds
        self._clock = clock
        self._failures: dict[str, deque] = defaultdict(deque)

    def _recent(self, key: str) -> deque:
        q, cutoff = self._failures[key], self._clock() - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        return q

    def check(self, key: str) -> None:
        q = self._recent(key)
        if len(q) >= self.max_failures:
            retry = int(q[0] + self.window - self._clock()) + 1
            raise HTTPException(429, "too many failed logins", headers={"Retry-After": str(retry)})

    def failed(self, key: str) -> None:
        self._recent(key).append(self._clock())

    def succeeded(self, key: str) -> None:
        self._failures.pop(key, None)


THROTTLE = LoginThrottle(settings.admin.login_max_failures, settings.admin.login_window_seconds)
