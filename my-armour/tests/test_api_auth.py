"""Admin authentication: login, JWT validation, throttling, misconfiguration."""
from datetime import datetime, timedelta, timezone

import jwt
import pytest

import armour_config
from app.auth import ISSUER, verify_password
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, JWT_SECRET, make_env

PROTECTED = [("GET", "/api/stats"), ("GET", "/api/events"), ("GET", "/api/events/1"),
             ("GET", "/api/policies"), ("PUT", "/api/policies"), ("GET", "/api/live"),
             ("POST", "/api/playground/scan")]


def login(api, username=ADMIN_USER, password=ADMIN_PASSWORD):
    return api.post("/api/login", json={"username": username, "password": password})


def test_login_returns_an_8_hour_bearer_token(api):
    r = login(api)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    claims = jwt.decode(body["access_token"], JWT_SECRET, algorithms=["HS256"], issuer=ISSUER)
    assert claims["sub"] == ADMIN_USER
    assert abs((claims["exp"] - claims["iat"]) - 8 * 3600) <= 1


@pytest.mark.parametrize("username,password", [
    (ADMIN_USER, "wrong password"),
    ("root", ADMIN_PASSWORD),
    ("root", "wrong password"),
    (ADMIN_USER, "x" * 100),                       # > 72 bytes: rejected cleanly, not a 500
])
def test_bad_credentials_are_401(api, username, password):
    r = login(api, username, password)
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid username or password"   # same message: no user enumeration


def test_repeated_failures_are_throttled(api):
    for _ in range(5):
        assert login(api, password="nope").status_code == 401
    r = login(api)                                  # even the right password is refused now
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


def test_success_resets_the_failure_count(api):
    for _ in range(4):
        login(api, password="nope")
    assert login(api).status_code == 200
    for _ in range(4):
        assert login(api, password="nope").status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_endpoints_need_a_token(api, method, path):
    r = api.request(method, path, json={})
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"


def _token(secret=JWT_SECRET, alg="HS256", **claims):
    now = datetime.now(timezone.utc)
    payload = {"sub": ADMIN_USER, "iat": now, "exp": now + timedelta(hours=1), "iss": ISSUER, **claims}
    return jwt.encode(payload, secret, algorithm=alg)


@pytest.mark.parametrize("bad_token", [
    "not-a-jwt",
    _token(exp=datetime.now(timezone.utc) - timedelta(seconds=1)),        # expired
    _token(secret="x" * 48),                                               # wrong key
    _token(sub="someone-else"),                                            # not the admin
    _token(iss="another-app"),                                             # wrong issuer
    jwt.encode({"sub": ADMIN_USER, "iss": ISSUER}, JWT_SECRET, algorithm="HS256"),  # no exp
    jwt.encode({"sub": ADMIN_USER}, None, algorithm="none"),               # unsigned
    _token(alg="HS512"),                                                   # algorithm not allowed
], ids=["garbage", "expired", "wrong-key", "other-user", "wrong-issuer", "no-exp", "alg-none", "hs512"])
def test_invalid_tokens_are_rejected(api, bad_token):
    r = api.get("/api/stats", headers={"Authorization": f"Bearer {bad_token}"})
    assert r.status_code == 401


def test_valid_token_is_accepted(api, auth):
    assert api.get("/api/policies", headers=auth).status_code == 200


@pytest.mark.parametrize("env", [
    {},                                                                  # nothing configured
    {"admin_username": ADMIN_USER, "jwt_secret": JWT_SECRET},            # no password hash
    {"admin_username": ADMIN_USER, "admin_password_hash": "$2b$04$x", "jwt_secret": "short"},
], ids=["unconfigured", "no-hash", "weak-jwt-secret"])
def test_admin_api_is_503_not_open_when_misconfigured(api, monkeypatch, env):
    monkeypatch.setattr(armour_config, "env", make_env(**env))
    assert login(api).status_code == 503
    assert api.get("/api/stats", headers={"Authorization": f"Bearer {_token()}"}).status_code == 503


def test_verify_password_handles_bad_input(admin_hash):
    assert verify_password(ADMIN_PASSWORD, admin_hash)
    assert not verify_password(ADMIN_PASSWORD, "not-a-bcrypt-hash")
    assert not verify_password("é" * 40, admin_hash)                     # 80 bytes


def test_cors_allows_only_the_dashboard_origin(api):
    allowed = api.options("/api/login", headers={"Origin": "http://localhost:3000",
                                                 "Access-Control-Request-Method": "POST"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    other = api.options("/api/login", headers={"Origin": "https://evil.example",
                                               "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in other.headers
