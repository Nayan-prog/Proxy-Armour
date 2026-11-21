"""GET/PUT /api/policies, GET /internal/policies, and their effect on /scan."""
import pytest

from armour_config import settings
from app import db
from app.models import Policy
from tests.conftest import ADMIN_USER


def policies(api, auth):
    return {p["type"]: p for p in api.get("/api/policies", headers=auth).json()}


def test_policies_are_seeded_from_config(api, auth):
    p = policies(api, auth)
    assert p["EMAIL"]["action"] == "tokenize" and p["EMAIL"]["severity"] == "low"
    assert p["AADHAAR"]["action"] == "block" and p["AADHAAR"]["severity"] == "high"
    assert p["EMAIL"]["updated_by"] == "config.yaml"
    assert p["EMAIL"]["updated_at"].endswith("Z") or p["EMAIL"]["updated_at"].endswith("+00:00")
    assert set(p) == set(settings.policy.types)


def test_put_updates_policy_and_records_who(api, auth):
    r = api.put("/api/policies", headers=auth, json={"policies": [
        {"type": "EMAIL", "action": "block", "severity": "high"},
        {"type": "PAN", "action": "tokenize"}]})
    assert r.status_code == 200
    p = {row["type"]: row for row in r.json()}
    assert (p["EMAIL"]["action"], p["EMAIL"]["severity"], p["EMAIL"]["updated_by"]) == ("block", "high", ADMIN_USER)
    assert (p["PAN"]["action"], p["PAN"]["severity"]) == ("tokenize", "medium")   # severity kept
    with db.session_factory()() as session:
        assert session.get(Policy, "EMAIL").updated_by == ADMIN_USER


def test_put_takes_effect_on_scan_immediately(api, auth):
    assert api.post("/scan", json={"text": "mail rahul@acme.com"}).json()["action"] == "tokenize"
    api.put("/api/policies", headers=auth, json={"policies": [
        {"type": "EMAIL", "action": "block", "severity": "high"}]})
    r = api.post("/scan", json={"text": "mail rahul@acme.com"}).json()
    assert (r["action"], r["risk"]) == ("block", "high")            # severity override applied


def test_internal_policies_for_the_proxy(api, auth, secret_header):
    assert api.get("/internal/policies").status_code == 401
    api.put("/api/policies", headers=auth, json={"policies": [{"type": "EMAIL", "action": "allow"}]})
    r = api.get("/internal/policies", headers=secret_header)
    assert r.status_code == 200
    assert r.json()["types"]["EMAIL"] == "allow" and r.json()["default_action"] == "block"


def test_internal_policies_read_the_table_not_just_memory(api, secret_header):
    # another API worker changed the table: this worker must still serve it
    with db.session_factory()() as session:
        session.get(Policy, "PHONE_IN").action = "block"
        session.commit()
    assert api.get("/internal/policies", headers=secret_header).json()["types"]["PHONE_IN"] == "block"


@pytest.mark.parametrize("body", [
    {"policies": [{"type": "NOT_A_TYPE", "action": "block"}]},
    {"policies": [{"type": "EMAIL", "action": "redact"}]},
    {"policies": [{"type": "email", "action": "block"}]},
    {"policies": [{"type": "EMAIL", "action": "block", "severity": "critical"}]},
    {"policies": [{"type": "EMAIL", "action": "block", "updated_by": "mallory"}]},
    {"policies": []},
])
def test_invalid_policy_updates_are_422(api, auth, body):
    assert api.put("/api/policies", headers=auth, json=body).status_code == 422
    assert policies(api, auth)["EMAIL"]["action"] == "tokenize"      # nothing changed


def test_without_a_database_policies_are_read_only(api, auth):
    db.configure(None)
    p = policies(api, auth)
    assert p["EMAIL"]["action"] == "tokenize" and p["EMAIL"]["updated_at"] is None
    r = api.put("/api/policies", headers=auth, json={"policies": [{"type": "EMAIL", "action": "block"}]})
    assert r.status_code == 503
