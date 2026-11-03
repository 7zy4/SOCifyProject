import io
import sqlite3
from importlib import import_module

import pytest

from socify.timeutils import parse_timestamp
from socify.validation import ValidationError

PRIVATE_DETAIL = "private-db.sqlite table=auth_sessions token=private-secret /srv/private/config"


def fail_with(error):
    def fail(*args, **kwargs):
        raise error

    return fail


def assert_safe_failure(response, code, status=422):
    assert response.status_code == status, response.json
    assert response.json["error"]["code"] == code
    assert response.json["error"]["message"]
    assert response.json["correlation_id"]
    assert PRIVATE_DETAIL not in response.get_data(as_text=True)
    assert "private-secret" not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "error",
    [
        ValueError(PRIVATE_DETAIL),
        sqlite3.IntegrityError(PRIVATE_DETAIL),
        OverflowError(PRIVATE_DETAIL),
        UnicodeError(PRIVATE_DETAIL),
        KeyError(PRIVATE_DETAIL),
        TypeError(PRIVATE_DETAIL),
    ],
    ids=["parser", "database", "overflow", "unicode", "missing-key", "wrong-type"],
)
def test_capsule_library_errors_do_not_expose_internal_details(autopsy_case, client, database, monkeypatch, error):
    count = database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0]
    monkeypatch.setattr("socify.autopsy_capsules.inspect_capsule", fail_with(error))
    response = client.post("/api/cases/import-capsule", data={"file": (io.BytesIO(b"bad archive"), "case.zip")})
    assert_safe_failure(response, "INVALID_CAPSULE")
    assert database.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0] == count


def test_catalog_errors_do_not_expose_internal_details(client, login_as, monkeypatch):
    login_as("admin")
    monkeypatch.setattr("socify.attack.activate_attack_version", fail_with(ValueError(PRIVATE_DETAIL)))
    assert_safe_failure(client.post("/api/attack/catalogs/unavailable/activate"), "ATTACK_VERSION_NOT_FOUND", 404)


def test_case_context_error_does_not_expose_details_or_mutate_case(autopsy_case, client, database, monkeypatch):
    version = database.execute("SELECT version FROM incident_cases WHERE id=?", (autopsy_case,)).fetchone()[0]
    monkeypatch.setattr(import_module("socify.autopsy_api"), "text_value", fail_with(ValueError(PRIVATE_DETAIL)))
    response = client.patch(f"/api/cases/{autopsy_case}/context", json={"objective": "Updated objective", "version": version})
    assert_safe_failure(response, "INVALID_CASE_CONTEXT")
    assert database.execute("SELECT version FROM incident_cases WHERE id=?", (autopsy_case,)).fetchone()[0] == version


@pytest.mark.parametrize("error_type", [ValueError, UnicodeError])
def test_record_error_does_not_expose_details_or_create_record(autopsy_case, client, database, monkeypatch, error_type):
    monkeypatch.setattr(import_module("socify.autopsy_api"), "validate_record", fail_with(error_type(PRIVATE_DETAIL)))
    response = client.post(f"/api/cases/{autopsy_case}/records/asset", json={})
    assert_safe_failure(response, "INVALID_RECORD")
    assert database.execute("SELECT COUNT(*) FROM autopsy_records WHERE case_id=?", (autopsy_case,)).fetchone()[0] == 0


def test_chronology_parser_error_is_private_but_validation_is_actionable(autopsy_case, client):
    endpoint = f"/api/cases/{autopsy_case}/chronology"
    assert_safe_failure(client.get(endpoint, query_string={"page": PRIVATE_DETAIL}), "INVALID_CHRONOLOGY_FILTER")
    response = client.get(endpoint, query_string={"page": 0})
    assert response.status_code == 422
    assert response.json["error"]["message"] == "الترقيم خارج النطاق"


def test_record_validation_still_identifies_the_missing_field(autopsy_case, client):
    response = client.post(f"/api/cases/{autopsy_case}/records/asset", json={})
    assert response.status_code == 422
    assert response.json["error"]["message"] == "الحقل name مطلوب"


@pytest.mark.parametrize(
    "value", [PRIVATE_DETAIL, "2026-25-90", float("inf"), float("nan"), 10**1000], ids=["private-text", "invalid-date", "infinity", "nan", "overflow"]
)
def test_timestamp_errors_are_deliberate_validation_messages(value):
    with pytest.raises(ValidationError) as error:
        parse_timestamp(value)
    assert "timestamp" in error.value.public_message
    assert PRIVATE_DETAIL not in error.value.public_message
