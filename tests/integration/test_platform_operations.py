import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from socify.attack_snapshot import load_stix_snapshot
from socify.operations import backup_database, migration_dry_run, restore_database, verify_database


def test_platform_read_models_and_ui_routes(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    assert client.get("/health/live").json["status"] == "live"
    assert client.get("/health/ready").json["status"] == "ready"
    assert client.get("/test").status_code == 302
    assert client.get("/dashboard").status_code == 302
    login_as("admin")
    for path in (
        "/dashboard",
        "/events",
        "/alerts",
        "/rules",
        "/sources",
        "/imports",
        "/incidents",
        "/lab",
        "/attack",
        "/hunt",
        "/graph",
        "/playbooks",
        "/scores",
        "/audit",
        "/admin",
        "/profile",
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert 'dir="rtl"' in response.text
    for path in ("/api/health", "/api/dashboard", "/api/stats", "/api/profile", "/api/settings", "/api/admin/role-matrix"):
        assert client.get(path).status_code == 200
    assert client.get("/api/audit?page=invalid").status_code == 400
    audit = client.get("/api/audit?page=1&page_size=10&action=login&resource=session")
    assert audit.status_code == 200
    assert audit.json["page_size"] == 10


def test_attack_snapshot_loads_compact_and_stix_formats(tmp_path: Path, database: sqlite3.Connection) -> None:
    compact = {
        "techniques": [
            {
                "technique_id": "T9999",
                "name": "Synthetic Technique",
                "tactics": ["discovery"],
                "description": "Training fixture",
                "source_url": "https://attack.mitre.org/",
                "is_subtechnique": False,
            }
        ]
    }
    compact_path = tmp_path / "compact.json"
    compact_path.write_text(json.dumps(compact), encoding="utf-8")
    assert load_stix_snapshot(database, str(compact_path), "test", allow_partial=True) == 1
    assert database.execute("SELECT name FROM attack_techniques WHERE technique_id = 'T9999'").fetchone()[0] == "Synthetic Technique"
    stix = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Synthetic Sub-technique",
                "description": "Fixture",
                "x_mitre_is_subtechnique": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999.001"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            },
            {"type": "identity", "name": "ignored"},
        ]
    }
    stix_path = tmp_path / "stix.json"
    stix_path.write_text(json.dumps(stix), encoding="utf-8")
    assert load_stix_snapshot(database, str(stix_path), "test-2", allow_partial=True) == 1
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        load_stix_snapshot(database, str(invalid), "bad")


def test_backup_restore_and_migration_drill(app, tmp_path: Path) -> None:
    source = Path(app.config["DATABASE"])
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    assert verify_database(str(source))["integrity"] == "ok"
    assert backup_database(str(source), str(backup))["foreign_key_violations"] == 0
    assert restore_database(str(backup), str(restored))["integrity"] == "ok"
    assert migration_dry_run(str(restored))["schema_version"] == "2"
    with pytest.raises(ValueError):
        backup_database(str(tmp_path / "missing.db"), str(backup))
    with pytest.raises(ValueError):
        restore_database(str(tmp_path / "missing.db"), str(restored))
    with pytest.raises(ValueError):
        migration_dry_run(str(tmp_path / "missing.db"))


def test_scenario_authoring_versioning_and_state_machine(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("instructor")
    payload = {
        "name": "Synthetic chain",
        "description": "Safe isolated training chain",
        "difficulty": "beginner",
        "objectives": ["Investigate a synthetic event"],
        "steps": [
            {
                "name": "Synthetic login",
                "event": {"event_type": "failed_login", "source": "training", "title": "Synthetic"},
                "mitre_ids": ["T1110"],
                "hint": "Inspect the source IP",
            }
        ],
    }
    created = client.post("/api/scenarios", json=payload)
    assert created.status_code == 201
    scenario_id = created.json["id"]
    assert client.get(f"/api/scenarios/{scenario_id}").status_code == 200
    assert client.post(f"/api/scenarios/{scenario_id}/transition", json={"state": "published"}).status_code == 409
    for state in ("validated", "published", "ready"):
        response = client.post(f"/api/scenarios/{scenario_id}/transition", json={"state": state})
        assert response.status_code == 200
    cloned = client.post(f"/api/scenarios/{scenario_id}/clone", json={"name": "Synthetic chain copy"})
    assert cloned.status_code == 201
    versioned = client.post(f"/api/scenarios/{scenario_id}/versions", json={**payload, "difficulty": "advanced"})
    assert versioned.status_code == 201
    assert versioned.json["version"] == 2
    for bad in (
        {},
        {**payload, "steps": []},
        {**payload, "difficulty": "impossible"},
        {**payload, "steps": [{"name": "Unsafe", "event": {"url": "https://public.example"}}]},
    ):
        assert client.post("/api/scenarios", json=bad).status_code == 422


def test_attack_catalog_search_coverage_and_navigator(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("analyst")
    search = client.get("/api/attack/techniques?q=Brute")
    assert search.status_code == 200
    assert any(item["technique_id"] == "T1110" for item in search.json["items"])
    assert client.get("/api/attack/techniques?q=" + "x" * 101).status_code == 422
    assert client.get("/api/attack/techniques/T0000").status_code == 404
    assert client.get("/api/attack/coverage").status_code == 200
    navigator = client.get("/api/attack/navigator-layer")
    assert navigator.status_code == 200
    assert navigator.json["domain"] == "enterprise-attack"


def test_event_filters_mutations_and_validation(client: FlaskClient, login_as: Callable[[str], None], event_payload: dict[str, object]) -> None:
    login_as("admin")
    created = client.post("/api/events", json=event_payload, headers={"Idempotency-Key": "platform-operations-event"})
    assert created.status_code == 201
    event_id = created.json["id"]
    for query, status in (
        ("page=bad", 400),
        ("sort=unknown", 422),
        ("start=not-a-date", 422),
        ("end=not-a-date", 422),
        ("q=" + "x" * 201, 422),
        ("severity=medium&status=open&source=acceptance-fixture&event_type=failed_login&direction=asc", 200),
    ):
        assert client.get(f"/api/events?{query}").status_code == status
    assert client.get(f"/api/events/{event_id}").status_code == 200
    assert client.get(f"/api/events/{event_id}/raw").json["raw_payload"]["synthetic"] is True
    assert client.put(f"/api/events/{event_id}", json={}).status_code == 422
    assert client.put(f"/api/events/{event_id}", json={"status": "invalid"}).status_code == 422
    assert client.put(f"/api/events/{event_id}", json={"severity": "high", "status": "investigating"}).status_code == 200
    assert client.delete(f"/api/events/{event_id}").status_code == 409
    assert client.get("/api/events/999999").status_code == 404
    assert client.post("/api/events", json={"source": "fixture", "event_type": "test", "title": "x", "severity": "impossible"}).status_code == 422


def test_source_crud_validation_and_explicit_connector_status(client: FlaskClient, login_as: Callable[[str], None]) -> None:
    login_as("admin")
    assert client.post("/api/sources", json={}).status_code == 422
    assert client.post("/api/sources", json={"name": "x", "type": "unknown"}).status_code == 422
    created = client.post("/api/sources", json={"name": "Training file", "type": "file", "credential": "temporary-secret"})
    assert created.status_code == 201
    source_id = created.json["id"]
    listed = client.get("/api/sources")
    source = next(item for item in listed.json if item["id"] == source_id)
    assert source["credentials_stored"] is True
    assert "credential_ciphertext" not in source
    assert client.patch(f"/api/sources/{source_id}", json={}).status_code == 422
    updated = client.patch(f"/api/sources/{source_id}", json={"name": "Training file updated", "credential": None})
    assert updated.status_code == 200
    assert updated.json["credentials_stored"] is False
    tested = client.post(f"/api/sources/{source_id}/test")
    assert tested.status_code == 200
    assert tested.json["status"] == "connected"
    assert client.delete(f"/api/sources/{source_id}").status_code == 204
    assert client.patch("/api/sources/999999", json={"name": "Missing"}).status_code == 404


def test_auth_profile_session_and_admin_validation(client: FlaskClient, login_as: Callable[[str], None], user_ids: dict[str, int]) -> None:
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200
    assert client.post("/api/auth/login", json={}).status_code == 401
    assert client.post("/api/auth/register", json={}).status_code == 422
    login_as("admin")
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/auth/sessions").status_code == 200
    assert client.delete("/api/auth/sessions/999999").status_code == 404
    users = client.get("/api/admin/users")
    assert users.status_code == 200
    analyst_id = user_ids["analyst"]
    assert client.patch(f"/api/admin/users/{analyst_id}", json={}).status_code == 422
    assert client.patch(f"/api/admin/users/{analyst_id}", json={"role": "invalid"}).status_code == 422
    assert client.patch("/api/admin/users/999999", json={"is_active": True}).status_code == 404
    assert client.delete("/api/admin/users/999999/mfa").status_code == 422
