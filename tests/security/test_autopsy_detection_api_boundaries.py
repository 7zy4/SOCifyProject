import json
from datetime import timedelta

import pytest

from socify import autopsy_ingestion, autopsy_intel
from socify.autopsy_worker import run_autopsy_worker_once
from socify.timeutils import utc_now


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"version": True, "mode": "rules"},
        {"version": 1, "mode": []},
        {"version": 1, "mode": "unknown"},
        {"version": 1, "mode": "rules", "after_id": -1},
        {"version": 1, "mode": "rules", "after_id": True},
        {"version": 1, "mode": "rules", "after_id": 2**100},
        {"version": 1, "mode": "rules", "unknown": True},
    ],
)
def test_detection_scan_rejects_untrusted_parameters_before_queuing(autopsy_case, client, database, payload):
    before = database.execute("SELECT COUNT(*) FROM autopsy_jobs").fetchone()[0]
    response = client.post(f"/api/cases/{autopsy_case}/detection", json=payload)
    assert response.status_code == 422
    assert database.execute("SELECT COUNT(*) FROM autopsy_jobs").fetchone()[0] == before


def test_deep_json_is_rejected_without_a_server_error_or_database_write(autopsy_case, client, database):
    before = database.execute("SELECT COUNT(*) FROM autopsy_jobs").fetchone()[0]
    payload = '{"nested":' * 1200 + "null" + "}" * 1200
    response = client.post(f"/api/cases/{autopsy_case}/detection", data=payload, content_type="application/json")
    assert response.status_code == 422
    assert response.json["error"]["code"] == "STRUCTURE_LIMIT_EXCEEDED"
    assert database.execute("SELECT COUNT(*) FROM autopsy_jobs").fetchone()[0] == before


def test_wide_json_is_rejected_before_expanding_validation_work(autopsy_case, client):
    payload = '{"values":[' + ",".join("0" for _ in range(200001)) + "]}"
    response = client.post(f"/api/cases/{autopsy_case}/detection", data=payload, content_type="application/json")
    assert response.status_code == 422 and response.json["error"]["code"] == "STRUCTURE_LIMIT_EXCEEDED"


def test_detection_stale_scope_closed_case_capacity_and_revoked_creator_fail_closed(autopsy_case, app, client, database, user_ids):
    base = f"/api/cases/{autopsy_case}"
    current = client.get(base).json["version"]
    assert client.post(base + "/detection", json={"version": current - 1, "mode": "rules"}).status_code == 409
    queued = client.post(base + "/detection", json={"version": current, "mode": "rules"}).json
    assert client.post(base + "/records/war_room", json={"title": "Updated scope", "body": "New investigative facts"}).status_code == 201
    with app.app_context():
        run_autopsy_worker_once()
    assert client.get(base + f"/jobs/{queued['id']}").json["error_code"] == "ACCESS_REVOKED"
    current = client.get(base).json["version"]
    second = client.post(base + "/detection", json={"version": current, "mode": "rules"}).json
    database.execute("UPDATE users SET is_active=0 WHERE id=?", (user_ids["analyst"],))
    with app.app_context():
        run_autopsy_worker_once()
    assert database.execute("SELECT error_code FROM autopsy_jobs WHERE id=?", (second["id"],)).fetchone()[0] == "ACCESS_REVOKED"
    database.execute("UPDATE users SET is_active=1 WHERE id=?", (user_ids["analyst"],))
    database.execute("UPDATE incident_cases SET status='closed' WHERE id=?", (autopsy_case,))
    assert client.post(base + "/detection", json={"version": current, "mode": "rules"}).status_code == 409


@pytest.mark.parametrize(
    "change",
    [
        {"version": True},
        {"verdict": []},
        {"attack_outcome": "unknown_value"},
        {"group": "x" * 101},
        {"suppressed_until": "2030-01-01"},
        {"suppressed_until": "2020-01-01T00:00:00Z"},
        {"suppressed_until": "2030-01-01T00:00:00Z"},
        {"reason": ""},
        {"extra": "untrusted"},
    ],
)
def test_alert_review_validates_every_input_before_database_use(autopsy_case, client, change):
    payload = {
        "version": 0,
        "verdict": "undetermined",
        "attack_outcome": "unknown",
        "group": "",
        "suppressed_until": None,
        "reason": "Synthetic bounded review",
        **change,
    }
    assert client.patch(f"/api/cases/{autopsy_case}/alerts/9999", json=payload).status_code == 422


def test_local_intelligence_expiry_configuration_refresh_and_invalid_requests(autopsy_case, app, client, login_as, monkeypatch):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    first = client.post(base + "/imports", json={"filename": "before.json", "content": '[{"title":"Before feed activation","source_ip":"192.0.2.8"}]'})
    assert first.status_code == 201
    assert client.get(base + "/observables").json["items"][0]["enrichment"]["status"] == "not_configured"
    bundle = {
        "name": "Refresh test",
        "version": "1",
        "source": "Synthetic expiry source",
        "license": "Synthetic test license",
        "format": "flat",
        "expires_at": "2030-01-01T00:00:00Z",
        "content": [{"type": "ip", "value": "192.0.2.8", "verdict": "suspicious"}],
    }
    created = client.post("/api/autopsy/intelligence", json=bundle).json
    assert client.post(f"/api/autopsy/intelligence/{created['id']}/activate").status_code == 200
    assert (
        client.post(base + "/imports", json={"filename": "after.json", "content": '[{"title":"After feed activation","source_ip":"192.0.2.8"}]'}).status_code
        == 201
    )
    observable = client.get(base + "/observables").json["items"][0]
    assert observable["enrichment"]["verdict"] == "suspicious" and observable["occurrences"] == 2
    assert client.post(base + "/observables/9999/enrich").status_code == 404
    for changes in (
        {"format": []},
        {"expires_at": []},
        {"license": ""},
        {"content": [{"type": "ip", "value": "192.0.2.8", "unexpected": True}]},
        {
            "format": "stix21",
            "content": {"type": "bundle", "objects": [{"type": "indicator", "pattern_type": "stix", "pattern": "[domain-name:value LIKE 'example%']"}]},
        },
        {"format": "misp", "content": {"Event": {"Attribute": [{"type": [], "value": "untrusted"}]}}},
    ):
        assert client.post("/api/autopsy/intelligence", json={**bundle, "version": "invalid", **changes}).status_code == 422
    monkeypatch.setattr(autopsy_intel, "utc_now", lambda: utc_now() + timedelta(days=2000))
    assert client.post(f"/api/autopsy/intelligence/{created['id']}/activate").status_code == 409


def test_bounded_fts_count_is_explicit_and_keeps_complete_authorized_pagination(autopsy_case, client, login_as, monkeypatch):
    monkeypatch.setattr(autopsy_ingestion, "SEARCH_COUNT_LIMIT", 2)
    base = f"/api/cases/{autopsy_case}"
    content = json.dumps([{"title": f"Bounded search source {index}"} for index in range(3)])
    assert client.post(base + "/imports", json={"filename": "bounded.json", "content": content}).status_code == 201
    login_as("soc_manager")
    other = client.post("/api/cases", json={"title": "Other private source", "reason": "forensic_review", "objective": "Keep unrelated matches private"}).json[
        "id"
    ]
    assert client.post(f"/api/cases/{other}/imports", json={"filename": "bounded.json", "content": content}).status_code == 201
    login_as("analyst")
    for resource in ("logs", "timeline"):
        first = client.get(base + f"/{resource}?q=Bounded&limit=2").json
        assert first["total"] == 2 and first["total_relation"] == "gte" and first["has_next"]
        second = client.get(base + f"/{resource}?q=Bounded&limit=2&page=2").json
        assert second["total_relation"] == "gte" and not second["has_next"]
        assert len(first["items"]) == 2 and len(second["items"]) == 1
        assert not {row["id"] for row in first["items"]} & {row["id"] for row in second["items"]}
    assert client.get(base + "/logs").json["total_relation"] == "eq"
    assert len(client.get(base + "/logs/export?format=json&q=Bounded").json) == 3
