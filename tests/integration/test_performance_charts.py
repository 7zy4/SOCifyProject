"""Chart denominators, response targets and authorization use retained case facts."""

import json
from datetime import UTC, datetime

import pytest

from socify.soc_insights import measured_percentage

NOW = datetime(2026, 11, 4, 12, tzinfo=UTC)


@pytest.fixture
def performance_clock(monkeypatch):
    monkeypatch.setattr("socify.soc_insights.utc_now", lambda: NOW)


def case(client, database, title, created="2026-11-02T08:00:00Z", *, status="draft", closed=None):
    response = client.post("/api/cases", json={"title": title})
    assert response.status_code == 201, response.json
    identifier = response.json["id"]
    database.execute("UPDATE incident_cases SET created_at=?, status=?, closed_at=? WHERE id=?", (created, status, closed, identifier))
    return identifier


def performance(client, query="days=7"):
    response = client.get("/api/soc/performance?" + query)
    assert response.status_code == 200, response.json
    return response.json


def policy(client, identifier, minutes, calendar=None):
    base = f"/api/cases/{identifier}"
    response = client.post(
        base + "/sla",
        json={
            "version": client.get(base).json["version"],
            "minutes": minutes,
            "calendar": calendar or {"mode": "24x7", "timezone": "UTC"},
            "reason": "Agreed investigation response target",
        },
    )
    assert response.status_code == 201, response.json


def test_completion_uses_created_cohort_without_mixing_old_closed_backlog(app, client, login_as, database, performance_clock):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("analyst")
    case(client, database, "Older case closed recently", "2026-09-01T08:00:00Z", status="closed", closed="2026-11-03T09:00:00Z")
    case(client, database, "Recent completed case", status="closed", closed="2026-11-03T09:00:00Z")
    case(client, database, "Recent active case")
    case(client, database, "Reopened case", status="reopened", closed="2026-11-03T09:00:00Z")
    case(client, database, "Cancelled case", status="cancelled")
    case(client, database, "Future timestamp", "2026-11-05T08:00:00Z")
    data = performance(client)
    assert data["counts"]["closed"] == 2
    assert data["completion"] == {"total": 3, "completed": 1, "pending": 2, "unmeasured": 0, "percentage": 33.3, "basis": "created_in_period"}
    historical = performance(client, "days=all")
    assert historical["completion"]["total"] == 4 and historical["completion"]["percentage"] == 50
    assert historical["speed"]["compliance_percent"] is None
    assert historical["speed"]["unmeasured"] == 2


@pytest.mark.parametrize("closed", [None, "not-a-time", "2026-11-01T07:00:00Z", "2030-01-01T00:00:00Z"])
def test_invalid_closure_never_claims_complete_or_zero_speed(app, client, login_as, database, performance_clock, closed):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("analyst")
    case(client, database, "Incomplete chronology", status="closed", closed=closed)
    data = performance(client)
    assert data["completion"] == {"total": 1, "completed": 0, "pending": 0, "unmeasured": 1, "percentage": None, "basis": "created_in_period"}
    assert data["speed"]["included"] == 0 and data["speed"]["compliance_percent"] is None


def test_completion_recalculates_when_closed_work_is_reopened_or_cancelled(app, client, login_as, database, performance_clock):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("analyst")
    identifier = case(client, database, "Reconsidered investigation", status="closed", closed="2026-11-03T09:00:00Z")
    assert performance(client)["completion"]["percentage"] == 100
    database.execute("UPDATE incident_cases SET status='reopened' WHERE id=?", (identifier,))
    assert performance(client)["completion"]["percentage"] == 0
    assert performance(client)["speed"]["included"] == 0
    database.execute("UPDATE incident_cases SET status='cancelled' WHERE id=?", (identifier,))
    assert performance(client)["completion"]["percentage"] is None
    assert performance(client)["completion"]["total"] == 0


def test_speed_uses_configured_working_time_and_retained_pauses(app, client, login_as, database, performance_clock):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("soc_manager")
    paused = case(client, database, "Paused evidence collection", "2026-11-03T08:00:00Z")
    policy(client, paused, 90)
    for action, stamp in [("pause", "2026-11-03T08:30:00Z"), ("resume", "2026-11-03T12:30:00Z")]:
        response = client.post(
            f"/api/cases/{paused}/sla/{action}",
            json={"version": client.get(f"/api/cases/{paused}").json["version"], "reason": "Authorized collection wait"},
        )
        assert response.status_code == 201, response.json
        payload = json.loads(database.execute("SELECT payload FROM autopsy_records WHERE id=?", (response.json["id"],)).fetchone()[0])
        payload["at"] = stamp
        database.execute("UPDATE autopsy_records SET payload=? WHERE id=?", (json.dumps(payload), response.json["id"]))
    database.execute("UPDATE incident_cases SET status='closed', closed_at='2026-11-03T13:00:00Z' WHERE id=?", (paused,))
    late = case(client, database, "Response exceeded target", "2026-11-03T08:00:00Z")
    policy(client, late, 60)
    database.execute("UPDATE incident_cases SET status='closed', closed_at='2026-11-03T10:00:00Z' WHERE id=?", (late,))
    working = case(client, database, "Weekend and holiday excluded", "2026-10-23T16:00:00Z")
    policy(
        client,
        working,
        120,
        {"mode": "business", "timezone": "UTC", "weekdays": [0, 1, 2, 3, 4], "start_hour": 9, "end_hour": 17, "holidays": ["2026-10-26"]},
    )
    database.execute("UPDATE incident_cases SET status='closed', closed_at='2026-10-27T10:00:00Z' WHERE id=?", (working,))
    case(client, database, "No agreed target", status="closed", closed="2026-11-03T09:00:00Z")
    data = performance(client, "member=team&days=30")
    assert data["speed"] == {"on_time": 2, "late": 1, "unmeasured": 1, "included": 3, "compliance_percent": 66.7, "basis": "configured_case_sla"}
    # The aggregate is consistent with the individual case's response clock.
    assert client.get(f"/api/cases/{paused}/workflow").json["sla"]["elapsed_work_seconds"] == 3600
    assert client.get(f"/api/cases/{working}/workflow").json["sla"]["remaining_work_seconds"] == 0
    recent = performance(client, "member=team&days=7")
    assert recent["speed"]["included"] == 2 and recent["speed"]["compliance_percent"] == 50


def test_speed_uses_latest_policy_but_does_not_measure_invalid_chronology(app, client, login_as, database, performance_clock):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("soc_manager")
    identifier = case(client, database, "Revised response target", "2026-11-03T08:00:00Z")
    policy(client, identifier, 30)
    policy(client, identifier, 120)
    database.execute("UPDATE incident_cases SET status='closed', closed_at='2026-11-03T10:00:00Z' WHERE id=?", (identifier,))
    assert performance(client)["speed"]["compliance_percent"] == 100
    database.execute("UPDATE incident_cases SET created_at='not-a-time' WHERE id=?", (identifier,))
    data = performance(client)
    assert data["speed"]["included"] == 0 and data["speed"]["unmeasured"] == 1
    assert data["completion"]["total"] == 0


def test_chart_data_obeys_member_selection_and_no_data_state(autopsy_case, app, client, login_as, database, user_ids, performance_clock):
    database.execute("UPDATE incident_cases SET created_at='2026-11-02T08:00:00Z' WHERE id=?", (autopsy_case,))
    assert performance(client)["completion"]["pending"] == 1
    assert client.get("/api/soc/performance?member=team").status_code == 403
    login_as("soc_manager")
    assert performance(client, f"member={user_ids['analyst']}")["completion"]["total"] == 1
    own = performance(client, "member=me")
    assert own["completion"]["total"] == 0 and own["completion"]["percentage"] is None
    assert own["speed"]["included"] == 0 and own["speed"]["compliance_percent"] is None
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    empty_scope = performance(client, "member=team")
    assert empty_scope["completion"]["total"] == 0 and empty_scope["speed"]["included"] == 0


def test_rounding_never_hides_the_last_pending_or_late_case(app, client, login_as, database, performance_clock):
    app.config["LEGACY_TRAINING_TESTS"] = False
    login_as("soc_manager")
    identifier = case(client, database, "Response boundary", "2026-11-03T08:00:00Z")
    policy(client, identifier, 60)
    database.execute("UPDATE incident_cases SET status='closed',closed_at='2026-11-03T09:00:00Z' WHERE id=?", (identifier,))
    # Bulk historical setup is isolated fixture data, never a claim of users or UI completions.
    database.execute("BEGIN")
    try:
        database.executemany(
            "INSERT INTO incident_cases(reference,workspace_id,title,status,assignee,creator,created_at,updated_at,closed_at) SELECT ?,workspace_id,title,status,assignee,creator,created_at,updated_at,closed_at FROM incident_cases WHERE id=?",
            [(f"metric-boundary-{index}", identifier) for index in range(1999)],
        )
        database.execute(
            "INSERT INTO autopsy_records(case_id,kind,payload,created_by,updated_by,created_at,updated_at) SELECT c.id,r.kind,r.payload,r.created_by,r.updated_by,r.created_at,r.updated_at FROM incident_cases c JOIN autopsy_records r ON r.case_id=? AND r.kind='workflow_sla' WHERE c.id>?",
            (identifier, identifier),
        )
        database.commit()
    except Exception:
        database.rollback()
        raise
    initial = performance(client)
    assert initial["completion"]["completed"] == initial["completion"]["total"] == 2000
    assert initial["speed"]["on_time"] == initial["speed"]["included"] == 2000
    assert initial["completion"]["percentage"] == initial["speed"]["compliance_percent"] == 100
    database.execute("UPDATE incident_cases SET status='draft',closed_at=NULL WHERE id=?", (identifier,))
    partial = performance(client)
    assert partial["completion"]["completed"] == 1999 and partial["completion"]["pending"] == 1
    assert partial["completion"]["percentage"] == 99.95
    database.execute("UPDATE incident_cases SET status='closed',closed_at='2026-11-03T10:00:00Z' WHERE id=?", (identifier,))
    late = performance(client)
    assert late["speed"]["on_time"] == 1999 and late["speed"]["late"] == 1 and late["speed"]["included"] == 2000
    assert late["speed"]["compliance_percent"] == 99.95
    database.execute("UPDATE incident_cases SET closed_at='2026-11-03T10:00:00Z' WHERE id>?", (identifier,))
    database.execute("UPDATE incident_cases SET closed_at='2026-11-03T09:00:00Z' WHERE id=?", (identifier,))
    low = performance(client)
    assert low["speed"]["on_time"] == 1 and low["speed"]["late"] == 1999 and low["speed"]["included"] == 2000
    assert low["speed"]["compliance_percent"] == 0.05
    database.execute("UPDATE incident_cases SET status='draft',closed_at=NULL WHERE id>?", (identifier,))
    one = performance(client)
    assert one["completion"]["completed"] == 1 and one["completion"]["pending"] == 1999 and one["completion"]["total"] == 2000
    assert one["completion"]["percentage"] == 0.05
    assert client.post("/api/cases", json={"title": "Outside the supported performance scope"}).status_code == 201
    assert client.get("/api/soc/performance").status_code == 422


@pytest.mark.parametrize("numerator,expected", [(1, 0.001), (99999, 99.999)])
def test_percentage_precision_is_safe_beyond_the_current_case_limit(numerator, expected):
    assert measured_percentage(numerator, 100000) == expected
    assert 0 < measured_percentage(numerator, 100000) < 100


def test_pending_task_case_context_never_crosses_case_batch_or_selection_scope(autopsy_case, app, client, login_as, user_ids):
    public = client.get(f"/api/cases/{autopsy_case}").json
    login_as("soc_manager")
    secret = client.post("/api/cases", json={"title": "Restricted identity investigation"}).json
    login_as("analyst")
    visible = performance(client)
    assert len(visible["tasks"]) == 2
    assert all(task["case_reference"] == public["reference"] and task["case_title"] == public["title"] for task in visible["tasks"])
    assert secret["title"] not in json.dumps(visible) and secret["reference"] not in json.dumps(visible)
    login_as("soc_manager")
    selected = performance(client, f"member={user_ids['analyst']}")
    assert all(task["case_id"] == autopsy_case and task["case_title"] == public["title"] for task in selected["tasks"])
    assert {task["case_reference"] for task in performance(client, "member=team")["tasks"]} == {public["reference"], secret["reference"]}
    imported = client.post(f"/api/cases/{autopsy_case}/imports", json={"filename": "restricted.json", "content": '[{"title":"Restricted retained evidence"}]'})
    assert imported.status_code == 201
    assert (
        client.put(
            f"/api/cases/{autopsy_case}/imports/{imported.json['id']}/access",
            json={"restricted": True, "members": [], "reason": "Restrict sensitive collection"},
        ).status_code
        == 200
    )
    login_as("analyst")
    restricted = performance(client)
    assert restricted["tasks"] == []
    assert public["title"] not in json.dumps(restricted) and secret["title"] not in json.dumps(restricted)
    login_as("soc_manager")
    app.config["REQUIRE_INVESTIGATION_SELECTION"] = True
    assert performance(client, "member=team")["tasks"] == []
