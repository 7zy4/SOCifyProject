import secrets
from datetime import UTC, datetime

import pytest

from socify.autopsy_workflow import business_seconds, factual_metrics, validate_calendar
from socify.security import password_error, totp_code


def version(client, base):
    return client.get(base).json["version"]


def test_sla_pause_resume_and_team_metrics_scope(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    assert client.get(base + "/workflow").json["sla"]["configured"] is False
    assert client.post(base + "/sla", json={}).status_code == 403
    login_as("soc_manager")
    policy = {
        "version": version(client, base),
        "minutes": 60,
        "calendar": {"mode": "business", "timezone": "Asia/Riyadh", "weekdays": [6, 0, 1, 2, 3], "start_hour": 9, "end_hour": 17, "holidays": []},
        "reason": "Internal review service window",
    }
    configured = client.post(base + "/sla", json=policy)
    assert configured.status_code == 201, configured.json
    assert client.post(base + "/sla", json=policy).status_code == 422
    status = client.get(base + "/workflow").json["sla"]
    assert status["configured"] and status["status"] in {"running", "breached"}
    assert client.post(base + "/sla/pause", json={"version": version(client, base), "reason": "Waiting on authorized evidence collection"}).status_code == 201
    assert client.get(base + "/workflow").json["sla"]["status"] == "paused"
    assert client.post(base + "/sla/pause", json={"version": version(client, base), "reason": "Already paused"}).status_code == 409
    assert client.post(base + "/sla/resume", json={"version": version(client, base), "reason": "Evidence collection resumed"}).status_code == 201
    assert client.post(base + "/sla/invalid", json={}).status_code == 404
    metrics = client.get("/api/workflow/metrics").json
    assert metrics["visible_cases"] == 1 and metrics["sampled_cases"] == 1
    assert metrics["metrics"]["detection_delay_seconds"]["mean_seconds"] is None
    job = client.post(base + "/imports", json={"filename": "private.json", "content": '[{"title":"Restricted collection"}]'}).json
    assert (
        client.put(
            base + f"/imports/{job['id']}/access", json={"restricted": True, "members": [], "reason": "Limit disclosure to assigned batch analysts"}
        ).status_code
        == 200
    )
    login_as("analyst")
    result = client.get("/api/workflow/metrics").json
    assert result["excluded_batch_scope"] == 1
    assert not result["metrics"]


@pytest.mark.parametrize(
    "calendar",
    [
        {},
        {"mode": []},
        {"mode": "business", "timezone": "Unknown/Zone"},
        {"mode": "business", "weekdays": [True], "start_hour": 9, "end_hour": 17},
        {"mode": "business", "weekdays": [0, 0], "start_hour": 9, "end_hour": 17},
        {"mode": "business", "weekdays": [0], "start_hour": 18, "end_hour": 17},
        {"mode": "business", "weekdays": [0], "start_hour": 9, "end_hour": 17, "holidays": ["2026-02-30"]},
        {"mode": "24x7", "unexpected": True},
    ],
)
def test_sla_calendar_rejects_invalid_input(calendar):
    with pytest.raises(ValueError):
        validate_calendar(calendar)


def test_sla_working_hours_holidays_dst_and_unknown_metrics():
    calendar = validate_calendar(
        {"mode": "business", "timezone": "UTC", "weekdays": [0, 1, 2, 3, 4], "start_hour": 9, "end_hour": 17, "holidays": ["2026-10-26"]}
    )
    start, end = datetime(2026, 10, 23, 16, tzinfo=UTC), datetime(2026, 10, 27, 10, tzinfo=UTC)
    assert business_seconds(start, end, calendar) == 7200
    assert business_seconds(end, start, calendar) == 0
    dst = validate_calendar({"mode": "business", "timezone": "America/New_York", "weekdays": [6], "start_hour": 0, "end_hour": 4})
    assert business_seconds(datetime(2026, 11, 1, 4, tzinfo=UTC), datetime(2026, 11, 1, 9, tzinfo=UTC), dst) == 5 * 3600
    now = datetime(2026, 10, 25, tzinfo=UTC)
    records = {
        "foothold": [{"evidence_id": 1, "first_observed_at": "2026-10-24T10:00:00Z"}],
        "response": [
            {"phase": "detection", "status": "succeeded", "evidence_id": 1, "performed_at": "2026-10-24T10:05:00Z"},
            {"phase": "containment", "status": "succeeded", "evidence_id": 1, "performed_at": "2026-10-24T09:00:00Z"},
            {"phase": "recovery", "status": "succeeded", "evidence_id": 1, "performed_at": "2030-01-01T00:00:00Z"},
        ],
    }
    result = factual_metrics({"closed_at": None}, records, now)
    assert result["detection_delay_seconds"] == 300
    assert result["containment_delay_seconds"] is None and result["recovery_delay_seconds"] is None
    assert any("negative" in item for item in result["issues"])
    assert any("future" in item for item in result["issues"])


def test_collection_authorization_evidence_and_postmortem_independent_review(autopsy_case, client, login_as, user_ids, database):
    base = f"/api/cases/{autopsy_case}"
    request = {
        "version": version(client, base),
        "recipe_id": "windows_auth",
        "collector_id": user_ids["analyst"],
        "reason": "Collect retained logs for scope review",
    }
    created = client.post(base + "/collections", json=request)
    assert created.status_code == 201, created.json
    path = base + f"/collections/{created.json['id']}"
    assert (
        client.post(path + "/approve", json={"version": 1, "case_version": version(client, base), "reason": "Unauthorized analyst approval"}).status_code == 403
    )
    assert client.post(path + "/document", json={"version": 1, "case_version": version(client, base)}).status_code == 409
    login_as("soc_manager")
    assert (
        client.post(path + "/approve", json={"version": 1, "case_version": version(client, base), "reason": "Approved retained Windows scope"}).status_code
        == 200
    )
    login_as("analyst")
    assert client.post(base + "/imports", json={"filename": "retained.json", "content": '[{"title":"Authorized collection evidence"}]'}).status_code == 201
    evidence = client.get(base).json["evidence"][0]["id"]
    documented = client.post(
        path + "/document",
        json={
            "version": 2,
            "case_version": version(client, base),
            "evidence_id": evidence,
            "tool": "Synthetic approved collector/1",
            "collected_at": "2026-10-24T10:00:00Z",
            "source": "Internal retained export",
            "artifacts": ["security_evtx"],
        },
    )
    assert documented.status_code == 200, documented.json
    assert documented.json["payload"]["state"] == "documented_with_gaps"
    assert "sysmon_evtx" in documented.json["payload"]["missing_artifacts"]
    assert client.post(base + "/postmortems", json={"version": version(client, base)}).status_code == 409
    database.execute("UPDATE incident_cases SET status='awaiting_review' WHERE id=?", (autopsy_case,))
    client.post(base + "/records/war_room", json={"title": "Private", "body": "Private postmortem exclusion fixture", "visibility": "private"})
    postmortem = client.post(base + "/postmortems", json={"version": version(client, base)})
    assert postmortem.status_code == 201
    assert "Private postmortem exclusion fixture" not in str(postmortem.json)
    login_as("soc_manager")
    review = {
        "version": 1,
        "case_version": version(client, base),
        "executive_summary": "Synthetic evidence review completed",
        "lessons": "Retain complete source exports before triage",
        "limitations": "Synthetic fixture coverage only",
    }
    reviewed = client.post(base + f"/postmortems/{postmortem.json['id']}/review", json=review)
    assert reviewed.status_code == 200, reviewed.json
    assert reviewed.json["payload"]["state"] == "reviewed"
    assert client.post(base + f"/postmortems/{postmortem.json['id']}/review", json={**review, "case_version": version(client, base)}).status_code == 409


def test_root_cause_branching_requires_evidence_and_rejects_cycles(autopsy_case, client):
    base = f"/api/cases/{autopsy_case}"
    whys = [
        {"id": "root", "question": "Why access?", "answer": "Hypothesis pending collection", "assessment": "hypothesis"},
        {"id": "child", "parent_id": "root", "question": "Why credentials?", "answer": "Unverified credential source", "assessment": "unverified"},
    ]
    payload = {"category": "unknown", "conclusion": "Insufficient retained evidence", "whys": whys}
    created = client.post(base + "/records/root_cause", json=payload)
    assert created.status_code == 201
    assert created.json["payload"]["whys"][1]["parent_id"] == "root"
    for changes in (
        [{**whys[0], "parent_id": "child"}, whys[1]],
        [{**whys[0], "assessment": "supported"}],
        [whys[0], {**whys[1], "id": "root"}],
        [{**whys[0], "parent_id": "missing"}],
    ):
        assert client.post(base + "/records/root_cause", json={**payload, "whys": changes}).status_code == 422
    assert password_error("Unicode-surrogate-\ud800-test") is not None


def test_operational_mfa_requires_password_status_does_not_leak_secret_and_recovery_one_use(autopsy_case, client):
    assert client.get("/api/auth/mfa/status").json["enabled"] is False
    assert client.post("/api/auth/mfa/enroll", json={}).status_code == 403
    assert client.post("/api/auth/mfa/enroll", json={"current_password": secrets.token_urlsafe(20)}).status_code == 403
    enrolled = client.post("/api/auth/mfa/enroll", json={"current_password": "Training-Safe-Password-2026!"})
    assert enrolled.status_code == 200
    status = client.get("/api/auth/mfa/status").json
    assert status["pending"] and "secret" not in status
    enabled = client.post("/api/auth/mfa/verify", json={"code": totp_code(enrolled.json["secret"])})
    assert enabled.status_code == 200
    assert client.get("/api/auth/mfa/status").json["recovery_codes_remaining"] == 10
    assert client.post("/api/auth/mfa/enroll", json={"current_password": "Training-Safe-Password-2026!"}).status_code == 409
    disabled = client.delete("/api/auth/mfa", json={"current_password": "Training-Safe-Password-2026!", "code": enabled.json["backup_codes"][0]})
    assert disabled.status_code == 204
    assert client.get("/api/auth/mfa/status").json["enabled"] is False


def test_operational_mfa_login_requires_factor_and_recovery_code_is_single_use(autopsy_case, app, client, database):
    enrolled = client.post("/api/auth/mfa/enroll", json={"current_password": "Training-Safe-Password-2026!"}).json
    enabled = client.post("/api/auth/mfa/verify", json={"code": totp_code(enrolled["secret"])}).json
    browser = app.test_client()
    credentials = {"email": "analyst@socify.local", "password": "Training-Safe-Password-2026!"}
    required = browser.post("/api/auth/login", json=credentials)
    assert required.status_code == 428 and required.json["error"]["code"] == "MFA_REQUIRED"
    assert browser.post("/api/auth/login", json={**credentials, "mfa_code": "invalid"}).status_code == 401
    code = enabled["backup_codes"][0]
    assert browser.post("/api/auth/login", json={**credentials, "mfa_code": code}).status_code == 200
    sessions = browser.get("/api/auth/sessions").json["items"]
    assert sessions[0]["is_current"] is True and "session_hash" not in sessions[0]
    assert browser.get("/api/auth/mfa/status").json["recovery_codes_remaining"] == 9
    assert browser.post("/api/auth/login", json={**credentials, "mfa_code": code}).status_code == 401
    assert code not in str(database.execute("SELECT code_hash FROM mfa_backup_codes").fetchall())
    assert enrolled["secret"] not in str(database.execute("SELECT secret_ciphertext FROM mfa_enrollments").fetchall())
