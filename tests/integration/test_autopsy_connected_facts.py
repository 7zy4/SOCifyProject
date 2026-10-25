import json
from datetime import UTC, datetime

from socify.autopsy_scope import investigation_scope
from socify.autopsy_worker import run_autopsy_worker_once


def test_evidenced_scope_ioc_branching_cause_corrective_and_war_room_share_report(autopsy_case, app, client):
    base = f"/api/cases/{autopsy_case}"
    assert (
        client.post(
            base + "/imports", json={"filename": "facts.json", "content": '[{"title":"Retained scope evidence","source_ip":"2001:db8::1"}]'}
        ).status_code
        == 201
    )
    evidence = client.get(base).json["evidence"][0]["id"]
    actor = client.get("/api/auth/me").json["user"]["id"]
    assets = []
    for index, assessment in enumerate(("confirmed", "suspected", "checked_clear", "unexamined")):
        created = client.post(
            base + "/records/asset",
            json={
                "name": f"Scoped internal asset {index}",
                "type": "web_server" if index == 0 else "workstation",
                "role": "defender",
                "owner": "Internal infrastructure team",
                "assessment": assessment,
            },
        )
        assert created.status_code == 201, created.json
        assets.append(created.json["id"])
    indicator = {"type": "ip", "value": "2001:0db8::1", "classification": "observable", "source": "Retained scope evidence", "confidence": 60}
    created = client.post(base + "/records/indicator", json=indicator)
    assert created.status_code == 201
    assert client.post(base + "/records/indicator", json={**indicator, "value": "2001:db8::1"}).status_code == 409
    promoted = client.patch(
        base + f"/records/{created.json['id']}",
        json={"version": 1, "payload": {**indicator, "classification": "ioc", "confidence": 90, "evidence_id": evidence}},
    )
    assert promoted.status_code == 200 and promoted.json["payload"]["value"] == "2001:db8::1"
    foothold = client.post(
        base + "/records/foothold",
        json={
            "title": "Earliest retained observation",
            "asset_id": assets[0],
            "evidence_id": evidence,
            "first_observed_at": "2026-10-20T10:00:00Z",
            "confidence": 70,
            "limitations": "Retained records do not establish the original compromise",
        },
    )
    assert foothold.status_code == 201
    whys = [
        {
            "id": "root",
            "question": "Why scope?",
            "answer": "Retained evidence supports the observed configuration",
            "assessment": "supported",
            "evidence_id": evidence,
        },
        {
            "id": "branch",
            "parent_id": "root",
            "question": "Why retention gap?",
            "answer": "Retention policy remains an unverified contributing factor",
            "assessment": "hypothesis",
        },
    ]
    cause = client.post(
        base + "/records/root_cause",
        json={"category": "misconfiguration", "conclusion": "Configuration finding supported within the retained scope", "evidence_id": evidence, "whys": whys},
    )
    assert cause.status_code == 201, cause.json
    corrective = {
        "title": "Validate the retention policy",
        "owner_id": actor,
        "due_at": "2026-11-01T00:00:00Z",
        "status": "open",
        "root_cause_id": cause.json["id"],
        "why_id": "branch",
    }
    assert client.post(base + "/records/corrective", json={**corrective, "why_id": "foreign"}).status_code == 422
    assert client.post(base + "/records/corrective", json=corrective).status_code == 201
    task = client.post(f"/api/incidents/{autopsy_case}/tasks", json={"title": "Verify approved retention action", "required": True, "assignee": actor})
    assert task.status_code == 201
    decision = {
        "title": "Evidence-based team decision",
        "body": "Keep the investigation limited to retained sources",
        "decision": "Request the missing original collection before attributing initial access",
        "visibility": "team",
        "task_id": task.json["id"],
        "evidence_id": evidence,
    }
    assert client.post(base + "/records/war_room", json={**decision, "task_id": True}).status_code == 422
    assert client.post(base + "/records/war_room", json={**decision, "task_id": 999999}).status_code == 422
    assert client.post(base + "/records/war_room", json=decision).status_code == 201
    assert client.post(base + "/records/war_room", json={**decision, "visibility": "private", "body": "PRIVATE_CONNECTED_FACT_NOT_EXPORTED"}).status_code == 201
    scope = client.get(base + "/workflow").json["scope"]
    assert scope["counts_by_assessment"] == {"confirmed": 1, "suspected": 1, "checked_clear": 1, "unexamined": 1, "undetermined": 0}
    assert scope["earliest_retained_observation"]["asset_id"] == assets[0]
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
    assert report.status_code == 202
    snapshot = client.get(base + f"/reports/{report.json['id']}").json["payload"]
    assert snapshot["scope"] == scope
    assert "PRIVATE_CONNECTED_FACT_NOT_EXPORTED" not in json.dumps(snapshot)
    assert snapshot["records"]["war_room"][0]["payload"]["task_id"] == task.json["id"]
    assert snapshot["records"]["war_room"][0]["payload"]["evidence_id"] == evidence
    assert snapshot["records"]["corrective"][0]["payload"]["why_id"] == "branch"
    with app.app_context():
        assert run_autopsy_worker_once("connected-report-facts") == report.json["job_id"]
    markdown = client.get(base + f"/reports/{report.json['id']}/files/md").text
    assert "نطاق الفحص وحدود الاستنتاج" in markdown
    assert "المهمة المرتبطة" in markdown and decision["decision"] in markdown
    assert "PRIVATE_CONNECTED_FACT_NOT_EXPORTED" not in markdown
    assert client.get(base + "/custody").json["integrity_valid"] is True


def test_scope_does_not_invent_patient_zero_or_merge_untested_hosts():
    result = investigation_scope(
        {
            "asset": [{"name": "same name"}, {"name": "same name", "assessment": "unexamined"}],
            "foothold": [
                {"first_observed_at": "2030-01-01T00:00:00Z", "evidence_id": 1, "asset_id": 1},
                {"first_observed_at": "invalid"},
                {"first_observed_at": "2026-10-20T00:00:00Z"},
            ],
        },
        datetime(2026, 10, 25, tzinfo=UTC),
    )
    assert result["asset_records"] == 2
    assert result["counts_by_assessment"]["undetermined"] == 1
    assert result["counts_by_assessment"]["unexamined"] == 1
    assert result["earliest_retained_observation"] is None and result["excluded_observations"] == 3
