import base64
import hashlib
import io
import json
import sqlite3

import pytest
from test_autopsy_teams import new_member, switch

from socify.autopsy_worker import run_autopsy_worker_once
from socify.autopsy_yara import validate_input


def rule_pack():
    return {
        "name": "Internal synthetic signatures",
        "version": 1,
        "origin": "Internal fixture repository",
        "license": "Synthetic test permission",
        "source": 'rule Local_Test { strings: $a = "SOCIFY_SYNTHETIC_FINDING" condition: $a }',
        "fixtures": {
            "positive": [base64.b64encode(b"SOCIFY_SYNTHETIC_FINDING").decode()],
            "negative": [base64.b64encode(b"unrelated synthetic bytes").decode()],
        },
    }


def test_local_yara_pack_isolated_publish_snapshot_sample_and_report(autopsy_case, app, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    payload = rule_pack()
    assert client.post("/api/autopsy/yara", json=payload).status_code == 403
    login_as("soc_manager")
    published = client.post("/api/autopsy/yara", json=payload)
    assert published.status_code == 201, published.json
    pack = published.json
    assert pack["validation"]["isolation"]["syscalls"] == "linux-seccomp"
    assert pack["validation"]["fixtures_passed"] == {"positive": 1, "negative": 1}
    assert pack["sha256"] == hashlib.sha256(payload["source"].encode()).hexdigest()
    assert client.post("/api/autopsy/yara", json=payload).status_code == 409
    broken = {**payload, "version": 2, "source": "rule Invalid { condition: broken syntax }"}
    assert client.post("/api/autopsy/yara", json=broken).status_code == 422
    wrong_fixture = {**payload, "version": 2, "fixtures": {**payload["fixtures"], "negative": payload["fixtures"]["positive"]}}
    assert client.post("/api/autopsy/yara", json=wrong_fixture).status_code == 422
    includes = {**payload, "version": 2, "source": 'include "/etc/passwd"\n' + payload["source"]}
    assert client.post("/api/autopsy/yara", json=includes).status_code == 422
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute("UPDATE autopsy_yara_packs SET source='tampered' WHERE id=?", (pack["id"],))
    sample = client.post(base + "/samples", data={"file": (io.BytesIO(b"SOCIFY_SYNTHETIC_FINDING"), "synthetic.bin")})
    assert sample.status_code == 201
    path = base + f"/samples/{sample.json['id']}/analyze"
    assert client.post(path, json={"yara_pack_id": True}).status_code == 422
    assert client.post(path, json={"yara_pack_id": 999999}).status_code == 404
    queued = client.post(path, json={"yara_pack_id": pack["id"]})
    assert queued.status_code == 202
    assert client.post(path, json={}).status_code == 409
    assert client.post(path, json={"yara_pack_id": pack["id"]}).json["duplicate"] is True
    newer = client.post("/api/autopsy/yara", json={**payload, "version": 2})
    assert newer.status_code == 201
    with app.app_context():
        assert run_autopsy_worker_once("yara-versioned-check") == queued.json["id"]
    status = client.get(base + f"/jobs/{queued.json['id']}").json
    assert status["state"] == "completed", status
    result = client.get(base + "/records?kind=analysis").json["items"][0]["payload"]
    assert result["yara_pack"]["id"] == pack["id"] and result["yara_pack"]["version"] == 1
    assert result["yara_rules_sha256"] == pack["sha256"]
    assert result["yara_matches"][0]["rule"] == "Local_Test"
    report = client.post(base + "/reports", json={"version": client.get(base).json["version"], "profile": "full"})
    assert report.status_code == 202
    snapshot = json.loads(database.execute("SELECT payload FROM autopsy_reports WHERE id=?", (report.json["id"],)).fetchone()[0])
    assert "Internal synthetic signatures" in json.dumps(snapshot)


@pytest.mark.parametrize(
    "change",
    [
        {"version": True},
        {"version": 0},
        {"name": ""},
        {"source": "x" * 65537},
        {"source": "\ud800"},
        {"license": None},
        {"unknown": "field"},
        {"fixtures": []},
        {"fixtures": {"positive": [], "negative": []}},
        {"fixtures": {"positive": ["%invalid"], "negative": ["eA=="]}},
        {"fixtures": {"positive": [""], "negative": ["eA=="]}},
    ],
)
def test_local_yara_input_rejects_ambiguous_unbounded_or_unlicensed_packs(change):
    with pytest.raises((ValueError, UnicodeError)):
        validate_input({**rule_pack(), **change})


def test_shift_handoff_preserves_accounts_prior_actions_and_transfers_pending_work(autopsy_case, client, database, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    replacement = new_member(database, user_ids["analyst"], "investigator", "next.shift@internal.test")
    login_as("soc_manager")
    job = client.post(base + "/imports", json={"filename": "shift.json", "content": '[{"title":"Retained shift source"}]'}).json
    assert (
        client.put(
            base + f"/imports/{job['id']}/access", json={"restricted": True, "members": [user_ids["analyst"]], "reason": "Shift evidence scope"}
        ).status_code
        == 200
    )
    task = client.post(
        f"/api/incidents/{autopsy_case}/tasks", json={"title": "Complete retained log review", "required": True, "assignee": user_ids["analyst"]}
    ).json
    escalation = client.post(
        base + "/records/escalation",
        json={
            "to_user": user_ids["analyst"],
            "from_level": "management",
            "to_level": "l1",
            "reason": "Investigate retained source",
            "priority": "high",
            "status": "raised",
        },
    )
    assert escalation.status_code == 201
    payload = {
        "from_user": user_ids["analyst"],
        "to_user": replacement,
        "version": client.get(base).json["version"],
        "reason": "Scheduled end-of-shift handoff with retained evidence",
    }
    assert client.post(base + "/handoff", json={**payload, "to_user": user_ids["auditor"]}).status_code == 422
    assert client.post(base + "/handoff", json={**payload, "version": 1}).status_code == 409
    result = client.post(base + "/handoff", json=payload)
    assert result.status_code == 200, result.json
    assert result.json["previous_access"] == "retained"
    assert database.execute("SELECT is_active FROM users WHERE id=?", (user_ids["analyst"],)).fetchone()[0] == 1
    assert database.execute("SELECT assignee FROM case_tasks WHERE id=?", (task["id"],)).fetchone()[0] == replacement
    previous = client.get(base + "/records?kind=escalation").json["items"]
    assert previous[0]["payload"]["to_user"] == replacement
    assert previous[1]["payload"]["to_user"] == user_ids["analyst"] and previous[1]["payload"]["status"] == "returned"
    assert database.execute("SELECT payload FROM autopsy_record_revisions WHERE record_id=? AND version=1", (escalation.json["id"],)).fetchone()
    switch(client, replacement)
    assert client.get(base + "/logs").json["total"] == 1
    assert client.patch(f"/api/incidents/{autopsy_case}/tasks/{task['id']}", json={"status": "completed"}).status_code == 200
    login_as("analyst")
    assert client.get(base).status_code == 200
    assert client.post(base + "/handoff", json=payload).status_code == 403


def test_yara_backend_failure_and_untrusted_digest_never_publish(autopsy_case, client, login_as, monkeypatch):
    login_as("soc_manager")

    def unavailable(*args, **kwargs):
        raise TimeoutError("Synthetic isolated backend unavailable")

    monkeypatch.setattr("socify.autopsy_yara.compute_artifacts", unavailable)
    assert client.post("/api/autopsy/yara", json=rule_pack()).status_code == 503
    monkeypatch.setattr("socify.autopsy_yara.compute_artifacts", lambda *args, **kwargs: {"validation": b'{"valid":true,"sha256":"incorrect"}'})
    assert client.post("/api/autopsy/yara", json=rule_pack()).status_code == 503
    assert client.get("/api/autopsy/yara").json["items"] == []


@pytest.mark.parametrize("change", [{"reason": ""}, {"from_user": True}, {"version": -1}, {"to_user": None}, {"unknown": "field"}])
def test_shift_handoff_invalid_input_cannot_change_membership(autopsy_case, client, login_as, user_ids, change):
    login_as("soc_manager")
    base = f"/api/cases/{autopsy_case}"
    before = client.get(base).json
    payload = {"from_user": user_ids["analyst"], "to_user": user_ids["soc_manager"], "reason": "Scheduled shift transfer", "version": before["version"]}
    assert client.post(base + "/handoff", json={**payload, **change}).status_code == 422
    assert client.get(base).json["members"] == before["members"]
    assert client.get(base).json["version"] == before["version"]
