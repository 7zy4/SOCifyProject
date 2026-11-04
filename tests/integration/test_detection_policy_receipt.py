"""Execution-time detection policies remain attributable without exposing rule content."""

import copy
import hashlib
import io
import json
import sqlite3
from datetime import timedelta

import pytest

from socify import autopsy_detection, autopsy_worker
from socify.autopsy_detection import _execution_rules, _rule_policy_fingerprint
from socify.autopsy_domain import canonical
from socify.autopsy_worker import run_autopsy_worker_once
from socify.timeutils import parse_timestamp

ORIGINAL = "Receipt original marker"
REVISED = "Receipt revised marker"


def publish(client, phrase, previous=None):
    source = f"title: Internal policy test\nlogsource:\n  category: socify_normalized\ndetection:\n  selected:\n    title|contains: {phrase}\n  condition: selected\nlevel: high\n"
    payload = {
        "source": source,
        "fixtures": {"positive": [{"title": phrase}], "negative": [{"title": "Routine evidence"}]},
        "reason": "Isolated receipt acceptance",
    }
    if previous:
        payload.update(rule_id=previous["id"], version=previous["version"])
    response = client.post("/api/autopsy/sigma/publish", json=payload)
    assert response.status_code == 201, response.json
    return response.json


def import_events(client, case):
    response = client.post(
        f"/api/cases/{case}/imports",
        json={"filename": "receipt.json", "content": json.dumps([{"title": ORIGINAL + " one"}, {"title": ORIGINAL + " two"}])},
    )
    assert response.status_code == 201, response.json


def queue(client, case, mode="rules"):
    base = f"/api/cases/{case}"
    response = client.post(base + "/detection", json={"version": client.get(base).json["version"], "mode": mode})
    assert response.status_code == 202, response.json
    return response.json["id"]


def execute(app, client, case, identifier):
    with app.app_context():
        assert run_autopsy_worker_once() == identifier
    job = client.get(f"/api/cases/{case}/jobs/{identifier}").json
    assert job["state"] == "completed", job
    records = client.get(f"/api/cases/{case}/records?kind=analysis").json["items"]
    return job, next(row for row in records if row["id"] == job["result_record_id"])


def receipt(database, case, identifier):
    rows = database.execute("SELECT * FROM autopsy_custody WHERE case_id=? AND action='detection' ORDER BY id", (case,)).fetchall()
    row = next(dict(row) for row in rows if json.loads(row["details"])["job_id"] == identifier)
    return row, json.loads(row["details"])


def fingerprint(app):
    with app.app_context():
        return _rule_policy_fingerprint(_execution_rules(1, False))


def test_queued_rule_change_binds_actual_execution_and_later_edits_do_not_rewrite_receipt(autopsy_case, app, client, database, login_as, user_ids):
    case = autopsy_case
    import_events(client, case)
    login_as("soc_manager")
    first = publish(client, ORIGINAL)
    original_fingerprint = fingerprint(app)
    login_as("analyst")
    identifier = queue(client, case)
    queued = json.loads(database.execute("SELECT parameters FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()[0])
    login_as("soc_manager")
    revised = publish(client, REVISED, first)
    revised_fingerprint = fingerprint(app)
    assert revised_fingerprint != original_fingerprint
    login_as("analyst")
    job, result = execute(app, client, case, identifier)
    retained, details = receipt(database, case, identifier)
    assert details["policy_sha256"] == revised_fingerprint
    assert details["attempt"] == job["attempts"] == 1
    assert result["payload"]["evaluated_events"] == 2 and result["payload"]["alert_ids"] == []
    assert not any("policy" in field or "receipt" in field for field in result["payload"])
    events = database.execute(
        "SELECT id FROM security_events WHERE owner_case_id=? AND autopsy_active=1 AND source!='rules_engine' ORDER BY id", (case,)
    ).fetchall()
    assert details["scope"] == {
        "case_version": queued["case_version"],
        "after_id": 0,
        "through_id": queued["through_id"],
        "evaluated_events": 2,
        "event_ids_sha256": hashlib.sha256(canonical([row[0] for row in events]).encode()).hexdigest(),
    }
    assert set(details) == {"job_id", "attempt", "policy_sha256", "rule_count", "scope"}
    assert ORIGINAL not in retained["details"] and REVISED not in retained["details"] and "Internal policy test" not in retained["details"]
    audit = database.execute(
        "SELECT * FROM security_audit_logs WHERE resource_type='autopsy_case' AND resource_id=? AND action='detection'", (str(case),)
    ).fetchone()
    assert json.loads(audit["details"]) == details and audit["actor_id"] == user_ids["analyst"] and audit["workspace_id"] == 1
    assert client.get("/api/audit?action=detection").status_code == 403
    login_as("soc_manager")
    assert client.get("/api/audit?action=detection").json["items"][0]["id"] == audit["id"]
    publish(client, ORIGINAL, revised)
    assert fingerprint(app) != revised_fingerprint
    assert receipt(database, case, identifier)[0] == retained
    assert client.post(f"/api/cases/{case}/jobs/{identifier}/retry").status_code == 409
    second = queue(client, case)
    _, later_result = execute(app, client, case, second)
    assert len(later_result["payload"]["alert_ids"]) == 2
    assert receipt(database, case, second)[1]["policy_sha256"] != revised_fingerprint
    assert receipt(database, case, identifier)[0] == retained
    original_record = next(row for row in client.get(f"/api/cases/{case}/records?kind=analysis").json["items"] if row["id"] == result["id"])
    assert original_record == result
    assert client.get(f"/api/cases/{case}/custody").json["integrity_valid"]
    login_as("auditor")
    for suffix in ("custody", "records?kind=analysis", f"jobs/{identifier}"):
        assert client.get(f"/api/cases/{case}/{suffix}").status_code == 404


def policy_rows():
    return [
        {
            "id": number,
            "workspace_id": 1,
            "name": f"Internal {number}",
            "version": 1,
            "condition_type": "dsl",
            "condition_value": '{"z":2,"a":1}',
            "dsl_json": '{"b":[1,2],"a":true}',
            "action_type": "create_alert",
            "action_value": '{"severity":"high","confidence":0.8}',
            "match_count": 0,
        }
        for number in (21, 42)
    ]


def test_fingerprint_ignores_row_order_object_key_order_and_operational_counters():
    source = policy_rows()
    equivalent = copy.deepcopy(source[::-1])
    for row in equivalent:
        for key in ("condition_value", "dsl_json", "action_value"):
            row[key] = json.dumps(dict(reversed(list(json.loads(row[key]).items()))), indent=2)
        row.update(match_count=999, average_evaluation_ms=1.23, last_triggered_at="2030-01-01T00:00:00Z")
    assert _rule_policy_fingerprint(source) == _rule_policy_fingerprint(equivalent)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 22),
        ("workspace_id", 2),
        ("name", "Changed output identity"),
        ("version", 2),
        ("condition_type", "error_level"),
        ("condition_value", '{"level":"critical"}'),
        ("dsl_json", '{"b":[2,1],"a":true}'),
        ("action_type", "changed"),
        ("action_value", '{"severity":"critical","confidence":0.8}'),
    ],
)
def test_fingerprint_changes_when_rule_identity_or_decision_facts_change(field, value):
    source = policy_rows()
    changed = copy.deepcopy(source)
    changed[0][field] = value
    assert _rule_policy_fingerprint(source) != _rule_policy_fingerprint(changed)


def test_inactive_archived_and_foreign_rules_do_not_change_selected_policy(autopsy_case, app, database, user_ids):
    before = fingerprint(app)
    foreign = database.execute("INSERT INTO training_workspaces(public_id,name,created_at) VALUES ('receipt-other','Other','2026-11-04T00:00:00Z')").lastrowid
    identifiers = []
    for name, owner, active, archived in (
        ("Inactive private", 1, 0, None),
        ("Archived private", 1, 1, "2026-11-04T00:00:00Z"),
        ("Foreign private", foreign, 1, None),
    ):
        identifiers.append(
            database.execute(
                "INSERT INTO rules(name,workspace_id,is_active,archived_at,created_by,created_at) VALUES (?,?,?,?,?,'2026-11-04T00:00:00Z')",
                (name, owner, active, archived, user_ids["soc_manager"]),
            ).lastrowid
        )
    assert fingerprint(app) == before
    database.execute("UPDATE rules SET is_active=1 WHERE id=?", (identifiers[0],))
    assert fingerprint(app) != before


def test_lazy_builtin_initialization_is_included_in_execution_receipt(autopsy_case, app, client, database):
    import_events(client, autopsy_case)
    database.execute("UPDATE rules SET archived_at='2026-11-04T00:00:00Z' WHERE workspace_id=1 AND name LIKE '[SOCify]%'")
    before = fingerprint(app)
    identifier = queue(client, autopsy_case)
    execute(app, client, autopsy_case, identifier)
    _, details = receipt(database, autopsy_case, identifier)
    assert details["policy_sha256"] == fingerprint(app) != before
    assert details["rule_count"] == database.execute("SELECT COUNT(*) FROM rules WHERE workspace_id=1 AND is_active=1 AND archived_at IS NULL").fetchone()[0]


def test_empty_scan_has_empty_event_scope_and_anomaly_does_not_claim_a_rule_policy(autopsy_case, app, client, database):
    identifier = queue(client, autopsy_case)
    execute(app, client, autopsy_case, identifier)
    _, details = receipt(database, autopsy_case, identifier)
    assert details["scope"]["evaluated_events"] == 0
    assert details["scope"]["event_ids_sha256"] == hashlib.sha256(b"[]").hexdigest()
    second = queue(client, autopsy_case, "anomaly")
    execute(app, client, autopsy_case, second)
    assert database.execute("SELECT COUNT(*) FROM autopsy_custody WHERE case_id=? AND action='detection'", (autopsy_case,)).fetchone()[0] == 1


def test_revoked_access_cannot_create_a_policy_receipt(autopsy_case, app, client, database, user_ids):
    identifier = queue(client, autopsy_case)
    database.execute("UPDATE users SET is_active=0 WHERE id=?", (user_ids["analyst"],))
    with app.app_context():
        run_autopsy_worker_once()
    assert database.execute("SELECT error_code FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()[0] == "ACCESS_REVOKED"
    assert not database.execute("SELECT 1 FROM autopsy_custody WHERE case_id=? AND action='detection'", (autopsy_case,)).fetchone()
    assert not database.execute("SELECT 1 FROM security_audit_logs WHERE action='detection'").fetchone()


def test_policy_and_evaluation_share_the_write_lock(autopsy_case, app, client, database, login_as, monkeypatch):
    import_events(client, autopsy_case)
    login_as("soc_manager")
    rule = publish(client, ORIGINAL)
    expected = fingerprint(app)
    identifier = queue(client, autopsy_case)
    evaluate = autopsy_detection.evaluate_rules
    blocked_writes = []
    database.execute("PRAGMA busy_timeout=0")

    def evaluate_under_competing_write(connection, event):
        assert connection.in_transaction
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            database.execute("UPDATE rules SET version=version+1 WHERE id=?", (rule["id"],))
        blocked_writes.append(event)
        return evaluate(connection, event)

    monkeypatch.setattr(autopsy_detection, "evaluate_rules", evaluate_under_competing_write)
    _, result = execute(app, client, autopsy_case, identifier)
    assert len(blocked_writes) == 2 and len(result["payload"]["alert_ids"]) == 2
    assert receipt(database, autopsy_case, identifier)[1]["policy_sha256"] == expected


def test_receipt_failure_rolls_back_alerts_and_audit_together(autopsy_case, app, client, database, login_as, monkeypatch):
    import_events(client, autopsy_case)
    login_as("soc_manager")
    publish(client, ORIGINAL)
    identifier = queue(client, autopsy_case)

    def unavailable_custody(*args, **kwargs):
        raise RuntimeError("Synthetic audit failure")

    monkeypatch.setattr(autopsy_detection, "custody", unavailable_custody)
    with app.app_context():
        run_autopsy_worker_once()
    assert client.get(f"/api/cases/{autopsy_case}/jobs/{identifier}").json["state"] == "failed"
    assert not database.execute("SELECT 1 FROM alerts WHERE owner_case_id=?", (autopsy_case,)).fetchone()
    assert not database.execute("SELECT 1 FROM autopsy_custody WHERE case_id=? AND action='detection'", (autopsy_case,)).fetchone()


def no_detection_effects(database, case):
    assert not database.execute("SELECT 1 FROM alerts WHERE owner_case_id=?", (case,)).fetchone()
    assert not database.execute("SELECT 1 FROM autopsy_records WHERE case_id=? AND kind='analysis'", (case,)).fetchone()
    assert not database.execute("SELECT 1 FROM autopsy_custody WHERE case_id=? AND action='detection'", (case,)).fetchone()


@pytest.mark.parametrize("same_identity", [False, True])
def test_reclaimed_detection_rejects_stale_snapshot_and_replacement_can_finish(autopsy_case, app, client, database, login_as, monkeypatch, same_identity):
    import_events(client, autopsy_case)
    login_as("soc_manager")
    first_rule = publish(client, REVISED)
    identifier = queue(client, autopsy_case)
    first_identity = "local-autopsy-worker"
    next_identity = first_identity if same_identity else "replacement-worker"
    with app.app_context():
        stale = autopsy_worker.claim_job(first_identity)
    assert stale["state"] == "processing" and stale["attempts"] == 1 and stale["worker_id"] == first_identity
    database.execute("UPDATE autopsy_jobs SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?", (identifier,))
    with app.app_context():
        replacement = autopsy_worker.claim_job(next_identity)
    assert replacement["id"] == identifier and replacement["attempts"] == 2
    claimed = dict(database.execute("SELECT * FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone())
    monkeypatch.setattr(autopsy_worker, "claim_job", lambda identity: stale)
    with app.app_context():
        assert run_autopsy_worker_once(first_identity) == identifier
        with pytest.raises(autopsy_worker.JobClaimLostError):
            autopsy_detection.run_detection_job(stale)
    assert dict(database.execute("SELECT * FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()) == claimed
    no_detection_effects(database, autopsy_case)
    publish(client, ORIGINAL, first_rule)
    monkeypatch.setattr(autopsy_worker, "claim_job", lambda identity: replacement)
    with app.app_context():
        assert run_autopsy_worker_once(next_identity) == identifier
    job = client.get(f"/api/cases/{autopsy_case}/jobs/{identifier}").json
    assert job["state"] == "completed" and job["attempts"] == 2 and job["result_record_id"]
    assert receipt(database, autopsy_case, identifier)[1]["attempt"] == 2
    assert database.execute("SELECT COUNT(*) FROM alerts WHERE owner_case_id=?", (autopsy_case,)).fetchone()[0] == 2


@pytest.mark.parametrize("change", ["expired", "cancelled", "identity", "attempt", "lease"])
def test_detection_lock_rejects_lost_claim_before_effects(autopsy_case, app, client, database, login_as, change):
    import_events(client, autopsy_case)
    login_as("soc_manager")
    publish(client, ORIGINAL)
    identifier = queue(client, autopsy_case)
    with app.app_context():
        claimed = autopsy_worker.claim_job("original-worker")
    if change == "cancelled":
        assert client.post(f"/api/cases/{autopsy_case}/jobs/{identifier}/cancel").status_code == 200
    else:
        mutation = {
            "expired": ("lease_expires_at", "2000-01-01T00:00:00Z"),
            "identity": ("worker_id", "other-worker"),
            "attempt": ("attempts", 2),
            "lease": ("lease_expires_at", "2035-01-01T00:00:00Z"),
        }[change]
        database.execute(f"UPDATE autopsy_jobs SET {mutation[0]}=? WHERE id=?", (mutation[1], identifier))
    state = dict(database.execute("SELECT * FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone())
    with app.app_context(), pytest.raises(autopsy_worker.JobClaimLostError):
        autopsy_detection.run_detection_job(claimed)
    no_detection_effects(database, autopsy_case)
    assert dict(database.execute("SELECT * FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()) == state


@pytest.mark.parametrize(
    "lease,valid",
    [
        ("2030-01-01T10:00:00Z", False),
        ("2030-01-01T10:00:00.500000Z", False),
        ("2030-01-01T13:00:01+03:00", True),
        ("2030-01-01T10:00:00.500001Z", True),
        ("invalid", False),
    ],
)
def test_claim_expiry_compares_actual_utc_instants(autopsy_case, app, client, database, monkeypatch, lease, valid):
    identifier = queue(client, autopsy_case)
    with app.app_context():
        claimed = autopsy_worker.claim_job("clock-worker")
    database.execute("UPDATE autopsy_jobs SET lease_expires_at=? WHERE id=?", (lease, identifier))
    claimed["lease_expires_at"] = lease
    monkeypatch.setattr(autopsy_worker, "utc_now", lambda: parse_timestamp("2030-01-01T10:00:00.5Z"))
    with app.app_context():
        assert bool(autopsy_worker.current_job_claim(claimed)) is valid


def test_expiry_during_detection_rolls_back_and_next_claim_recovers(autopsy_case, app, client, database, login_as, monkeypatch):
    import_events(client, autopsy_case)
    login_as("soc_manager")
    publish(client, ORIGINAL)
    identifier = queue(client, autopsy_case)
    evaluate = autopsy_detection.evaluate_rules
    now = autopsy_worker.utc_now()

    with monkeypatch.context() as elapsed:

        def expires_after_evaluation(connection, event):
            result = evaluate(connection, event)
            elapsed.setattr(autopsy_worker, "utc_now", lambda: now + timedelta(minutes=10))
            return result

        elapsed.setattr(autopsy_detection, "evaluate_rules", expires_after_evaluation)
        with app.app_context():
            assert run_autopsy_worker_once() == identifier
    no_detection_effects(database, autopsy_case)
    assert database.execute("SELECT state FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()[0] == "processing"
    database.execute("UPDATE autopsy_jobs SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?", (identifier,))
    _, result = execute(app, client, autopsy_case, identifier)
    assert len(result["payload"]["alert_ids"]) == 2
    assert receipt(database, autopsy_case, identifier)[1]["attempt"] == 2


@pytest.mark.parametrize("kind", ["report", "sample"])
@pytest.mark.parametrize("interruption", ["same_identity", "different_identity", "expired", "cancelled"])
def test_stale_analysis_completion_cannot_write_files_records_or_new_claim_state(autopsy_case, app, client, database, monkeypatch, kind, interruption):
    base = f"/api/cases/{autopsy_case}"
    if kind == "report":
        response = client.post(base + "/reports", json={"version": client.get(base).json["version"]})
        assert response.status_code == 202
        identifier = response.json["job_id"]
    else:
        uploaded = client.post(base + "/samples", data={"file": (io.BytesIO(b"Inert claim fixture"), "inert.bin")})
        assert uploaded.status_code == 201
        response = client.post(base + f"/samples/{uploaded.json['id']}/analyze", json={})
        assert response.status_code == 202
        identifier = response.json["id"]
    real_claim = autopsy_worker.claim_job
    replacement, state_after_interruption = [], []
    now = autopsy_worker.utc_now()

    def interrupted_compute(payload):
        if interruption in {"same_identity", "different_identity"}:
            database.execute("UPDATE autopsy_jobs SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?", (identifier,))
            replacement.append(real_claim("local-autopsy-worker" if interruption == "same_identity" else "replacement-worker"))
        elif interruption == "cancelled":
            database.execute("UPDATE autopsy_jobs SET state='cancelled',worker_id=NULL,lease_expires_at=NULL WHERE id=?", (identifier,))
        else:
            monkeypatch.setattr(autopsy_worker, "utc_now", lambda: now + timedelta(minutes=10))
        state_after_interruption.append(dict(database.execute("SELECT * FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()))
        # Finalization boundary fixture, not native renderer/analysis validation.
        return {"json": b"{}"} if kind == "report" else {"status": "bounded fixture"}

    monkeypatch.setattr(autopsy_worker, "compute_" + kind, interrupted_compute)
    with app.app_context():
        assert run_autopsy_worker_once() == identifier
    assert dict(database.execute("SELECT * FROM autopsy_jobs WHERE id=?", (identifier,)).fetchone()) == state_after_interruption[0]
    assert not database.execute("SELECT 1 FROM autopsy_report_files").fetchone()
    assert not database.execute("SELECT 1 FROM autopsy_records WHERE case_id=? AND kind='analysis'", (autopsy_case,)).fetchone()
    assert not database.execute("SELECT 1 FROM autopsy_custody WHERE case_id=? AND action='report_rendered'", (autopsy_case,)).fetchone()
    if replacement:
        monkeypatch.setattr(autopsy_worker, "claim_job", lambda identity: replacement[0])
        monkeypatch.setattr(autopsy_worker, "compute_" + kind, lambda payload: {"json": b"{}"} if kind == "report" else {"status": "bounded fixture"})
        with app.app_context():
            assert run_autopsy_worker_once(replacement[0]["worker_id"]) == identifier
        assert client.get(base + f"/jobs/{identifier}").json["state"] == "completed"
