"""A team-level SLA policy starts every new case on the same deadline the case page, the overdue flag and the dashboards read."""

import json
from datetime import timedelta

from socify.timeutils import parse_timestamp, utc_now

AROUND_THE_CLOCK = {"mode": "24x7", "timezone": "UTC"}
MINUTES = {"critical": 30, "high": 120, "medium": 480, "low": 1440}


def _case(client, severity="high", title="Suspicious sign-in burst"):
    made = client.post("/api/cases", json={"title": title, "reason": "alert_review", "objective": "Establish impact and contain", "severity": severity})
    assert made.status_code == 201, made.json
    return made.json


def _policy(client, minutes=None, calendar=None):
    return client.put("/api/team/sla-policy", json={"minutes": minutes or MINUTES, "calendar": calendar or AROUND_THE_CLOCK})


def _latest_sla(database, case_id):
    row = database.execute("SELECT payload FROM autopsy_records WHERE case_id = ? AND kind = 'workflow_sla' ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    return json.loads(row[0]) if row else None


def test_without_a_team_policy_a_case_keeps_the_fixed_due_date(client, database, login_as):
    login_as("analyst")
    assert client.get("/api/team/sla-policy").json["policy"] is None
    case = _case(client)
    assert case["sla_due_at"] and _latest_sla(database, case["id"]) is None
    assert client.get(f"/api/cases/{case['id']}/workflow").json["sla"]["configured"] is False


def test_only_the_manager_sets_the_policy_and_bad_values_are_refused(client, database, login_as):
    login_as("analyst")
    assert _policy(client).status_code == 403
    assert client.get("/api/team/sla-policy").json["can_manage"] is False
    login_as("soc_manager")
    assert client.get("/api/team/sla-policy").json["can_manage"] is True
    for minutes, calendar in (
        ({"critical": 30, "high": 120, "medium": 480}, AROUND_THE_CLOCK),
        ({**MINUTES, "low": 0}, AROUND_THE_CLOCK),
        ({**MINUTES, "low": "1440"}, AROUND_THE_CLOCK),
        (MINUTES, {"mode": "business", "timezone": "Mars/Base", "weekdays": [0], "start_hour": 8, "end_hour": 16}),
        (MINUTES, {"mode": "business", "timezone": "UTC", "weekdays": [0], "start_hour": 16, "end_hour": 8}),
    ):
        refused = _policy(client, minutes, calendar)
        assert refused.status_code == 422, (minutes, calendar)
    assert client.put("/api/team/sla-policy", json={"minutes": MINUTES}).status_code == 422
    saved = _policy(client)
    assert saved.status_code == 200 and saved.json["policy"]["version"] == 1 and saved.json["policy"]["minutes"] == MINUTES
    assert _policy(client, {**MINUTES, "low": 2880}).json["policy"]["version"] == 2
    audit = database.execute(
        "SELECT details FROM security_audit_logs WHERE action = 'update' AND resource_type = 'team_sla_policy' ORDER BY id DESC"
    ).fetchone()
    assert json.loads(audit[0])["version"] == 2


def test_a_new_case_starts_on_the_policy_for_its_severity(client, database, login_as):
    login_as("soc_manager")
    assert _policy(client).status_code == 200
    login_as("analyst")
    case = _case(client, "critical")
    sla = _latest_sla(database, case["id"])
    assert sla["source"] == "team_policy" and sla["minutes"] == 30 and sla["severity_at_configuration"] == "critical"
    due = parse_timestamp(database.execute("SELECT sla_due_at FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0])
    assert due - parse_timestamp(case["created_at"]) == timedelta(minutes=30)
    status = client.get(f"/api/cases/{case['id']}/workflow").json["sla"]
    assert status["configured"] and status["status"] == "running" and status["projected_due_at"]
    assert abs(parse_timestamp(status["projected_due_at"]) - due) < timedelta(seconds=5)


def test_a_business_calendar_projects_the_due_date_into_working_hours(client, database, login_as):
    login_as("soc_manager")
    calendar = {"mode": "business", "timezone": "Asia/Riyadh", "weekdays": [6, 0, 1, 2, 3], "start_hour": 8, "end_hour": 16, "holidays": []}
    assert _policy(client, calendar=calendar).status_code == 200
    login_as("analyst")
    case = _case(client, "medium")
    due = database.execute("SELECT sla_due_at FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0]
    from zoneinfo import ZoneInfo

    local = parse_timestamp(due).astimezone(ZoneInfo("Asia/Riyadh"))
    # Eight working hours always end inside a Sunday to Thursday working day.
    assert local.weekday() in {6, 0, 1, 2, 3} and 8 <= local.hour + local.minute / 60 <= 16
    assert parse_timestamp(due) - parse_timestamp(case["created_at"]) >= timedelta(hours=8)


def test_a_severity_change_moves_a_policy_case_to_its_new_budget(client, database, login_as):
    login_as("soc_manager")
    _policy(client)
    case = _case(client, "low")
    first = database.execute("SELECT sla_due_at FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()[0]
    current = client.get(f"/api/cases/{case['id']}").json
    changed = client.patch(f"/api/incidents/{case['id']}", json={"version": current["version"], "severity": "critical"})
    assert changed.status_code == 200, changed.json
    sla = _latest_sla(database, case["id"])
    assert sla["minutes"] == 30 and sla["policy_version"] == 2 and sla["source"] == "team_policy"
    assert changed.json["sla_due_at"] < first


def test_a_hand_set_case_sla_is_kept_and_pause_and_resume_move_the_due_date(client, database, login_as):
    login_as("soc_manager")
    _policy(client)
    case = _case(client, "high")
    version = client.get(f"/api/cases/{case['id']}").json["version"]
    configured = client.post(
        f"/api/cases/{case['id']}/sla", json={"version": version, "minutes": 600, "calendar": AROUND_THE_CLOCK, "reason": "Customer contract"}
    )
    assert configured.status_code == 201, configured.json
    row = database.execute("SELECT sla_due_at FROM incident_cases WHERE id = ?", (case["id"],)).fetchone()
    assert parse_timestamp(row[0]) - parse_timestamp(case["created_at"]) == timedelta(minutes=600)
    version = client.get(f"/api/cases/{case['id']}").json["version"]
    assert client.patch(f"/api/incidents/{case['id']}", json={"version": version, "severity": "critical"}).status_code == 200
    assert _latest_sla(database, case["id"])["minutes"] == 600
    version = client.get(f"/api/cases/{case['id']}").json["version"]
    assert client.post(f"/api/cases/{case['id']}/sla/pause", json={"version": version, "reason": "Waiting for the vendor"}).status_code == 201
    database.execute("UPDATE incident_cases SET sla_due_at = ? WHERE id = ?", ((utc_now() - timedelta(hours=1)).isoformat().replace("+00:00", "Z"), case["id"]))
    paused = client.get(f"/api/cases/{case['id']}").json
    assert paused["sla_paused_at"] and paused["overdue"] is False
    assert client.post(f"/api/cases/{case['id']}/sla/resume", json={"version": paused["version"], "reason": "Vendor answered"}).status_code == 201
    resumed = client.get(f"/api/cases/{case['id']}").json
    assert resumed["sla_paused_at"] is None and resumed["overdue"] is False and resumed["sla_due_at"] > utc_now().isoformat()


def test_a_case_past_its_budget_is_overdue_on_the_list_and_the_dashboard(client, database, login_as):
    login_as("soc_manager")
    _policy(client, {**MINUTES, "low": 1})
    case = _case(client, "low")
    past = (utc_now() - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    database.execute("UPDATE incident_cases SET created_at = ? WHERE id = ?", (past, case["id"]))
    version = client.get(f"/api/cases/{case['id']}").json["version"]
    # A manager's later change on the same calendar recomputes the due date from the case start: now in the past.
    assert (
        client.post(f"/api/cases/{case['id']}/sla", json={"version": version, "minutes": 1, "calendar": AROUND_THE_CLOCK, "reason": "Re-applied"}).status_code
        == 201
    )
    assert client.get(f"/api/cases/{case['id']}").json["overdue"] is True
    assert client.get(f"/api/cases/{case['id']}/workflow").json["sla"]["status"] == "breached"


def test_the_policy_ticks_the_first_run_step(client, login_as):
    login_as("soc_manager")
    step = next(item for item in client.get("/api/onboarding").json["items"] if item["id"] == "sla_calendar")
    assert step["detected"] is False
    _policy(client)
    step = next(item for item in client.get("/api/onboarding").json["items"] if item["id"] == "sla_calendar")
    assert step["detected"] is True
