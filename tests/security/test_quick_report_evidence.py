"""The short handoff keeps reasoning without opening another evidence-access path."""

import json

import pytest

from socify.quick_reports import QUICK_REPORT_QUESTIONS


def save_report(client, case_id):
    answers = {q["id"]: q["options"][0]["value"] for q in QUICK_REPORT_QUESTIONS}
    result = client.put(f"/api/cases/{case_id}/quick-report", json={"answers": answers})
    assert result.status_code == 200, result.json


def upload(client, case_id, *, pretty=False, **changes):
    content = json.dumps(
        [
            {
                "external_id": "quick-handoff-001",
                "source": "handoff-gateway",
                "timestamp": "2026-11-04T02:51:58Z",
                "title": "Accepted authentication",
                "description": "Authentication decisions only; no session or endpoint execution evidence.",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc AAAA",
                **changes,
            }
        ],
        indent=2 if pretty else None,
    )
    result = client.post(f"/api/cases/{case_id}/imports", json={"filename": "handoff.json", "content": content})
    assert result.status_code in {200, 201}, result.json
    event = client.get(f"/api/cases/{case_id}/logs").json["items"][0]
    return result.json, event["id"]


def bookmark(
    client, case_id, event_id, *, title="Shared evidence reasoning", notes="Accepted authentication alone is not proof of compromise.", visibility="team"
):
    result = client.post(
        f"/api/cases/{case_id}/records/bookmark",
        json={
            "event_id": event_id,
            "title": title,
            "notes": notes,
            "visibility": visibility,
        },
    )
    assert result.status_code == 201, result.json
    return result.json


@pytest.mark.parametrize("reader", ["analyst", "soc_manager"])
def test_print_keeps_escaped_review_and_shared_evidence_limits_but_never_private_notes(autopsy_case, client, login_as, reader):
    base = f"/api/cases/{autopsy_case}"
    _, event_id = upload(client, autopsy_case, description="Source limitation <img src=x onerror=alert(1)>; authentication decisions only.")
    bookmark(client, autopsy_case, event_id, notes="Shared finding <script>alert(2)</script>")
    bookmark(client, autopsy_case, event_id, notes="PRIVATE-ANALYST-REASON", visibility="private")
    alert = client.get(base + "/alerts").json["items"][0]
    saved_review = client.patch(
        base + f"/alerts/{alert['id']}",
        json={
            "version": alert["review_version"],
            "verdict": "undetermined",
            "attack_outcome": "unknown",
            "group": "handoff",
            "suppressed_until": None,
            "reason": "Review reason <svg onload=alert(3)>; MFA evidence missing.",
        },
    )
    assert saved_review.status_code == 200, saved_review.json
    save_report(client, autopsy_case)
    login_as(reader)
    summary = client.get(base + "/quick-report").json["auto_summary"]
    assert summary["evidence_notes_count"] == 1
    assert summary["evidence_notes"][0]["event_id"] == event_id
    result = client.get(f"/cases/{autopsy_case}/quick-report/print", headers={"X-SOCify-Language": "en"})
    assert result.status_code == 200
    assert "PRIVATE-ANALYST-REASON" not in result.text + json.dumps(summary)
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in result.text
    assert "&lt;svg onload=alert(3)&gt;" in result.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in result.text
    assert "<svg onload" not in result.text and "<script>alert(2)" not in result.text and "<img src=x" not in result.text
    assert "authentication decisions only" in result.text
    assert "MFA evidence missing" in result.text
    assert "Documentation time (UTC)" in result.text
    assert "Missing evidence does not establish absence of compromise" not in result.text
    assert "Showing 1 of 1" not in result.text
    assert "raw_data" not in json.dumps(summary["evidence_notes"])
    assert "raw_payload" not in json.dumps(summary["evidence_notes"])
    assert "provenance" not in json.dumps(summary["evidence_notes"])


def test_note_summary_is_bounded_and_reports_total_without_claiming_completeness(autopsy_case, client, database):
    _, event_id = upload(client, autopsy_case)
    for index in range(12):
        bookmark(client, autopsy_case, event_id, title=f"Retained note {index:02d}", notes=f"Evidence note {index:02d}")
    # Read-side bounds also apply to oversized legacy text, without exposing raw payloads.
    database.execute("UPDATE security_events SET description=? WHERE id=?", ("L" * 2000 + "OMITTED-END-OF-LONG-TEXT", event_id))
    save_report(client, autopsy_case)
    summary = client.get(f"/api/cases/{autopsy_case}/quick-report").json["auto_summary"]
    assert summary["evidence_notes_count"] == 12 and summary["evidence_notes_limit"] == 10
    assert len(summary["evidence_notes"]) == 10
    assert summary["evidence_notes"][0]["title"] == "Retained note 11"
    assert len(summary["evidence_notes"][0]["source_description"]) == 2001
    html = client.get(f"/cases/{autopsy_case}/quick-report/print", headers={"X-SOCify-Language": "en"}).text
    assert "Showing 10 of 12" in html
    assert "Display limit" not in html and "Maximum characters" not in html
    assert "OMITTED-END-OF-LONG-TEXT" not in html
    assert "Evidence note 00" not in html and "Evidence note 11" in html


@pytest.mark.parametrize("change", ["inactive_membership", "inactive_event", "unlinked", "foreign_event"])
def test_bookmark_must_still_reference_active_evidence_in_this_case(autopsy_case, client, database, change):
    _, event_id = upload(client, autopsy_case)
    note = bookmark(client, autopsy_case, event_id, notes="HIDDEN-STALE-OR-FOREIGN-NOTE")
    save_report(client, autopsy_case)
    if change == "inactive_membership":
        database.execute("UPDATE case_events SET active_event=0 WHERE case_id=? AND event_id=?", (autopsy_case, event_id))
    elif change == "inactive_event":
        database.execute("UPDATE security_events SET autopsy_active=0 WHERE id=?", (event_id,))
    elif change == "unlinked":
        database.execute("DELETE FROM case_events WHERE case_id=? AND event_id=?", (autopsy_case, event_id))
    else:
        foreign = client.post("/api/cases", json={"title": "Different case"}).json["id"]
        _, foreign_event = upload(client, foreign, external_id="foreign-only")
        database.execute("UPDATE autopsy_records SET payload=json_set(payload,'$.event_id',?) WHERE id=?", (foreign_event, note["id"]))
    summary = client.get(f"/api/cases/{autopsy_case}/quick-report").json["auto_summary"]
    assert summary["evidence_notes_count"] == 0 and summary["evidence_notes"] == []
    assert "HIDDEN-STALE-OR-FOREIGN-NOTE" not in client.get(f"/cases/{autopsy_case}/quick-report/print").text


def test_partial_origin_and_revoked_access_cannot_be_bypassed_by_quick_report(autopsy_case, client, login_as, user_ids):
    base = f"/api/cases/{autopsy_case}"
    login_as("soc_manager")
    hidden, event_id = upload(client, autopsy_case)
    visible, duplicate_id = upload(client, autopsy_case, pretty=True)
    assert duplicate_id == event_id
    bookmark(client, autopsy_case, event_id, notes="RESTRICTED-ORIGIN-REASONING")
    save_report(client, autopsy_case)

    def access(job, members):
        login_as("soc_manager")
        result = client.put(base + f"/imports/{job['id']}/access", json={"restricted": True, "members": members, "reason": "Evidence scope review"})
        assert result.status_code == 200, result.json

    access(hidden, [])
    access(visible, [user_ids["analyst"]])
    login_as("analyst")
    assert client.get(base + "/logs").json["total"] == 1
    for path in (base + "/quick-report", f"/cases/{autopsy_case}/quick-report/print"):
        result = client.get(path)
        assert result.status_code == 403 and result.json["error"]["code"] == "BATCH_SCOPE_REQUIRED"
        assert "RESTRICTED-ORIGIN-REASONING" not in result.text
    access(hidden, [user_ids["analyst"]])
    login_as("analyst")
    assert "RESTRICTED-ORIGIN-REASONING" in client.get(f"/cases/{autopsy_case}/quick-report/print").text
    access(hidden, [])
    access(visible, [])
    login_as("analyst")
    assert client.get(base + "/logs").json["total"] == 0
    assert client.get(base + "/quick-report").status_code == 403
    assert client.get(f"/cases/{autopsy_case}/quick-report/print").status_code == 403


def test_case_membership_revocation_removes_report_access(autopsy_case, client, login_as, database, user_ids):
    _, event_id = upload(client, autopsy_case)
    bookmark(client, autopsy_case, event_id, notes="ONLY-FOR-AUTHORIZED-CASE-READERS")
    save_report(client, autopsy_case)
    database.execute("UPDATE incident_cases SET creator=?,assignee=? WHERE id=?", (user_ids["soc_manager"], user_ids["soc_manager"], autopsy_case))
    database.execute("DELETE FROM autopsy_case_members WHERE case_id=? AND user_id=?", (autopsy_case, user_ids["analyst"]))
    login_as("analyst")
    for path in (f"/api/cases/{autopsy_case}/quick-report", f"/cases/{autopsy_case}/quick-report/print"):
        result = client.get(path)
        assert result.status_code == 404
        assert "ONLY-FOR-AUTHORIZED-CASE-READERS" not in result.text
