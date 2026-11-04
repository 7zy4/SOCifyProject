import io
import json


def test_guided_dropdown_report_validation_printable_html_xss_safety_and_manager_escalation(app, client, login_as):
    app.config.update(LEGACY_TRAINING_TESTS=False, REQUIRE_CASE_APPROVAL=False, REQUIRE_INVESTIGATION_SELECTION=False)
    login_as("analyst")

    # Create case with XSS attempt in title to verify strict HTML escaping in printable report
    case_resp = client.post("/api/cases", json={"title": "Phishing Wire Case <script>alert(1)</script>", "severity": "high"})
    assert case_resp.status_code == 201, case_resp.json
    case_id = case_resp.json["id"]

    # Import suspicious log + run 1-click static file triage so the report auto-populates findings
    client.post(
        f"/api/cases/{case_id}/imports",
        json={
            "filename": "ps.json",
            "content": json.dumps([{"title": "Encoded PowerShell", "process_name": "powershell.exe", "command_line": "powershell.exe -enc AAAA"}]),
        },
    )
    client.post(
        f"/api/cases/{case_id}/quick-file-triage",
        data={"file": (io.BytesIO(b"MZ" + b"\x00" * 128 + b"CreateRemoteThread VirtualAllocEx"), "remittance.pdf")},
        content_type="multipart/form-data",
    )

    # 1. Fetch schema & auto-populated evidence summary
    schema_resp = client.get(f"/api/cases/{case_id}/quick-report")
    assert schema_resp.status_code == 200, schema_resp.json
    questions = schema_resp.json["questions"]
    assert len(questions) == 9
    assert schema_resp.json["auto_summary"]["logs_count"] >= 1
    assert schema_resp.json["auto_summary"]["alerts_count"] >= 1
    assert len(schema_resp.json["auto_summary"]["static_triage_items"]) == 1

    # 2. Reject invalid dropdown option values (strictly non-free-text answers!)
    bad_save = client.put(
        f"/api/cases/{case_id}/quick-report",
        json={"answers": {"incident_classification": "made_up_free_text_option"}},
    )
    assert bad_save.status_code == 422

    # 3. Save valid dropdown selections across all 9 questions
    valid_answers = {
        "incident_classification": "phishing_bec",
        "initial_vector": "email_attachment_or_link",
        "triage_verdict": "confirmed_true_positive",
        "impact_scope": "single_user_or_host",
        "data_exposure": "credentials_at_risk",
        "file_and_email_assessment": "malicious_artifact_identified",
        "containment_status": "indicators_added_to_watchlist_and_block",
        "recommended_next_step": "block_iocs_and_reset_credentials",
        "urgency_level": "immediate_p1",
    }
    saved = client.put(
        f"/api/cases/{case_id}/quick-report",
        json={"answers": valid_answers, "executive_note": "Note <img src=x onerror=alert(2)>"},
    )
    assert saved.status_code == 200, saved.json
    assert saved.json["report"]["status"] == "draft"
    assert saved.json["report"]["answers"]["triage_verdict"] == "confirmed_true_positive"

    # 4. Printable HTML report renders cleanly, escapes XSS, includes print CSS and auto-collected findings
    printable = client.get(f"/cases/{case_id}/quick-report/print")
    assert printable.status_code == 200
    html_text = printable.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html_text
    assert "<img src=x onerror=alert(2)>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text
    assert "quick-report-print.css" in html_text
    assert "remittance.pdf" in html_text
    assert '<span class="badge high" dir="ltr">high_risk' in html_text
    assert "PowerShell" in html_text

    # 5. Direct 1-click escalation to SOC Manager
    esc = client.post(f"/api/cases/{case_id}/quick-report/escalate", json={})
    assert esc.status_code == 200, esc.json
    assert esc.json["report"]["status"] == "escalated"

    # Analyst cannot acknowledge/approve as manager
    forbidden_ack = client.post(
        f"/api/cases/{case_id}/quick-report/acknowledge",
        json={"decision": "approved", "comment": "Self-approve attempt"},
    )
    assert forbidden_ack.status_code == 403

    # SOC Manager sees the escalated report in the Manager Inbox and acknowledges it
    login_as("soc_manager")
    inbox = client.get("/api/reports/escalated")
    assert inbox.status_code == 200, inbox.json
    assert any(item["case_id"] == case_id and item["urgency_level"] == "immediate_p1" for item in inbox.json["items"])

    ack = client.post(
        f"/api/cases/{case_id}/quick-report/acknowledge",
        json={"decision": "approved", "comment": "Approved containment & credential reset."},
    )
    assert ack.status_code == 200, ack.json
    assert ack.json["report"]["status"] == "acknowledged"
    assert ack.json["report"]["manager_decision"] == "approved"


def test_pending_evidence_is_a_truthful_documented_decision_without_response_side_effects(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    imported = client.post(
        base + "/imports",
        json={
            "filename": "identity.json",
            "content": json.dumps([{"title": "Authentication evidence", "process_name": "powershell.exe", "command_line": "powershell.exe -enc AAAA"}]),
        },
    )
    assert imported.status_code in {200, 201}, imported.json
    questions = client.get(base + "/quick-report").json["questions"]
    classification = next(q for q in questions if q["id"] == "incident_classification")
    assert classification["default"] == "" and classification["options"][0]["value"] == "phishing_bec"
    answers = {q["id"]: q["options"][0]["value"] for q in questions}
    answers.update(
        incident_classification="undetermined_pending_evidence",
        initial_vector="identity_vpn_login",
        triage_verdict="undetermined_pending_evidence",
        impact_scope="scope_under_assessment",
        data_exposure="none_observed",
        file_and_email_assessment="no_files_involved",
        containment_status="not_performed_pending_evidence",
        recommended_next_step="collect_and_validate_evidence",
    )
    before = {
        "case": client.get(base).json,
        "reviews": [tuple(row) for row in database.execute("SELECT * FROM autopsy_alert_reviews")],
        "responses": [tuple(row) for row in database.execute("SELECT * FROM autopsy_records WHERE kind='response'")],
        "alerts": [tuple(row) for row in database.execute("SELECT id,status FROM alerts")],
        "context": tuple(database.execute("SELECT alert_verdict,attack_outcome FROM autopsy_case_context WHERE case_id=?", (autopsy_case,)).fetchone()),
    }
    saved = client.put(base + "/quick-report", json={"answers": answers, "executive_note": "Awaiting MFA and session evidence; no containment performed."})
    assert saved.status_code == 200, saved.json
    assert saved.json["report"]["answers"] == answers
    html = client.get(f"/cases/{autopsy_case}/quick-report/print", headers={"X-SOCify-Language": "en"}).text
    assert "Classification Pending Evidence" in html
    assert "Unauthorized Access / Brute Force" not in html
    assert "Undetermined — Awaiting Evidence" in html
    assert "No Containment Performed — Awaiting Evidence" in html
    assert "Collect and Validate Evidence Before Response" in html
    after_case = client.get(base).json
    assert after_case["status"] == before["case"]["status"]
    assert after_case["version"] > before["case"]["version"]
    assert before["reviews"] == [tuple(row) for row in database.execute("SELECT * FROM autopsy_alert_reviews")]
    assert before["responses"] == [tuple(row) for row in database.execute("SELECT * FROM autopsy_records WHERE kind='response'")]
    assert before["alerts"] == [tuple(row) for row in database.execute("SELECT id,status FROM alerts")]
    assert before["context"] == tuple(
        database.execute("SELECT alert_verdict,attack_outcome FROM autopsy_case_context WHERE case_id=?", (autopsy_case,)).fetchone()
    )
