"""The printable quick report is assembled as HTML text, so every stored value must reach the page escaped."""

import re

from socify.quick_reports import QUICK_REPORT_QUESTIONS

ANSWERS = {question["id"]: question["options"][0]["value"] for question in QUICK_REPORT_QUESTIONS}
PAYLOAD = "\"'><script>alert(7331)</script><img src=x onerror=alert(7331)>"
# Free-text columns the report reads; closed vocabularies (status, severity) are validated on write and stay untouched.
STORED_TEXT = {
    "incident_cases": ("title", "description", "objective", "reference"),
    "users": ("name", "name_ar", "name_en", "team"),
    "case_quick_reports": ("executive_note", "manager_comment"),
    "case_tasks": ("title", "description"),
    "alerts": ("title", "description", "alert_id"),
}


def test_stored_markup_reaches_the_printable_report_escaped(autopsy_case, client, login_as, database):
    base = f"/api/cases/{autopsy_case}"
    assert client.post(base + "/quick-report/escalate", json={"answers": ANSWERS, "executive_note": "Initial note"}).status_code == 200
    login_as("soc_manager")
    version = client.get(base).json["version"]
    approved = client.post(base + "/quick-report/acknowledge", json={"decision": "approved", "case_version": version, "comment": "Reviewed"})
    assert approved.status_code == 200, approved.json
    clean = client.get(f"/cases/{autopsy_case}/quick-report/print")
    assert clean.status_code == 200 and "7331" not in clean.text

    database.execute("PRAGMA foreign_keys = OFF")
    changed = 0
    for table, columns in STORED_TEXT.items():
        present = {row[1] for row in database.execute(f"PRAGMA table_info({table})")}
        for column in columns:
            if column in present:
                # Text stored by an older release, a restored capsule or direct database access is not re-validated.
                changed += database.execute(f"UPDATE {table} SET {column} = ? || rowid WHERE {column} IS NOT NULL AND {column} <> ''", (PAYLOAD,)).rowcount
    assert changed >= 6

    printed = client.get(f"/cases/{autopsy_case}/quick-report/print")
    assert printed.status_code == 200
    page = printed.text
    assert page.count("7331") >= 4, "the stored text no longer reaches the report, so this test would prove nothing"
    assert "<script>alert(7331)" not in page and "<img src=x" not in page
    # No element or attribute may be opened by stored text: every payload occurrence stays inside escaped character data.
    assert not re.search(r"<[^>]*7331", page)
    assert "&lt;script&gt;alert(7331)&lt;/script&gt;" in page
