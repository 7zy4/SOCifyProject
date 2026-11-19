import re

from tests.integration.test_telemetry_workflow import upload
from tests.unit.test_snort import snort


def test_printed_report_reads_times_in_utc_and_skips_empty_review_reasons(autopsy_case, client, database):
    base = f"/api/cases/{autopsy_case}"
    upload(client, autopsy_case, [snort()])
    stored = database.execute("SELECT detected_at FROM alerts WHERE owner_case_id=? ORDER BY id LIMIT 1", (autopsy_case,)).fetchone()[0]
    guide = client.get(base + "/quick-report").json
    assert client.put(base + "/quick-report", json={"answers": {q["id"]: q["options"][0]["value"] for q in guide["questions"]}}).status_code == 200

    printed = client.get(f"/cases/{autopsy_case}/quick-report/print").text

    assert "<th>وقت الرصد (UTC)</th>" in printed
    assert stored not in printed, "the stored ISO timestamp is printed as is"
    assert re.search(rf'<span class="mono" dir="ltr">{stored[:10]} {stored[11:19]}</span>', printed)
    assert '<p dir="auto">—</p>' not in printed and '<p dir="auto"></p>' not in printed


def test_unreadable_stored_times_print_unchanged(app):
    from socify.quick_reports import _utc_time

    with app.app_context():
        assert _utc_time("2026-11-19T03:01:39.616326Z") == "2026-11-19 03:01:39"
        assert _utc_time("2026-11-19T06:01:39+03:00") == "2026-11-19 03:01:39"
        assert _utc_time(None) == "—"
        assert _utc_time("") == "—"
        assert _utc_time("not a time") == "not a time"
