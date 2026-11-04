"""Blue-team decisions grounded in retained evidence, through the visible interface."""

import hashlib
import json
import shutil
import subprocess
from contextlib import contextmanager
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_email_goal_journeys import reviews
from tests.e2e.test_email_goal_journeys import upload as upload_mail
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_performance_goal_journeys import counter, period
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import ARTIFACTS as JOURNEYS
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/blue-team-decisions")
FILES = (
    "socify/soc_insights.py",
    "socify/autopsy_ingestion.py",
    "socify/events.py",
    "socify/autopsy_email.py",
    "static/soc-insights.js",
    "static/autopsy_analysis.js",
    "static/autopsy_data.js",
)


def fingerprints():
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in FILES}


@contextmanager
def decision_session(app, language, scenario):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    try:
        with review_session(app, language, scenario) as (j, manager, result):
            result["plan_id"] = {
                "blue-backfill-case-versus-event-time": "NEXT-19",
                "blue-sibling-attachments-same-name": "NEXT-24",
                "blue-reused-hostname-dated-observations": "NEXT-31",
                "blue-ipv6-equivalent-evidence-search": "NEXT-32",
            }[scenario]
            result["phase"] = "development acceptance before the integrated publication gate"
            result["human_participants"] = 0
            result["checked_revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()  # noqa: S603,S607
            result["production_hashes_before"] = fingerprints()
            try:
                yield j, manager, result
            finally:
                result["production_hashes_after"] = fingerprints()
    finally:
        for path in JOURNEYS.glob(f"{scenario}-{language}*"):
            shutil.copy2(path, ARTIFACTS / path.name)


def upload_logs(j, rows, filename):
    j.click("link", "السجلات والأدلة")
    j.page.locator("input[name=file]").set_input_files({"name": filename, "mimeType": "application/json", "buffer": json.dumps(rows).encode()})
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name=rows[0]["title"], exact=True)).to_be_visible()


def conclude(j, note):
    j.click("link", "التحقيق والخط الزمني")
    dialog = note_dialog(j)
    dialog.locator("input[name=title]").fill("Scoped evidence conclusion")
    dialog.locator("textarea[name=body]").fill(note)
    j.click("button", "حفظ", dialog)
    assert any(item["payload"]["body"] == note for item in records(j, "war_room"))
    j.click("link", "التقارير والمراجعة")
    j.click("button", "إعداد تقرير جديد")
    snapshot = report(j, report_path(j))
    assert note in json.dumps(snapshot["payload"], ensure_ascii=False)
    return snapshot


def capture(j, scenario, language, stage):
    assert_accessible(j.page)
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        j.page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        j.page.screenshot(path=str(ARTIFACTS / f"{scenario}-{language}-{stage}-{width}.png"), full_page=True)
    j.page.set_viewport_size({"width": 1440, "height": 1000})


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_historical_event_is_not_described_as_current_attack_volume(app, language):
    scenario = "blue-backfill-case-versus-event-time"
    occurred = "2021-07-08T06:15:00Z"
    with decision_session(app, language, scenario) as (j, _manager, result):
        upload_logs(
            j,
            [
                {
                    "title": "Historical process observation",
                    "timestamp": occurred,
                    "hostname": "ARCHIVED-ENDPOINT",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -enc AAAA",
                }
            ],
            "historical-evidence.json",
        )
        current = j.state()
        assert current["created_at"][:4] != occurred[:4]
        j.nav("الأداء")
        period(j, "7")
        assert counter(j, "قضايا نشطة") == 1
        expect(j.page.locator(".performance-trend")).to_contain_text(j.text("أنشئت"))
        result["observed_unit"] = "The chart labels opened/closed cases; the source event predates the case."
        capture(j, scenario, language, "case-activity")
        j.nav("المراقبة")
        j.page.locator("[data-alert-toggle]").first.click()
        j.settle()
        dossier = j.page.locator(".dossier-view")
        expect(dossier).to_contain_text("ARCHIVED-ENDPOINT")
        rendered_time = j.page.evaluate("value => formatTime(value)", occurred)
        expect(dossier).to_contain_text(rendered_time)
        j.page.goto(j.case_url + "?tab=logs")
        j.settle()
        row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name="Historical process observation", exact=True))
        j.click("button", "تفاصيل السجل", row)
        expect(j.page.get_by_role("dialog")).to_contain_text(occurred[:10])
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        note = f"This case was opened for retrospective review. The retained process observation occurred at {occurred}; current case activity does not establish a current attack or endpoint connection."
        snapshot = conclude(j, note)
        assert occurred[:10] in json.dumps(snapshot["payload"])
        capture(j, scenario, language, "reported")
        result["plan_id"] = "NEXT-19"
        result["outcomes"] = [
            "Current case workload distinguished from historical event time",
            "Actual alert and raw record inspected",
            "Chronology preserved in a new immutable report snapshot",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_same_name_attachment_siblings_remain_distinguishable_in_the_report(app, language):
    scenario = "blue-sibling-attachments-same-name"
    benign, suspicious = b"%PDF-1.4\nRetained invoice text\n%%EOF", b"MZ" + b"\x00" * 70
    benign_digest, suspicious_digest = (hashlib.sha256(body).hexdigest() for body in (benign, suspicious))
    mail = EmailMessage(policy=SMTP)
    mail["From"], mail["To"], mail["Subject"] = "sender@example.test", "analyst@internal.test", "Two documents for independent review"
    mail.set_content("Two same-name documents are attached for evidence comparison.")
    for body in (benign, suspicious):
        mail.add_attachment(body, maintype="application", subtype="pdf", filename="invoice.pdf")
    mail.set_boundary("socify-distinct-sibling-attachments")
    with decision_session(app, language, scenario) as (j, _manager, result):
        j.nav("أمن البريد الإلكتروني")
        external = []
        j.page.on("request", lambda request: external.append(request.url) if request.url.startswith("https://") else None)
        upload_mail(j, mail.as_bytes(), "sibling-documents.eml")
        table = j.page.locator(".email-result table").filter(has=j.page.get_by_role("columnheader", name="SHA-256", exact=True))
        expect(table.get_by_role("cell", name="invoice.pdf", exact=True)).to_have_count(2)
        benign_row = table.get_by_role("row").filter(has_text=benign_digest)
        suspicious_row = table.get_by_role("row").filter(has_text=suspicious_digest)
        expect(suspicious_row).to_contain_text(j.text("تعارض امتداد"))
        expect(benign_row).not_to_contain_text(j.text("تعارض امتداد"))
        attachments = reviews(j)["items"][0]["payload"]["attachments"]
        assert len(attachments) == 2 and {item["sha256"] for item in attachments} == {benign_digest, suspicious_digest}
        capture(j, scenario, language, "comparison")
        j.click("button", "+ قائمة المراقبة", suspicious_row)
        watchlist = j.page.evaluate("() => api('/api/watchlist')")["items"]
        assert [item["value"] for item in watchlist] == [suspicious_digest]
        j.page.goto(j.case_url)
        j.settle()
        note = f"Two invoice.pdf attachments have distinct content. SHA-256 {suspicious_digest} has an executable signature inconsistent with its declared PDF type. The other attachment, SHA-256 {benign_digest}, has a PDF signature. Static findings do not establish execution or compromise."
        snapshot = conclude(j, note)
        saved = json.dumps(snapshot["payload"])
        assert suspicious_digest in saved and benign_digest in saved and not external
        capture(j, scenario, language, "reported")
        result["plan_id"] = "NEXT-24"
        result["outcomes"] = [
            "Both same-name attachments remained separately identifiable",
            "Only the mismatched attachment was selected for watchlisting",
            "The report preserves both digests and identifies the intended finding without executing content",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_reused_hostname_is_dated_case_evidence_not_a_live_contained_device(app, language):
    scenario = "blue-reused-hostname-dated-observations"
    rows = [
        {
            "title": "Older endpoint observation",
            "timestamp": "2021-01-02T09:00:00Z",
            "hostname": "REUSED-HOST",
            "source_ip": "192.0.2.10",
            "username": "former.operator",
        },
        {
            "title": "Later endpoint observation",
            "timestamp": "2025-12-03T10:00:00Z",
            "hostname": "REUSED-HOST",
            "source_ip": "192.0.2.20",
            "username": "later.operator",
        },
    ]
    with decision_session(app, language, scenario) as (j, manager, result):
        upload_logs(j, rows, "dated-host-observations.json")
        manager.login("manager@socify.local")
        manager.page.evaluate("""async () => {
            const other=await api('/api/cases',{method:'POST',body:{title:'Unrelated host observation'}});
            await api(`/api/cases/${other.id}/imports`,{method:'POST',body:{filename:'unrelated.json',content:JSON.stringify([{hostname:'REUSED-HOST',title:'Unrelated observation must not be merged',source_ip:'192.0.2.99',username:'unrelated.operator',timestamp:'2026-01-01T01:00:00Z'}])}});
        }""")
        result["setup_only"] = "One unrelated case and log prepared with authenticated API calls; the task uses the analyst's visible case."
        j.nav("أمن الأجهزة والأصول")
        j.page.get_by_role("link", name="REUSED-HOST", exact=True).click()
        j.settle()
        devices = j.page.locator("section.panel").filter(has=j.page.get_by_role("heading", name=j.text("أجهزة القضية"), exact=True))
        expect(devices.locator("details.evidence-event")).to_have_count(2)
        for details in devices.locator("details.evidence-event").all():
            details.locator("summary").click()
        expect(devices).to_contain_text("192.0.2.10")
        expect(devices).to_contain_text("192.0.2.20")
        expect(devices).to_contain_text("former.operator")
        expect(devices).to_contain_text("later.operator")
        expect(devices).not_to_contain_text("192.0.2.99")
        expect(devices).not_to_contain_text("unrelated.operator")
        for row in rows:
            expect(devices).to_contain_text(j.page.evaluate("value => formatTime(value)", row["timestamp"]))
        assert j.page.get_by_role("button", name="Isolate device", exact=True).count() == 0
        capture(j, scenario, language, "dated-evidence")
        j.page.goto(j.case_url)
        j.settle()
        note = "REUSED-HOST was observed as 192.0.2.10 / former.operator on 2021-01-02 and 192.0.2.20 / later.operator on 2025-12-03. These are separate retained observations in this case. Current ownership, connectivity and containment are unverified; no live endpoint action was performed."
        snapshot = conclude(j, note)
        saved = json.dumps(snapshot["payload"])
        assert "192.0.2.99" not in saved and "unrelated.operator" not in saved
        capture(j, scenario, language, "reported")
        result["plan_id"] = "NEXT-31"
        result["outcomes"] = [
            "Both dated observations remained visible with their own address and account",
            "Same-name host in another case was excluded",
            "The report makes no current connectivity or containment claim",
        ]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_ipv6_search_finds_equivalent_retained_addresses_without_merging_another_host(app, language):
    scenario = "blue-ipv6-equivalent-evidence-search"
    compressed, expanded, other = "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::2"
    rows = [
        {"title": "IPv6 compressed observation", "source_ip": compressed, "timestamp": "2026-01-01T01:00:00Z"},
        {"title": "IPv6 expanded observation", "source_ip": expanded, "timestamp": "2026-01-01T01:01:00Z"},
        {"title": "Different IPv6 observation", "source_ip": other, "timestamp": "2026-01-01T01:02:00Z"},
    ]
    with decision_session(app, language, scenario) as (j, _manager, result):
        upload_logs(j, rows, "ipv6-observations.json")
        form = j.page.get_by_role("form", name=j.text("بحث سجلات القضية"), exact=True)
        form.locator("input[name=q]").fill(compressed)
        j.click("button", "بحث السجلات", form)
        titles = [cell.inner_text() for cell in j.page.get_by_role("cell").all() if "observation" in cell.inner_text()]
        result["query"] = compressed
        result["observed_titles"] = titles
        capture(j, scenario, language, "search")
        expect(j.page.get_by_role("cell", name="IPv6 compressed observation", exact=True)).to_be_visible()
        expect(j.page.get_by_role("cell", name="IPv6 expanded observation", exact=True)).to_be_visible()
        expect(j.page.get_by_role("cell", name="Different IPv6 observation", exact=True)).to_have_count(0)
        expect(j.page.get_by_role("form", name=j.text("بحث سجلات القضية"), exact=True).locator("input[name=q]")).to_have_css("direction", "ltr")
        form = j.page.get_by_role("form", name=j.text("بحث سجلات القضية"), exact=True)
        form.locator("input[name=q]").fill(expanded)
        j.click("button", "بحث السجلات", form)
        expect(j.page.get_by_role("cell", name="IPv6 compressed observation", exact=True)).to_be_visible()
        expect(j.page.get_by_role("cell", name="IPv6 expanded observation", exact=True)).to_be_visible()
        expect(j.page.get_by_role("cell", name="Different IPv6 observation", exact=True)).to_have_count(0)
        for title, value in (("IPv6 compressed observation", compressed), ("IPv6 expanded observation", expanded)):
            row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name=title, exact=True))
            j.click("button", "تفاصيل السجل", row)
            expect(j.page.get_by_role("dialog")).to_contain_text(value)
            j.click("button", "إغلاق", j.page.get_by_role("dialog"))
            exhibit = j.page.locator("form").filter(has=j.page.locator("input[name=event_id]"))
            exhibit.locator("input[name=event_id]").fill(title)
            exhibit.locator("input[name=event_id]").press("ArrowDown")
            exhibit.get_by_role("option").filter(has_text=title).first.click()
            j.click("button", "حفظ", exhibit)
        assert len([item for item in j.state()["evidence"] if item["evidence_type"] == "event"]) == 2
        note = f"The retained values {compressed} and {expanded} represent the same IPv6 address. They are two observations, separate from {other}; original values were preserved and no external host was queried."
        snapshot = conclude(j, note)
        assert expanded in json.dumps(snapshot["payload"]) and compressed in json.dumps(snapshot["payload"])
        j.page.locator("summary").filter(has_text=j.text("عرض بيانات النسخة للمراجعة")).click()
        preview = j.page.locator(".report-preview")
        record_data = preview.locator("dt").filter(has_text=j.text("سجلات التحقيق")).locator("xpath=following-sibling::dd[1]")
        for _ in range(8):
            collapsed = record_data.locator("details:not([open]) > summary:visible")
            if not collapsed.count():
                break
            collapsed.first.click()
        expect(record_data.get_by_text(note, exact=True)).to_be_visible()
        capture(j, scenario, language, "reported")
        result["plan_id"] = "NEXT-32"
        result["outcomes"] = [
            "Equivalent IPv6 representations found through the visible log search",
            "Different address excluded",
            "Exact original address strings retained in the investigation report",
            "Saved investigation conclusion read in the visible report snapshot preview",
        ]
