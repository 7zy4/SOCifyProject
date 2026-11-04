"""Scripted evidence decisions; no human study or native-export acceptance claim."""

import hashlib
import json
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_email_goal_journeys import reviews, upload
from tests.e2e.test_followup_decision_journeys import preview_note
from tests.e2e.test_investigation_link_journeys import choose, note_dialog, records
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import review_session
from tests.unit.test_telemetry import zeek

ARTIFACTS = Path("artifacts/usability_campaign/evidence-interpretation-decisions")
FILES = (
    "socify/autopsy_email.py",
    "socify/network_insights.py",
    "static/autopsy_analysis.js",
    "static/telemetry.js",
    "static/autopsy_reports.js",
    "static/comic-workspace.css",
)
SCENARIOS = {
    "AFTER-47": {
        "hypothesis": "Conflicting retained mail authentication claims can be investigated without asserting live SPF/DKIM validation.",
        "nearest_prior": "test_email_goal_journeys.py::mail-header-language checks one mismatch and readable labels, not conflicting authserv-id trust or a saved decision.",
        "novel_boundary": "Two contradictory Authentication-Results origins; qualified conclusion plus a linked pending follow-up and report preview.",
    },
    "AFTER-48": {
        "hypothesis": "Periodicity can be compared with maintenance evidence without being treated as a command-and-control verdict.",
        "nearest_prior": "test_telemetry_browser.py::test_telemetry_investigation_and_evidence_navigation checks details/event links, not a competing maintenance explanation.",
        "novel_boundary": "Regular heartbeat with matching independent maintenance evidence and irregular control; retained qualified decision, case remains open.",
    },
}


def fingerprints():
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in FILES}


@contextmanager
def decision_session(app, monkeypatch, language, scenario):
    folder = ARTIFACTS / "attempts" / f"{scenario}-{language}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    with review_session(app, language, scenario) as (j, _manager, result):
        result.update(
            **SCENARIOS[scenario],
            plan_id=scenario,
            interpretation_kind="Scripted decision hypothesis and observed interface behavior; no human participants or inferred satisfaction",
            human_participants=0,
            clean_round_claim=False,
            native_export_claim=False,
            checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
            test_file_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            production_hashes_before=fingerprints(),
            setup_provenance="Isolated seeded accounts only. Initial case, all evidence uploads, decisions and report generation use actual UI; API reads independently assert persisted state.",
            evidence_folder=str(folder),
        )
        external = []
        j.page.on("request", lambda request: external.append(request.url) if urlsplit(request.url).hostname not in {"127.0.0.1", "localhost", None} else None)
        try:
            yield j, result, folder
            assert not external, "Unexpected external browser request"
            result["outcome_classification"] = "completed scripted decision task"
        except Exception as error:
            result["outcome_classification"] = "product failure" if "PRODUCT:" in str(error) else "unclassified failure pending review"
            raise
        finally:
            result["external_browser_requests"] = external
            result["production_hashes_after"] = fingerprints()
            result["product_changed_during_attempt"] = result["production_hashes_before"] != result["production_hashes_after"]


def fixture(folder, result, filename, body, purpose):
    path = folder / filename
    path.write_bytes(body)
    result.setdefault("fixtures", []).append({"path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "purpose": purpose, "inert": True})


def capture(j, result, folder, stage):
    result.setdefault("visible_observations", []).append({"stage": stage, "text": j.page.locator("main").inner_text()})
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        j.page.evaluate("scrollTo({top:0,behavior:'instant'})")
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "PRODUCT: page overflow"
        assert_accessible(j.page)
        path = folder / f"{stage}-{width}.png"
        j.page.screenshot(path=str(path), full_page=True)
        result.setdefault("screenshots", []).append(str(path))
        fingerprints_layout = j.page.locator(".email-result details[open] > p.cell-meta").evaluate_all(
            "items=>items.map(item=>({text:item.textContent,width:item.clientWidth,content_width:item.scrollWidth}))"
        )
        if fingerprints_layout:
            result.setdefault("fingerprint_layout", []).append({"viewport": width, "elements": fingerprints_layout})
            assert all(item["content_width"] <= item["width"] + 1 for item in fingerprints_layout), (
                "PRODUCT: retained email fingerprint is clipped inside its container"
            )
        if stage == "periodic-versus-control":
            layout = j.page.locator(".telemetry-view").evaluate("""root=>{
                const edge=root.getBoundingClientRect();
                const controls=[...root.querySelectorAll('input[name=connection_search],.insight-counters,.network-detail')].map(item=>{
                    const bounds=item.getBoundingClientRect();
                    return {selector:item.className||item.name,left:bounds.left,right:bounds.right,width:bounds.width,content_width:item.scrollWidth};
                });
                const destination=[...root.querySelectorAll('.network-detail td bdi')].find(item=>item.textContent==='203.0.113.9');
                const range=document.createRange();range.selectNodeContents(destination);
                const header_cells=[...root.querySelectorAll('.network-detail th')].map(item=>{
                    const cell=item.getBoundingClientRect();const text=document.createRange();text.selectNodeContents(item);
                    const content=text.getBoundingClientRect();
                    return {text:item.textContent,width:item.clientWidth,content_width:item.scrollWidth,cell_left:cell.left,cell_right:cell.right,content_left:content.left,content_right:content.right};
                });
                return {root_left:edge.left,root_right:edge.right,controls,destination_line_boxes:range.getClientRects().length,header_cells};
            }""")
            result.setdefault("telemetry_layout", []).append({"viewport": width, **layout})
            assert all(item["left"] >= layout["root_left"] - 1 and item["right"] <= layout["root_right"] + 1 for item in layout["controls"]), (
                "PRODUCT: network controls or evidence details extend outside their panel"
            )
            assert layout["destination_line_boxes"] == 1, "PRODUCT: a short destination address is split by an undersized evidence value column"
            assert all(
                item["content_width"] <= item["width"] + 1 and item["content_left"] >= item["cell_left"] - 1 and item["content_right"] <= item["cell_right"] + 1
                for item in layout["header_cells"]
            ), "PRODUCT: network evidence labels overlap their value column"
    j.page.set_viewport_size({"width": 1440, "height": 1000})


def conclude(j, note, followup):
    if not urlsplit(j.page.url).path.startswith(f"/cases/{j.case_id}"):
        j.click("link", "فتح التحقيق")
    j.click("link", "التحقيق والخط الزمني")
    dialog = note_dialog(j)
    dialog.locator("input[name=title]").fill("Qualified evidence assessment and follow-up")
    dialog.locator("textarea[name=body]").fill(note + "\n\n" + followup)
    choose(j, dialog, "task_id", "Validate primary evidence")
    j.click("button", "حفظ", dialog)
    saved = records(j, "war_room")[0]
    assert saved["payload"]["body"] == note + "\n\n" + followup
    linked = next(task for task in j.state()["tasks"] if task["id"] == saved["payload"]["task_id"])
    assert linked["status"] != "completed"
    j.click("link", "التقارير والمراجعة")
    j.click("button", "إعداد تقرير جديد")
    snapshot = report(j, report_path(j))
    assert note in json.dumps(snapshot["payload"], ensure_ascii=False)
    assert followup in json.dumps(snapshot["payload"], ensure_ascii=False)
    preview_note(j, saved["payload"]["body"])
    assert j.state()["status"] != "closed"
    return snapshot, saved


def mail(subject, conflicting=False):
    message = EmailMessage(policy=SMTP)
    message["From"] = "Maintenance Desk <maintenance@example.test>"
    message["Reply-To"] = "maintenance@example.test"
    message["To"] = "analyst@internal.test"
    message["Subject"] = subject
    message["Date"] = "Tue, 03 Nov 2026 08:00:00 +0300"
    if conflicting:
        message["Authentication-Results"] = "forwarder.example.test; spf=pass smtp.mailfrom=example.test; dkim=pass header.d=example.test"
        message["Authentication-Results"] = "edge.example.test; spf=fail smtp.mailfrom=example.test; dkim=fail header.d=example.test"
    message.set_content("Retained forwarded service notice. No links, attachments, commands or requested action.")
    return message.as_bytes()


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_conflicting_mail_claims_lead_to_qualified_followup(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "AFTER-47") as (j, result, folder):
        control = mail("Unrelated maintenance notice")
        content = mail("Forwarded authentication claims", conflicting=True)
        fixture(folder, result, "unrelated-control.eml", control, "Unrelated inert message with no Authentication-Results")
        fixture(folder, result, "conflicting-authentication.eml", content, "Two contrary untrusted authserv-id claims; no DNS, attachment or active content")
        j.nav("أمن البريد الإلكتروني")
        upload(j, control, "unrelated-control.eml")
        upload(j, content, "conflicting-authentication.eml")
        current = j.page.locator("section[id^=email-review-]").filter(has=j.page.get_by_role("heading", name="Forwarded authentication claims", exact=True))
        current.locator("summary").filter(has_text=j.text("رؤوس الرسالة")).click()
        auth = current.locator("dt").filter(has_text="Authentication-Results").locator("xpath=following-sibling::dd[1]")
        for text in ("forwarder.example.test", "edge.example.test", "spf=pass", "spf=fail", "dkim=pass", "dkim=fail"):
            expect(auth).to_contain_text(text)
        expect(current).to_contain_text(j.text("رأس المصادقة يذكر فشلًا؛ لم يُتحقق منه مستقلًا"))
        stored = next(item for item in reviews(j)["items"] if item["payload"]["title"] == "Forwarded authentication claims")
        assert stored["payload"]["sha256"] == hashlib.sha256(content).hexdigest()
        assert "not independently verified" in stored["payload"]["limitations"]
        control_row = next(item for item in reviews(j)["items"] if item["payload"]["title"] == "Unrelated maintenance notice")
        assert not control_row["payload"]["headers"]["Authentication-Results"]
        capture(j, result, folder, "conflicting-origins")
        note = (
            (
                "الرأسان المحفوظان متعارضان: forwarder.example.test يذكر spf=pass وdkim=pass؛ edge.example.test يذكر spf=fail وdkim=fail. "
                "أصل الثقة غير مثبت؛ لا تثبت الرسالة مصادقة المرسل ولا خبثه، ولم يُجرَ تحقق SPF أو DKIM مستقل. "
                if language == "ar"
                else "The retained headers conflict: forwarder.example.test claims spf=pass and dkim=pass; edge.example.test claims spf=fail and dkim=fail. "
                "Trusted origin is not established; this message proves neither sender authentication nor maliciousness. SPF/DKIM were not independently verified. "
            )
            + "SHA-256: "
            + hashlib.sha256(content).hexdigest()
        )
        followup = (
            "المتابعة المطلوبة: احصل من مسؤول البريد المخول على سجل البوابة الأصلية وتسلسل التحويل ومعرف الجهة التي أضافت كل رأس، ثم طابقها مع الرسالة المحفوظة قبل الحكم."
            if language == "ar"
            else "Required follow-up: obtain original trusted gateway logs, forwarding chain and the identity of each header-adding service from the authorized mail custodian, then correlate with the retained message before a verdict."
        )
        snapshot, saved = conclude(j, note, followup)
        capture(j, result, folder, "qualified-report-preview")
        result["outcomes"] = [
            "Both conflicting origins read in the UI",
            "Original EML hash retained",
            "Qualified conclusion linked to an open primary-evidence task",
            "Saved conclusion and follow-up read in report snapshot preview",
        ]
        result["saved_note_id"], result["report_id"] = saved["id"], snapshot["id"]


def upload_records(j, rows, filename):
    j.click("link", "السجلات والأدلة")
    body = json.dumps(rows).encode()
    j.page.locator("input[name=file]").set_input_files({"name": filename, "mimeType": "application/json", "buffer": body})
    j.click("button", "استيراد وفحص فوري")


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_periodicity_is_compared_with_maintenance_evidence(app, monkeypatch, language):
    with decision_session(app, monkeypatch, language, "AFTER-48") as (j, result, folder):
        regular = [zeek(i, uid=f"MAINT-{i}") for i in range(7)]
        irregular = [
            zeek(i, ts=1790000000 + offset, uid=f"CONTROL-{i}", **{"id.resp_h": "203.0.113.44"}) for i, offset in enumerate((0, 13, 70, 99, 240, 490, 900))
        ]
        maintenance = [
            {
                "title": "Approved maintenance window CHG-481",
                "timestamp": "2026-09-21T14:13:20Z",
                "change_reference": "CHG-481",
                "source_ip": "10.0.0.2",
                "destination_ip": "203.0.113.9",
                "message": "Retained change record: approved health heartbeat every 60 seconds from 10.0.0.2 to 203.0.113.9:443; window starts at epoch 1790000000 and lasts 600 seconds. Owner confirmation remains required; authorization does not establish host integrity.",
            }
        ]
        fixture(
            folder,
            result,
            "connection-observations.json",
            json.dumps(regular + irregular).encode(),
            "Seven periodic flows over six minutes plus seven irregular flows to a distinct reserved documentation address",
        )
        fixture(
            folder,
            result,
            "maintenance-record.json",
            json.dumps(maintenance).encode(),
            "Independent retained maintenance change record; not a generated threat verdict",
        )
        upload_records(j, regular + irregular, "connection-observations.json")
        upload_records(j, maintenance, "maintenance-record.json")
        row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name=maintenance[0]["title"], exact=True))
        j.click("button", "تفاصيل السجل", row)
        expect(j.page.get_by_role("dialog")).to_contain_text("CHG-481")
        expect(j.page.get_by_role("dialog")).to_contain_text("every 60 seconds")
        capture(j, result, folder, "maintenance-source")
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        j.click("link", "تحليل الأدلة")
        j.click("link", "الشبكة")
        row = j.page.locator(".network-results tbody tr").filter(has=j.page.get_by_role("button", name="203.0.113.9", exact=True))
        expect(row).to_contain_text("دوري" if language == "ar" else "Periodic")
        control = j.page.locator(".network-results tbody tr").filter(has=j.page.get_by_role("button", name="203.0.113.44", exact=True))
        expect(control).not_to_contain_text("دوري" if language == "ar" else "Periodic")
        j.click("button", "203.0.113.9", row)
        detail = j.page.locator(".network-detail")
        expected_percent = j.page.evaluate("new Intl.NumberFormat(SOCifyLocale.language).format(100)") + "%"
        expect(detail).to_contain_text(expected_percent)
        assert detail.locator(".evidence-links button").count() == 7
        snapshot = j.page.evaluate("id=>api(`/api/cases/${id}/network-insights`)", j.case_id)
        periodic = next(item for item in snapshot["items"] if item["destination_ip"] == "203.0.113.9")
        assert periodic["periodic"] and periodic["median_interval_seconds"] == 60
        assert not next(item for item in snapshot["items"] if item["destination_ip"] == "203.0.113.44")["periodic"]
        capture(j, result, folder, "periodic-versus-control")
        detail.locator(".evidence-links button").first.click()
        expect(j.page.get_by_role("dialog")).to_contain_text("MAINT-")
        expect(j.page.get_by_role("dialog")).to_contain_text('"ts": 1790000000')
        capture(j, result, folder, "underlying-connection")
        j.click("button", "إغلاق", j.page.get_by_role("dialog"))
        j.click("button", "203.0.113.44", control)
        expect(detail).to_contain_text("203.0.113.44")
        assert detail.locator(".evidence-links button").count() == 7
        note = (
            "الاتصالات السبعة إلى 203.0.113.9:443 بفاصل 60 ثانية تتوافق مع نافذة الصيانة CHG-481؛ الانتظام وحده لا يثبت C2 أو الاختراق. "
            "الاتصالات غير المنتظمة إلى 203.0.113.44 لا يغطيها سجل الصيانة وتحتاج تحديد مالكها. لا تثبت هذه البيانات سلامة الأجهزة أو رؤية حية."
            if language == "ar"
            else "Seven connections to 203.0.113.9:443 at 60-second intervals match maintenance window CHG-481; periodicity alone does not establish C2 or compromise. "
            "Irregular connections to 203.0.113.44 are not covered by that change record and need owner attribution. These records establish neither host integrity nor live visibility."
        )
        followup = (
            "المتابعة المطلوبة: تأكيد تنفيذ CHG-481 مع المالك المخول، وطلب بيانات العملية والهوية للاتصالات إلى 203.0.113.44 في الفترة نفسها؛ تبقى القضية مفتوحة."
            if language == "ar"
            else "Required follow-up: confirm CHG-481 execution with the authorized owner and obtain process/identity context for 203.0.113.44 in the same window; keep the case open."
        )
        report_snapshot, saved = conclude(j, note, followup)
        capture(j, result, folder, "qualified-report-preview")
        result["outcomes"] = [
            "Periodic group compared against distinct irregular control",
            "Underlying connection and independent maintenance source opened",
            "Qualified scheduling interpretation saved without declaring C2, safety or closure",
            "Pending follow-up retained and read in report snapshot preview",
        ]
        result["saved_note_id"], result["report_id"] = saved["id"], report_snapshot["id"]
