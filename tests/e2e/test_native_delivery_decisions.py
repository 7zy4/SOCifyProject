"""Scripted delivery decisions across real source, report and archive boundaries.

Synthetic retained events and an owned TLS peer are explicit fixtures, not people.
No approval, closure or renderer result is manufactured. Windows exercises the
available interface and records an incomplete native boundary; Linux continues
through the actual isolated analysis service configured by the browser CI job.
"""

import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import unicodedata
import zipfile
from contextlib import nullcontext
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from docx import Document
from playwright.sync_api import expect

from scripts.local_services import local_worker_services
from socify.timeutils import utc_now
from tests.e2e import test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import panel, record_dialog, workflow
from tests.e2e.test_case_membership_journeys import grant
from tests.e2e.test_investigation_link_journeys import choose
from tests.e2e.test_native_corrective_followup import approve, prepare
from tests.e2e.test_performance_decision_journeys import plain
from tests.e2e.test_performance_goal_journeys import counter, number, period
from tests.e2e.test_report_recovery_journeys import report, report_path
from tests.e2e.test_review_workflow import ANSWERS, review_session
from tests.e2e.test_source_goal_journeys import create_connector, send_records, visible_logs
from tests.e2e.test_source_lifecycle_journeys import source_actions, source_row
from tests.e2e.test_timeline_decision_journeys import local_input
from tests.integration.test_source_https_transport import tls_source  # noqa: F401 -- real owned TLS peer

ARTIFACTS = Path("artifacts/usability_campaign/native-delivery-decisions")
PUBLIC_URL = "https://raw.githubusercontent.com/7zy4/SOCifyProject/154c1ae8352b62e5fd2749f306c42ffddc7c3f22/fixtures/import/events.json"
# Pinned digest of the public fixture above, not an authentication credential.
PUBLIC_SHA256 = "4510583353c18c71f4ae84f44600c7d10f10ef3050241bad24d0477740bcbd57"  # pragma: allowlist secret
NATIVE = sys.platform == "linux"
# These are predefined scenario evidence, not approvals created to satisfy a
# report gate. No real person, signature, system execution or external owner is
# represented. Public telemetry alone does not prove this authorization.
AUTHORIZATION = {
    "NEXT-34": {
        "title": "Authorized replay scope EX-34",
        "source": "exercise-control",
        "timestamp": "2026-11-02T08:00:00Z",
        "event_type": "change_authorization",
        "change_reference": "EX-34",
        "authority": "Exercise controller (synthetic scenario role; not a human approval)",
        "scope": "Replay delivery-a and delivery-b at 2026-11-02T09:00:00Z for DELIVERY-GATEWAY, with powershell.exe -enc AAAA recorded only as text.",
        "execution": "Log replay only in an isolated investigation; no command executed on an endpoint.",
        "limitations": "Authorizes only this scoped replay; does not establish activity or compromise outside the retained records.",
    },
    "NEXT-36": {
        "title": "Authorized replay scope EX-36",
        "source": "exercise-control",
        "timestamp": "2026-10-15T01:00:00Z",
        "event_type": "change_authorization",
        "change_reference": "EX-36",
        "authority": "Exercise controller (synthetic scenario role; not a human approval)",
        "scope": "Replay json-1 and json-2 for amina at 2026-10-15T01:20:00Z and 01:21:00Z into an isolated investigation.",
        "source_url": PUBLIC_URL,
        "source_sha256": PUBLIC_SHA256,
        "execution": "Import the pinned evidence only; no live phishing message, account authentication or host command is executed.",
        "limitations": "The public records alone establish neither authorization nor attack success. This separate fixture authorizes only the isolated replay.",
    },
}
CONDITIONS = {
    "NEXT-23-export-missing-not-zero": {
        "goal": "Export evidenced zero response time without inventing containment or recovery measurements.",
        "interpretation": "A measured zero is different from an absent response stage; inspect source times and exported labels before using the summary.",
        "nearest": "test_calendar_decision_journeys.py:response-metric-render-contract; test_report_review_journeys.py",
        "novelty": "Actual PDF and DOCX preserve the semantics of a newly investigated case, beyond an in-app component contract.",
    },
    "NEXT-34-partial-transfer-review-gate": {
        "goal": "Verify a documented authorized replay, keep its approved report stable through an incomplete update, and independently review recovery before closing.",
        "interpretation": "The failed transfer is not new evidence and does not refresh the report. Accepted recovery needs a new review.",
        "nearest": "test_source_transport_decision_journeys.py:source-transport-truncated-decision",
        "novelty": "Independent approval and closure follow recovery; importer atomicity alone is insufficient.",
    },
    "NEXT-36-real-source-to-delivery": {
        "goal": "Verify an authorized replay using separate predefined scope evidence, then deliver the investigation from a pinned public source through independent review and reconciled performance.",
        "interpretation": "Successful delivery requires the investigator's supported decisions and a separate manager review, not merely a successful pull.",
        "nearest": "artifacts/usability_campaign/remote_pull_probe.py; test_procedure_goal_journeys.py:complete-case-closure",
        "novelty": "One uninterrupted source-to-delivery task with stable repeat pull and actual native report, not separate disconnected probes.",
    },
    "AFTER-39-restored-capsule-source-continuity": {
        "goal": "Review an approved historical archive locally, intentionally connect a new source, and create a distinct locally reviewed report.",
        "interpretation": "Foreign source identity and approval are historical evidence, not live credentials or local approval authority.",
        "nearest": "test_case_continuity_journeys.py:capsule-restore-archive; test_event_occurrence_identity.py",
        "novelty": "Real approved report in an archive, disconnected occurrence history, new local source and independent native review in one UI task.",
    },
}


@pytest.fixture
def evidence_context(monkeypatch):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", ARTIFACTS)


def describe(result):
    result.update(
        condition=CONDITIONS[result["scenario"]],
        plan_id="-".join(result["scenario"].split("-")[:2]),
        initial_interpretation=CONDITIONS[result["scenario"]]["interpretation"],
        human_participants=0,
        baseline="5303e6f",
        kind="scripted interpretation with interface review",
        count_as_new_semantic_condition=False,
        setup="Isolated seeded accounts; case and decisions created through UI; harmless retained fixture records. No fabricated approvals, closure or native formats.",
        completed_tasks=0,
    )
    if result["plan_id"] in AUTHORIZATION:
        result["predefined_scenario_evidence"] = AUTHORIZATION[result["plan_id"]]


def visit(j, case_id, tab="reports"):
    j.case_id, j.case_url = case_id, f"{j.base}/cases/{case_id}"
    j.page.goto(j.case_url + f"?tab={tab}")
    j.settle()


def manager_context(j, manager):
    manager.login("manager@socify.local")
    visit(manager, j.case_id)


def shot(j, result, label):
    path = ARTIFACTS / f"{result['scenario']}-{result['language']}-{label}.png"
    j.page.evaluate("scrollTo({top:0,behavior:'instant'})")
    j.page.screenshot(path=str(path), full_page=True, animations="disabled")
    result.setdefault("screenshots", []).append(str(path))


def capture(j, result):
    assert_accessible(j.page)
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        shot(j, result, f"outcome-{width}")


def finish(result, blocked=None):
    if blocked:
        result.update(
            status="partial_native_blocked",
            completed_tasks=0,
            completion_claim="Incomplete task; native deliverable or independent approval not verified.",
            native_blocker=blocked,
        )
    else:
        result.update(completed_tasks=1, completion_claim="One scripted task completed in this language; no human participant or clean-round claim.")
    (ARTIFACTS / f"{result['scenario']}-{result['language']}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if blocked:
        pytest.skip(blocked)


def upload(j, events, filename="delivery-evidence.json"):
    j.click("link", "السجلات والأدلة")
    content = json.dumps(events).encode()
    j.page.locator("input[name=file]").set_input_files({"name": filename, "mimeType": "application/json", "buffer": content})
    j.click("button", "استيراد وفحص فوري")
    expect(j.page.get_by_role("cell", name=events[0]["title"], exact=True)).to_be_visible()
    return hashlib.sha256(content).hexdigest()


def snapshot(j):
    if NATIVE:
        return prepare(j)
    j.click("link", "التقارير والمراجعة")
    j.click("button", "إعداد تقرير جديد")
    path = report_path(j)
    current = report(j, path)
    assert current["state"] == "draft" and not current["formats"]
    return path


def assessment(j, note, vector="ctf_or_offline_log_pack", impact_scope="no_compromise_blocked"):
    j.click("link", "التقارير والمراجعة")
    for name, value in {**ANSWERS, "initial_vector": vector, "impact_scope": impact_scope}.items():
        j.page.locator(f'select[name="{name}"]').select_option(value)
    j.page.locator("input[name=executive_note]").fill(note)
    j.click("button", "حفظ وتصعيد مباشر للمدير")


def complete_investigation(j, note, *, response=True, vector="ctf_or_offline_log_pack", evidence="", impact_scope="no_compromise_blocked"):
    assessment(j, note, vector, impact_scope)
    j.click("link", "التحقيق والخط الزمني")
    j.record("root_cause", {"category": "other", "conclusion": note, "evidence_id": evidence})
    if response:
        j.click("link", "الاستجابة والتصعيد")
        j.record("response", {"title": "Validate scoped retained activity", "phase": "validation", "status": "not_applicable", "details": note})
    j.transition("awaiting_review")
    while j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True).count():
        j.page.get_by_role("button", name=j.text("إكمال المهمة"), exact=True).first.click()
        j.settle()
    assert all(task["status"] in {"completed", "reviewed"} for task in j.state()["tasks"])


def milestone(j, phase, at):
    j.click("link", "الاستجابة والتصعيد")
    dialog = record_dialog(j, "response")
    dialog.locator("input[name=title]").fill(f"Gateway {phase}")
    for field, value in (("phase", phase), ("status", "succeeded")):
        dialog.locator(f"input[name={field}]").fill(j.page.evaluate("value=>autopsyLabel(value)", value))
    choose(j, dialog, "performed_by", j.page.evaluate("state.user.name"))
    dialog.locator("input[name=performed_at]").fill(local_input(j, at))
    dialog.locator("input[name=evidence_id]").press("ArrowDown")
    dialog.get_by_role("option").first.click()
    dialog.locator("textarea[name=details]").fill(
        "Detection and acknowledgement occurred at the same retained gateway instant; no containment or recovery event was recorded."
    )
    j.click("button", "حفظ", dialog)


def revision(j, path):
    retained = report(j, path)
    return j.page.locator(".report-revision").filter(has=j.page.get_by_text(f"SHA-256: {retained['sha256']}", exact=True))


def download(j, path, format_name):
    link = revision(j, path).get_by_role("link", name=j.text(f"تنزيل {format_name.upper()}"), exact=True)
    expect(link).to_have_attribute("href", f"{path}/files/{format_name}")
    with j.page.expect_download() as pending:
        link.click()
    return Path(pending.value.path()).read_bytes()


def normalized_text(text):
    text = unicodedata.normalize("NFKC", text)
    return "".join(str(unicodedata.decimal(char)) if char.isdecimal() else char for char in text if unicodedata.category(char) != "Cf").replace("٫", ".")


def assert_pdf_cell(text, caption, expected):
    """Read a whole labelled value; a zero inside 10/30/120 is never zero."""
    label = "".join(normalized_text(caption).split())
    values = []
    for line in normalized_text(text).splitlines():
        compact = "".join(line.split())
        for candidate in (label, label[::-1]):
            if candidate in compact:
                values.append(compact.replace(candidate, "", 1).strip(":|"))
                break
    assert values, f"Missing exported metric: {caption}"
    for value in values:
        if isinstance(expected, Decimal):
            assert re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value), (caption, value)
            assert Decimal(value) == expected, (caption, value, expected)
        else:
            expected_text = "".join(normalized_text(expected).split())
            assert value in (expected_text, expected_text[::-1]), (caption, value, expected)


def read_preview(j, path, result, markers):
    """Expand relevant sections by visible controls, before inspecting exports."""
    card = revision(j, path)
    outer = card.locator("summary").filter(has_text=j.text("عرض بيانات النسخة للمراجعة"))
    if outer.locator("..").get_attribute("open") is None:
        outer.click()
    preview = card.locator(".report-preview")
    for caption in ("بيانات القضية ونطاق التحقيق", "قرارات التحقيق", "الأصول المستوردة وإصدارات المعالجة", "سجلات التحقيق"):
        section = preview.locator(":scope > dl > dt").filter(has_text=j.text(caption)).locator("+ dd")
        # Each synthetic report has bounded evidence. Only visible summary
        # controls are clicked; no DOM-open mutation or hidden-text read.
        for _ in range(100):
            index = section.locator("details").evaluate_all("items => items.findIndex(item => !item.open && item.getClientRects().length > 0)")
            if index < 0:
                break
            detail = section.locator("details").nth(index)
            detail.locator(":scope > summary").click()
            expect(detail).to_have_attribute("open", "")
            expect(detail.locator(":scope > dl, :scope > p").first).to_be_visible()
        assert not section.locator("details:not([open]) > summary:visible").count(), caption
    for marker in markers:
        expect(preview.get_by_text(marker, exact=False).first).to_be_visible()
        assert marker in preview.inner_text(), marker
    result.setdefault("report_previews", []).append({"report": path, "markers": list(markers), "approved_before_review": False})


def review_native_report(manager, path, result, markers):
    """Read the intended revision and actual files before granting approval."""
    visit(manager, manager.case_id)
    before = report(manager, path)
    assert before["state"] == "draft" and before["source_version"] == manager.state()["version"]
    assert before["created_by"] != manager.page.evaluate("state.user.id")
    expected = [before["payload"]["case"]["reference"], *markers]
    read_preview(manager, path, result, expected)
    docx_content, pdf_content = download(manager, path, "docx"), download(manager, path, "pdf")
    document = Document(io.BytesIO(docx_content))
    cells = [tuple(cell.text for cell in row.cells) for table in document.tables for row in table.rows]
    docx_text = "\n".join([*(paragraph.text for paragraph in document.paragraphs), *(cell for row in cells for cell in row)])
    assert pdf_content.startswith(b"%PDF-")
    suffix = path.rsplit("/", 1)[-1]
    basename = ARTIFACTS / f"{result['scenario']}-{result['language']}-report-{suffix}"
    pdf_path = basename.with_suffix(".pdf")
    pdf_path.write_bytes(pdf_content)
    basename.with_suffix(".docx").write_bytes(docx_content)
    executable = shutil.which("pdftotext")
    if not executable:
        finish(result, "Downloaded actual draft files, but native semantic review and approval are blocked: pdftotext is not installed.")
    exported = subprocess.run(  # noqa: S603 -- discovered executable, fixed arguments and owned PDF
        [executable, "-layout", "-enc", "UTF-8", str(pdf_path), "-"], capture_output=True, check=True
    ).stdout.decode("utf-8")
    basename.with_suffix(".txt").write_text(exported, encoding="utf-8")
    compact_pdf = "".join(normalized_text(exported).split())
    for marker in expected:
        assert marker in docx_text, ("DOCX missing case fact", marker)
        compact_marker = "".join(normalized_text(marker).split())
        assert compact_marker in compact_pdf or compact_marker[::-1] in compact_pdf, ("PDF missing case fact", marker)
    assert report(manager, path)["state"] == "draft"
    result.setdefault("native_content_reviews", []).append(
        {
            "report": path,
            "source_version": before["source_version"],
            "markers": expected,
            "pdf_sha256": hashlib.sha256(pdf_content).hexdigest(),
            "docx_sha256": hashlib.sha256(docx_content).hexdigest(),
            "state_during_review": "draft",
        }
    )
    return pdf_content, docx_content, cells, exported


def approve_reviewed_report(manager, path):
    # The existing UI helper uses the first card; enforce its exact identity.
    expect(manager.page.locator(".report-revision").first.locator("bdi").first).to_have_text(f"SHA-256: {report(manager, path)['sha256']}")
    approve(manager)
    approved = report(manager, path)
    assert approved["state"] == "approved" and approved["approved_by"] != approved["created_by"]


def reject_unreviewed_close(manager, path, result, prior_path):
    before = manager.state()
    assert before["status"] == "awaiting_review" and report(manager, path)["state"] == "draft"
    if NATIVE:
        # Isolate the stale-approval gate; another missing prerequisite must
        # not accidentally be the reason this native closure is rejected.
        assert manager.page.locator(".closure-requirements li").all_text_contents() == [manager.text("تقرير كامل معتمد مطابق لإصدار القضية الحالي")]
    with manager.page.expect_response(lambda response: response.url.endswith("/quick-report/acknowledge") and response.request.method == "POST") as pending:
        manager.decision("closed", "Attempt delivery using the earlier report approval; current recovered evidence still requires review.")
    assert pending.value.status == 409 and pending.value.json()["error"]["code"] == "CASE_CLOSURE_INCOMPLETE"
    expect(manager.page.locator(".closure-requirements")).to_have_attribute("open", "")
    expect(manager.page.locator(".closure-requirements")).to_contain_text(manager.text("تقرير كامل معتمد مطابق لإصدار القضية الحالي"))
    expect(manager.page.get_by_role("alert")).to_contain_text(manager.text("أكمل متطلبات الإغلاق"))
    after = manager.state()
    assert after["status"] == before["status"] and after["version"] == before["version"]
    assert report(manager, path)["state"] == "draft"
    result["unreviewed_close_rejected"] = {
        "prior_report_state": report(manager, prior_path)["state"],
        "current_report": path,
        "case_version_unchanged": True,
        "native_prior_approval_verified": NATIVE,
    }
    shot(manager, result, "current-report-review-required")
    # Rejected form retains its text. Acknowledge only the local navigation
    # discard prompt before returning to the performance and review screens.
    manager.page.once("dialog", lambda dialog: dialog.accept())
    performance(manager, result, 0)
    visit(manager, manager.case_id)


def assert_report_unchanged(j, path, prior):
    actual = report(j, path)
    assert actual["payload"] == prior["payload"] and actual["sha256"] == prior["sha256"]


def pull(j, expected_status=200):
    j.click("link", "السجلات والأدلة")
    with j.page.expect_response(lambda response: response.url.endswith("/pull") and response.request.method == "POST") as pending:
        j.click("button", "سحب السجلات الآن", source_row(j))
    response = pending.value
    assert response.status == expected_status, response.json()
    return response.json()


def endpoint(j, url):
    j.click("link", "السجلات والأدلة")
    j.click("button", "تعديل المصدر", source_actions(j))
    dialog = j.page.get_by_role("dialog")
    dialog.locator("input[name=endpoint]").fill(url)
    j.click("button", "حفظ", dialog)


def inspect_alert(j, expected):
    j.nav("المراقبة")
    row = j.page.locator(".monitoring-table > tbody > tr").filter(has=j.page.locator(f"a.case-link[href='/cases/{j.case_id}']")).first
    row.locator("[data-alert-toggle]").click()
    j.settle()
    expect(j.page.locator(".dossier-view")).to_contain_text(expected)
    assert j.page.locator(".dossier-view table").count() > 0
    j.click("link", "مراجعة التنبيه", row.locator("+ tr"))


def inspect_authorization(j, record):
    j.click("link", "السجلات والأدلة")
    row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name=record["title"], exact=True))
    j.click("button", "تفاصيل السجل", row)
    dialog = j.page.get_by_role("dialog")
    expect(dialog.locator("pre")).to_contain_text(record["change_reference"])
    expect(dialog.locator("pre")).to_contain_text(record["scope"])
    expect(dialog.locator("pre")).to_contain_text(record["limitations"])
    j.click("button", "إغلاق", dialog)


def add_authorization(j, result, key):
    record = AUTHORIZATION[key]
    filename = f"{key}-exercise-authorization.json"
    upload(j, [record], filename)
    inspect_authorization(j, record)
    shot(j, result, "authorization-evidence-reviewed")
    result["authorization_evidence"] = {"filename": filename, "facts": record, "human_approvals": 0}
    return filename


def review_alerts(j, reason, verdict="benign"):
    j.click("link", "التحليل")
    j.click("link", "الكشف")
    controls = j.page.get_by_role("button", name=j.text("تفاصيل ومراجعة"), exact=True)
    assert controls.count() > 0
    for index in range(controls.count()):
        controls.nth(index).click()
        dialog = j.page.get_by_role("dialog")
        dialog.locator("input[name=verdict]").fill(j.page.evaluate("value=>autopsyLabel(value)", verdict))
        dialog.locator("input[name=attack_outcome]").fill(j.page.evaluate("autopsyLabel('unknown')"))
        dialog.locator("textarea[name=reason]").fill(reason)
        j.click("button", "حفظ", dialog)
        expect(dialog).not_to_be_visible()
    alerts = j.page.evaluate("id=>api(`/api/cases/${id}/alerts`)", j.case_id)["items"]
    assert all(row["review"]["verdict"] == verdict for row in alerts)


def performance(j, result, closed):
    j.nav("الأداء")
    period(j, "7")
    assert counter(j, "أغلقت خلال الفترة") == closed
    assert number(j.page.get_by_text(j.text("تنبيهات دون قرار"), exact=True).locator("+ dd").inner_text()) == 0
    result.setdefault("performance", []).append(
        {"closed": closed, "completion": plain(j.page.locator("[data-completion-value]").inner_text()), "visible": j.page.locator("main").inner_text()}
    )
    shot(j, result, f"performance-{closed}")


def approve_and_close(manager, path, result, markers):
    content, _, _, _ = review_native_report(manager, path, result, markers)
    approve_reviewed_report(manager, path)
    manager.decision("closed", "Independently reviewed the retained source evidence, investigation decisions and this complete native report.")
    assert manager.state()["status"] == "closed"
    result["approved_delivery"] = {"case_id": manager.case_id, "report": path, "pdf_sha256": hashlib.sha256(content).hexdigest()}


def native_blocker():
    return (
        None
        if NATIVE
        else "Windows has no isolated Linux report renderer (libgobject/WeasyPrint runtime); native files, approval and closure are not verified."
    )


@pytest.mark.e2e
@pytest.mark.usefixtures("evidence_context")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_export_preserves_measured_zero_and_absent_response(app, language):
    scenario = "NEXT-23-export-missing-not-zero"
    blocked = native_blocker()
    with local_worker_services(app.config) if NATIVE else nullcontext(), review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        at = (utc_now() - timedelta(hours=1)).replace(second=0, microsecond=0).isoformat()
        digest = upload(j, [{"title": "Gateway detection and acknowledgement", "timestamp": at, "hostname": "DELIVERY-GATEWAY"}])
        for phase in ("detection", "acknowledgement"):
            milestone(j, phase, at)
        metrics = workflow(j)["metrics"]
        assert metrics["acknowledgement_delay_seconds"] == 0 and metrics["containment_delay_seconds"] is None
        complete_investigation(
            j, "The retained gateway confirms simultaneous detection and acknowledgement; containment and recovery are unmeasured.", response=False
        )
        path = snapshot(j)
        before = report(j, path)
        assert before["payload"]["metrics"]["acknowledgement_delay_seconds"] == 0
        assert before["payload"]["metrics"]["containment_delay_seconds"] is None
        assert before["payload"]["imports"][0]["sha256"] == digest
        manager_context(j, manager)
        manager.click("link", "الاستجابة والتصعيد")
        manager.page.locator(".response-metrics summary").click()
        expect(manager.page.locator("[data-response-duration=acknowledgement_delay_seconds]")).to_have_text(
            manager.page.evaluate("new Intl.NumberFormat(SOCifyLocale.language).format(0)")
        )
        expect(manager.page.locator("[data-response-duration=containment_delay_seconds]")).to_have_text(manager.text("غير مقاس"))
        shot(manager, result, "reviewed-zero-and-missing")
        visit(manager, j.case_id)
        if NATIVE:
            pdf_content, docx_content, cells, exported = review_native_report(
                manager, path, result, [digest, "simultaneous detection and acknowledgement", "containment and recovery are unmeasured"]
            )
            assert any(digest in cell for row in cells for cell in row), "DOCX must retain the source evidence digest"
            assert ("المدة حتى الإقرار بالثواني", "0.0") in cells or ("المدة حتى الإقرار بالثواني", "0") in cells
            assert ("المدة حتى الاحتواء بالثواني", "غير قابل للحساب") in cells
            assert ("المدة حتى التعافي بالثواني", "غير قابل للحساب") in cells
            assert_pdf_cell(exported, "المدة حتى الإقرار بالثواني", Decimal(0))
            for caption in ("المدة حتى الاحتواء بالثواني", "المدة حتى التعافي بالثواني"):
                assert_pdf_cell(exported, caption, "غير قابل للحساب")
            approve_reviewed_report(manager, path)
            result["export_semantics"] = {
                "pdf": hashlib.sha256(pdf_content).hexdigest(),
                "docx": hashlib.sha256(docx_content).hexdigest(),
                "zero_is_measured": True,
                "absent_stages_not_zero": True,
                "semantics_reviewed_before_approval": True,
            }
        assert_report_unchanged(manager, path, before)
        result["actual_outcome"] = {"report": path, "source_sha256": digest, "metrics": before["payload"]["metrics"]}
        capture(manager, result)
    finish(result, blocked)


@pytest.mark.e2e
@pytest.mark.usefixtures("evidence_context")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_partial_source_transfer_needs_fresh_independent_review(app, monkeypatch, tls_source, language):  # noqa: F811
    scenario = "NEXT-34-partial-transfer-review-gate"
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "siem.example")
    first = {
        "external_id": "delivery-a",
        "timestamp": "2026-11-02T09:00:00Z",
        "title": "Retained authorized encoded process",
        "hostname": "DELIVERY-GATEWAY",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
    }
    second = {**first, "external_id": "delivery-b", "title": "Recovered complete source marker"}
    tls_source["responses"]["body"] = (json.dumps(first) + "\n").encode()
    with local_worker_services(app.config) if NATIVE else nullcontext(), review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        result["transport_scope"] = (
            "Owned TLS peer with trusted test certificate and controlled DNS/address routing; real HTTP/TLS transfer, not a vendor service."
        )
        manager_context(j, manager)
        create_connector(manager, tls_source["url"] + "/events")
        assert pull(manager)["accepted"] == 1
        visit(j, j.case_id, "logs")
        inspect_alert(j, "DELIVERY-GATEWAY")
        review_alerts(
            j, "Encoded command text requires scope verification; the command string alone does not establish authorization or execution.", "undetermined"
        )
        authorization_file = add_authorization(j, result, "NEXT-34")
        review_alerts(
            j,
            "EX-34 independently documents a scoped log replay for delivery-a/delivery-b on DELIVERY-GATEWAY. Only that replay is benign; the records prove neither command execution nor wider compromise.",
        )
        complete_investigation(
            j,
            "EX-34 authorizes this isolated log replay. Encoded command text is retained evidence, not proof of execution. Review is limited to the accepted source export and documented replay scope.",
            vector="siem_builtin_rule",
            evidence=authorization_file,
            impact_scope="single_user_or_host",
        )
        first_path = snapshot(j)
        visit(manager, j.case_id)
        if NATIVE:
            inspect_authorization(manager, AUTHORIZATION["NEXT-34"])
            original_pdf, _, _, _ = review_native_report(
                manager,
                first_path,
                result,
                [
                    authorization_file,
                    "EX-34 authorizes this isolated log replay",
                    "not proof of execution",
                    hashlib.sha256(tls_source["responses"]["body"]).hexdigest(),
                ],
            )
            approve_reviewed_report(manager, first_path)
        prior = report(manager, first_path)
        endpoint(manager, tls_source["url"] + "/truncated")
        tls_source["responses"]["body"] = (json.dumps(first) + "\n" + json.dumps(second) + "\n").encode()
        baseline = manager.state()
        failure = pull(manager, 422)
        expect(manager.page.locator("#global-message")).to_be_visible()
        shot(manager, result, "incomplete-transfer-error")
        assert manager.state()["version"] == baseline["version"] and manager.state()["evidence"] == baseline["evidence"]
        assert visible_logs(manager)["total"] == 2
        assert_report_unchanged(manager, first_path, prior)
        shot(manager, result, "failed-transfer-preserves-evidence")
        result["failed_transfer"] = {"error": failure, "retained_count": 2, "source_events": 1, "authorization_records": 1, "old_report_unchanged": True}
        endpoint(manager, tls_source["url"] + "/events")
        recovered = pull(manager)
        assert recovered["accepted"] == 1 and recovered["skipped"] == 1
        assert visible_logs(manager)["total"] == 3
        visit(j, j.case_id)
        inspect_authorization(j, AUTHORIZATION["NEXT-34"])
        review_alerts(
            j,
            "Recovered delivery-b is covered by the same EX-34 scope as delivery-a: this is a permitted isolated log replay. No live execution or attack outcome is inferred.",
        )
        assessment(
            j,
            "The complete export now retains delivery-a and delivery-b, both within the separate EX-34 replay scope. No command execution or attack outcome is inferred; review includes the authorization evidence.",
            "siem_builtin_rule",
            impact_scope="single_user_or_host",
        )
        assert j.state()["status"] == "escalated"
        j.transition("awaiting_review")
        assert j.state()["status"] == "awaiting_review"
        second_path = snapshot(j)
        current = report(j, second_path)
        assert second_path != first_path and current["state"] == "draft"
        assert current["source_version"] == j.state()["version"]
        assert current["payload"]["summary"]["counts"]["normalized_logs"] == 3
        recovery_digest = hashlib.sha256(tls_source["responses"]["body"]).hexdigest()
        assert recovery_digest in {item["sha256"] for item in current["payload"]["imports"]}
        assert_report_unchanged(j, first_path, prior)
        visit(manager, j.case_id)
        shot(manager, result, "new-snapshot-awaits-review")
        reject_unreviewed_close(manager, second_path, result, first_path)
        assert_report_unchanged(manager, first_path, prior)
        if NATIVE:
            assert report(manager, first_path)["state"] == "approved"
        read_preview(
            manager,
            second_path,
            result,
            [authorization_file, recovery_digest, "delivery-a and delivery-b", "No command execution or attack outcome is inferred"],
        )
        if NATIVE:
            approve_and_close(
                manager,
                second_path,
                result,
                [authorization_file, recovery_digest, "delivery-a and delivery-b", "No command execution or attack outcome is inferred"],
            )
            preserved = manager.page.request.get(manager.base + first_path + "/files/pdf")
            assert preserved.ok and preserved.body() == original_pdf
            performance(manager, result, 1)
        else:
            assert manager.state()["status"] != "closed"
            performance(manager, result, 0)
        result["actual_outcome"] = {"previous_report": first_path, "new_report": second_path, "accepted_recovery": recovered, "old_snapshot_unchanged": True}
        capture(manager, result)
    finish(result, native_blocker())


@pytest.mark.e2e
@pytest.mark.usefixtures("evidence_context")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_public_source_reaches_native_delivery_and_performance(app, monkeypatch, language):
    scenario = "NEXT-36-real-source-to-delivery"
    monkeypatch.setenv("SOCIFY_SOURCE_ALLOWLIST", "raw.githubusercontent.com")
    with local_worker_services(app.config) if NATIVE else nullcontext(), review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        result["public_fixture"] = {
            "url": PUBLIC_URL,
            "sha256": PUBLIC_SHA256,
            "scope": "Actual public read-only HTTPS fixture; no real SIEM credentials, pagination or operational vendor guarantee.",
        }
        manager_context(j, manager)
        manager.click("link", "الاستجابة والتصعيد")
        form = panel(manager, "SLA وجمع الأدلة ومراجعة ما بعد الحادثة").locator("form").filter(has=manager.page.locator("input[name=minutes]"))
        form.locator("input[name=minutes]").fill("120")
        form.locator("input[name=reason]").fill("Two-hour continuous review target agreed for this isolated retained evidence case.")
        manager.click("button", "حفظ", form)
        connector = create_connector(manager, PUBLIC_URL)
        delivered = pull(manager)
        assert delivered["accepted"] == 2 and delivered["alerts_triggered"] > 0
        assert visible_logs(manager)["total"] == 2
        prior = manager.state()
        repeated = pull(manager)
        assert repeated["accepted"] == 0 and repeated["skipped"] == 2
        assert manager.state()["version"] == prior["version"] and manager.state()["evidence"] == prior["evidence"]
        visit(j, j.case_id, "logs")
        inspect_alert(j, "amina")
        review_alerts(
            j,
            "The records show phishing_email then failed_login for amina one minute later. They do not establish authorization or attack success; obtain independent scope evidence before concluding.",
            "undetermined",
        )
        authorization_file = add_authorization(j, result, "NEXT-36")
        review_alerts(
            j,
            "EX-36 covers only replay of json-1/json-2 for amina at the retained times and pinned source digest. This scoped replay is benign; the public records alone prove neither authorization nor attack success.",
        )
        complete_investigation(
            j,
            "EX-36 independently authorizes replay of the pinned two records for amina. The source shows a phishing classification followed by a failed-login record; it does not prove attack success or activity beyond the authorized replay. No live containment action is asserted.",
            vector="siem_builtin_rule",
            evidence=authorization_file,
            impact_scope="single_user_or_host",
        )
        path = snapshot(j)
        retained = report(j, path)
        assert PUBLIC_SHA256 in {item["sha256"] for item in retained["payload"]["imports"]}
        assert retained["payload"]["summary"]["counts"]["normalized_logs"] == 3
        assert all(alert["review"]["verdict"] == "benign" and "EX-36" in alert["review"]["reason"] for alert in retained["payload"]["alerts"])
        assert retained["payload"]["alerts"]
        result["matching_rules"] = [alert["title"] for alert in retained["payload"]["alerts"]]
        assert any("Phishing" in name or "phishing" in name for name in result["matching_rules"])
        performance(manager, result, 0)
        if NATIVE:
            visit(manager, j.case_id)
            inspect_authorization(manager, AUTHORIZATION["NEXT-36"])
            approve_and_close(
                manager,
                path,
                result,
                [PUBLIC_SHA256, authorization_file, "EX-36 independently authorizes replay", "amina", "does not prove attack success"],
            )
            assert workflow(manager)["sla"]["status"] == "closed"
            performance(manager, result, 1)
            assert plain(manager.page.locator("[data-completion-value]").inner_text()) == "100%"
            assert counter(manager, "بانتظار المراجعة") == 0 and counter(manager, "مهام معلقة") == 0
        else:
            assert manager.state()["status"] != "closed" and retained["state"] == "draft"
        assert_report_unchanged(manager, path, retained)
        result["actual_outcome"] = {
            "case_id": j.case_id,
            "source_id": connector["id"],
            "report": path,
            "rule_alert_count": len(retained["payload"]["alerts"]),
            "repeat": repeated,
        }
        capture(manager, result)
    finish(result, native_blocker())


@pytest.mark.e2e
@pytest.mark.usefixtures("evidence_context")
@pytest.mark.parametrize("language", ["ar", "en"])
def test_restored_archive_requires_local_source_and_local_approval(app, language):
    scenario = "AFTER-39-restored-capsule-source-continuity"
    with local_worker_services(app.config) if NATIVE else nullcontext(), review_session(app, language, scenario) as (j, manager, result):
        describe(result)
        manager_context(j, manager)
        old_case = j.case_id
        source = create_connector(manager)
        events = [{"title": "Retained source occurrence", "hostname": "ARCHIVED-GATEWAY", "timestamp": "2026-11-02T09:00:00Z"}] * 2
        payload = json.dumps({"events": events}).encode()
        code, imported = send_records(j.base, source, payload)
        assert code == 201 and imported["accepted"] == 2
        assert visible_logs(manager)["total"] == 2
        visit(j, old_case)
        complete_investigation(j, "Two retained occurrences document authorized gateway activity; both remain in the original source history.")
        old_path = snapshot(j)
        old_report = report(j, old_path)
        assert old_report["payload"]["summary"]["counts"]["normalized_logs"] == 2
        visit(manager, old_case)
        if NATIVE:
            old_pdf, _, _, _ = review_native_report(
                manager,
                old_path,
                result,
                [hashlib.sha256(payload).hexdigest(), "Two retained occurrences", "both remain in the original source history"],
            )
            approve_reviewed_report(manager, old_path)
            assert report(manager, old_path)["state"] == "approved"
            with manager.page.expect_download() as pending:
                manager.page.get_by_role("link", name=manager.text("تنزيل نسخة كاملة حساسة"), exact=True).click()
            capsule = Path(pending.value.path()).read_bytes()
            capsule_hash = hashlib.sha256(capsule).hexdigest()
            with zipfile.ZipFile(io.BytesIO(capsule)) as archive:
                pdf_member = next(name for name in archive.namelist() if name.startswith("reports/") and name.endswith("/pdf"))
                assert archive.read(pdf_member) == old_pdf
            manager.click("link", "استعادة حزمة كقضية جديدة")
            manager.page.get_by_label(manager.text("حزمة قضية محلية"), exact=True).set_input_files(
                {"name": "retained-delivery.zip", "mimeType": "application/zip", "buffer": capsule}
            )
            manager.click("button", "استعادة كقضية جديدة")
            manager.page.wait_for_url("**/cases/*?tab=reports")
            restored_id = int(re.search(r"/cases/(\d+)", manager.page.url)[1])
            visit(manager, restored_id)
            assert restored_id != old_case and manager.state()["status"] == "open"
            assert not manager.state()["reports"]
            assert manager.page.evaluate("id=>api(`/api/cases/${id}/siem-connectors`)", restored_id)["items"] == []
            assert visible_logs(manager)["total"] == 2
            manager.click("link", "التقارير والمراجعة")
            manager.click("button", "فحص الأرشيف")
            dialog = manager.page.get_by_role("dialog")
            dialog.locator("select[name=section]").select_option("autopsy_reports")
            expect(dialog.locator("pre")).to_contain_text('"approved"')
            shot(manager, result, "historical-approval-is-not-local")
            manager.click("button", "إغلاق", dialog)
            archives = manager.page.evaluate("id=>api(`/api/cases/${id}/capsules`)", restored_id)["items"]
            assert archives[0]["sha256"] == capsule_hash
            archive_file = f"/api/cases/{restored_id}/capsules/{archives[0]['id']}/file/{pdf_member}"
            assert manager.page.request.get(manager.base + archive_file).body() == old_pdf
            grant(manager, j.page.evaluate("state.user.name"))
            visit(j, restored_id)
            complete_investigation(
                j,
                "Historical source occurrences independently reviewed locally. Foreign approval does not authorize local closure or reconnect the previous source.",
            )
            local_path = snapshot(j)
            visit(manager, restored_id)
            review_native_report(
                manager,
                local_path,
                result,
                [
                    hashlib.sha256(payload).hexdigest(),
                    "Historical source occurrences independently reviewed locally",
                    "Foreign approval does not authorize local closure",
                ],
            )
            approve_reviewed_report(manager, local_path)
            locally_approved = report(manager, local_path)
            assert locally_approved["state"] == "approved"
            new_source = create_connector(manager)
            assert new_source["id"] != source["id"] and new_source["ingest_key"] != source["ingest_key"]
            new_payload = json.dumps(
                {"events": [{"external_id": "local-new", "title": "New locally authorized gateway evidence", "hostname": "LOCAL-GATEWAY"}]}
            ).encode()
            rejected_code, _ = send_records(j.base, new_source, new_payload, token=source["ingest_key"])
            assert rejected_code == 401, "An archived source credential must not authorize the newly registered local source"
            assert visible_logs(manager)["total"] == 2
            code, imported = send_records(j.base, new_source, new_payload)
            assert code == 201 and imported["accepted"] == 1
            assert visible_logs(manager)["total"] == 3
            sources = manager.page.evaluate("id=>api(`/api/cases/${id}/siem-connectors`)", restored_id)["items"]
            assert [item["id"] for item in sources] == [new_source["id"]]
            visit(j, restored_id)
            assessment(
                j, "A deliberately registered local source added one authorized gateway event; historical occurrences remain disconnected and preserved."
            )
            assert j.state()["status"] == "escalated"
            j.transition("awaiting_review")
            assert j.state()["status"] == "awaiting_review"
            final_path = snapshot(j)
            assert final_path != local_path and report(j, final_path)["state"] == "draft"
            assert report(j, final_path)["source_version"] == j.state()["version"]
            assert report(j, final_path)["payload"]["summary"]["counts"]["normalized_logs"] == 3
            assert_report_unchanged(j, local_path, locally_approved)
            visit(manager, restored_id)
            approve_and_close(
                manager,
                final_path,
                result,
                [
                    hashlib.sha256(new_payload).hexdigest(),
                    "local source added one authorized gateway event",
                    "historical occurrences remain disconnected and preserved",
                ],
            )
            assert manager.page.request.get(manager.base + archive_file).body() == old_pdf
            assert_report_unchanged(manager, old_path, old_report)
            assert manager.page.evaluate("id=>api(`/api/cases/${id}/logs`)", old_case)["total"] == 2
            assert hashlib.sha256(capsule).hexdigest() == capsule_hash
            result["actual_outcome"] = {
                "source_case": old_case,
                "restored_case": restored_id,
                "capsule_sha256": capsule_hash,
                "old_source": source["id"],
                "new_source": new_source["id"],
                "local_report": local_path,
                "final_report": final_path,
                "foreign_approval_trusted": False,
            }
            performance(manager, result, 1)
        else:
            result["actual_outcome"] = {
                "source_case": old_case,
                "retained_occurrences": 2,
                "draft_report": old_path,
                "not_run": [
                    "real approval of source report",
                    "approved capsule export and restore",
                    "local independent review",
                    "new source continuity",
                    "native closure",
                ],
            }
            assert manager.state()["status"] != "closed"
        capture(manager, result)
    finish(result, native_blocker())
