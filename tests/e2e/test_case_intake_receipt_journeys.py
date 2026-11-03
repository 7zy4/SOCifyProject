"""Begin a first investigation despite an interrupted creation response."""

import time

import pytest
from playwright.sync_api import expect

from tests.e2e.test_assignment_handoff_journeys import role_permission
from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_case_task_backlog_journeys import task_row
from tests.e2e.test_followup_handoff_journeys import evidence_images
from tests.e2e.test_investigation_link_journeys import note_dialog, records
from tests.e2e.test_review_workflow import review_session
from tests.e2e.test_scope_selection_journeys import approve

TITLE = "Gateway incident requiring investigation"
OBJECTIVE = "Establish the affected identities and document the response decision"


def cases(j):
    return j.page.evaluate("() => api('/api/cases?page_size=100')")["items"]


def open_intake(j, queued=False):
    j.click("button", "إيداع في طابور الفريق" if queued else "إنشاء قضية")
    dialog = j.page.get_by_role("dialog")
    dialog.locator("input[name=title]").fill(TITLE)
    dialog.locator("[name=objective]").fill(OBJECTIVE)
    return dialog


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize(
    "scenario",
    [
        "case-intake-receipt-lost",
        "case-queue-receipt-lost",
        "case-intake-pending-edit",
        "case-intake-reload",
        "case-intake-language-recovery",
        "case-intake-malformed-receipt",
        "case-intake-repeated-loss",
        "case-intake-changed-intent",
        "case-intake-same-title-new-case",
        "case-intake-permission-recovery",
        "case-queue-colleague-claim",
        "case-intake-approval-after-retry",
        "case-intake-from-logs",
        "case-intake-destination-recovery",
        "case-intake-storage-disabled",
    ],
)
def test_new_investigator_recovers_the_original_case(app, language, scenario):
    if scenario == "case-intake-approval-after-retry":
        app.config["REQUIRE_CASE_APPROVAL"] = True
    with review_session(app, language, scenario, create_case=False) as (j, manager, result):
        before = cases(j)
        queued = scenario in {"case-queue-receipt-lost", "case-queue-colleague-claim"}
        if scenario == "case-intake-from-logs":
            j.nav("إدارة السجلات")
        if scenario == "case-intake-storage-disabled":
            j.page.evaluate("Object.defineProperty(window, 'sessionStorage', {get() {throw new DOMException('Blocked', 'SecurityError')}})")
        dialog = open_intake(j, queued=queued)
        committed = []

        def intercept(route):
            response = route.fetch()
            assert response.status == 201, response.text()
            committed.append((response.json(), route, response))
            if scenario == "case-intake-malformed-receipt":
                route.fulfill(status=201, content_type="application/json", body="{interrupted")
            elif scenario == "case-intake-destination-recovery":
                j.page.route(
                    f"**/cases/{response.json()['id']}",
                    lambda request: request.fulfill(status=503, content_type="text/html", body="<main>Service unavailable</main>"),
                    times=1,
                )
                route.fulfill(response=response)
            elif scenario != "case-intake-pending-edit":
                route.abort()

        j.page.route("**/api/cases", intercept, times=2 if scenario == "case-intake-repeated-loss" else 1)
        dialog.get_by_role("button", name=j.text("حفظ"), exact=True).click()
        deadline = time.monotonic() + 10
        while not committed and time.monotonic() < deadline:
            j.page.wait_for_timeout(50)
        assert len(committed) == 1
        if scenario == "case-intake-pending-edit":
            try:
                expect(dialog.locator("input[name=title]")).to_be_disabled()
                expect(dialog.locator("[name=objective]")).to_be_disabled()
            finally:
                committed[0][1].fulfill(response=committed[0][2])
                j.page.wait_for_url(f"**/cases/{committed[0][0]['id']}")
                j.settle()
        elif scenario == "case-intake-destination-recovery":
            j.page.wait_for_url(f"**/cases/{committed[0][0]['id']}")
            expect(j.page.locator("main")).to_have_text("Service unavailable")
            j.page.go_back()
            j.settle()
            j.click("link", TITLE)
        else:
            j.settle()
            expect(dialog.get_by_role("alert").filter(visible=True)).to_be_visible()
            expect(dialog.locator("input[name=title]")).to_have_value(TITLE)
            if scenario == "case-intake-repeated-loss":
                j.click("button", "حفظ", dialog)
                assert len(committed) == 2 and committed[0][0]["id"] == committed[1][0]["id"]
            elif scenario == "case-intake-reload":
                j.page.once("dialog", lambda message: message.accept())
                j.page.reload()
                j.settle()
                dialog = open_intake(j)
            elif scenario == "case-intake-language-recovery":
                j.page.once("dialog", lambda message: message.accept())
                j.click("button", "إغلاق", dialog)
                j.page.locator("[data-language-toggle]").click()
                j.page.wait_for_function("expected => document.documentElement.lang === expected", arg="en" if language == "ar" else "ar")
                j.settle()
                dialog = open_intake(j)
                result["final_language"] = j.page.locator("html").get_attribute("lang")
            elif scenario == "case-intake-changed-intent":
                dialog.locator("input[name=title]").fill("Distinct gateway investigation")
            elif scenario == "case-intake-permission-recovery":
                manager.login("manager@socify.local")
                role_permission(manager, "cases.create", False)
                with j.page.expect_response(lambda response: response.url.endswith("/api/cases") and response.request.method == "POST") as denied:
                    j.click("button", "حفظ", dialog)
                assert denied.value.status == 403
                assert len(cases(j)) == len(before) + 1
                role_permission(manager, "cases.create", True)
            elif scenario == "case-queue-colleague-claim":
                manager.login("manager@socify.local")
                claim = manager.page.locator("section.panel tr").filter(has=manager.page.get_by_role("cell", name=TITLE, exact=True))
                manager.click("button", "استلام الملكية", claim)
            with j.page.expect_response(lambda r: r.url.endswith("/api/cases") and r.request.method == "POST") as response:
                j.click("button", "حفظ", dialog)
            assert response.value.status == 201
        j.settle()
        expect(dialog).not_to_be_visible()
        after = cases(j)
        assert len(after) == len(before) + (2 if scenario == "case-intake-changed-intent" else 1), "A second case was created by a retry"
        created = next(row for row in after if row["id"] == committed[0][0]["id"])
        assert created["title"] == TITLE
        if scenario == "case-intake-changed-intent":
            # The first request still has no received response. Recover it independently.
            j.nav("إدارة القضايا")
            dialog = open_intake(j)
            j.click("button", "حفظ", dialog)
            assert j.page.url.endswith(f"/cases/{created['id']}")
            assert len(cases(j)) == len(before) + 2
        if scenario == "case-queue-colleague-claim":
            assert created["assignee"] == manager.page.evaluate("state.user.id")
        if scenario == "case-intake-same-title-new-case":
            j.nav("إدارة القضايا")
            dialog = open_intake(j)
            j.click("button", "حفظ", dialog)
            assert len(cases(j)) == len(before) + 2
        if scenario == "case-intake-approval-after-retry":
            assert created["approval"]["state"] == "pending"
            expect(j.page.get_by_text(j.text("لا يمكن بدء التحقيق قبل اعتماد المدير"), exact=True)).to_be_visible()
            expect(j.page.locator("input[name=file]")).to_have_count(0)
            manager.login("manager@socify.local")
            manager.page.goto(f"{manager.base}/cases/{created['id']}")
            manager.settle()
            approve(manager)
            j.page.reload()
            j.settle()
            assert next(row for row in cases(j) if row["id"] == created["id"])["approval"]["state"] == "approved"
        if scenario in {"case-intake-from-logs", "case-intake-approval-after-retry"}:
            j.case_id = created["id"]
            j.case_url = f"{j.base}/cases/{j.case_id}"
            if scenario == "case-intake-from-logs":
                assert "tab=logs" in j.page.url
            upload_logs(j, "gateway-intake.json", "Authorized gateway connection")
            j.click("link", "التحقيق والخط الزمني")
            note = note_dialog(j)
            j.click("button", "حفظ", note)
            assert len(records(j, "war_room")) == 1
            j.click("link", "الملخص والمسؤوليات")
            j.click("button", "إكمال المهمة", task_row(j, "Validate primary evidence"))
            assert next(task for task in j.state()["tasks"] if task["title"] == "Validate primary evidence")["status"] == "completed"
        if scenario != "case-intake-storage-disabled":
            assert not j.page.evaluate("Object.keys(sessionStorage).filter(key => key.startsWith('socify:case-create:'))"), (
                "A displayed creation was not acknowledged"
            )
        result["outcome"] = {
            "case-intake-changed-intent": "A changed request created a distinct case, then the original uncertain request recovered its own case without a third creation",
            "case-intake-same-title-new-case": "A deliberate new request after acknowledgement created a separate case with the same title",
            "case-intake-destination-recovery": "After a failed destination page, Back exposed the created case and its link opened that same case",
        }.get(scenario, "The first case was created once and the user reached the intended destination without losing entered details")
        evidence_images(j, result)
