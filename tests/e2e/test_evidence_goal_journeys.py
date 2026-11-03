"""Complete evidence and detection tasks without confusing a preview with a saved result."""

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.test_batch_boundary_journeys import upload_logs
from tests.e2e.test_case_continuity_journeys import panel, record_dialog, workflow
from tests.e2e.test_review_workflow import review_session


def collection_form(journey):
    journey.click("button", "توثيق الجمع المنفذ محليًا")
    dialog = journey.page.get_by_role("dialog")
    artifacts = dialog.locator("select[multiple]")
    artifacts.select_option(artifacts.locator("option").first.get_attribute("value"))
    dialog.locator("input[name=tool]").fill("Identity console export")
    dialog.locator("input[name=source]").fill("Authorized identity gateway")
    dialog.locator("input[name=collected_at]").fill("2026-11-02T09:00")
    return dialog


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["collection-evidence-recovery", "collection-gap-followup", "evidence-foreign-case-selection"])
def test_investigator_selects_actual_evidence_from_the_correct_case(app, language, scenario):
    with review_session(app, language, scenario) as (j, manager, result):
        manager.login("manager@socify.local")
        if scenario == "evidence-foreign-case-selection":
            manager.create_case()
            upload_logs(manager, "unrelated.json", "Other case only")
            upload_logs(j, "authorized.json", "This case only")
            j.click("link", "التحقيق والخط الزمني")
            dialog = record_dialog(j, "root_cause")
            dialog.locator("input[name=category]").fill(j.page.evaluate("autopsyLabel('other')"))
            dialog.locator("textarea[name=conclusion]").fill("Only the evidence retained in this case supports this conclusion.")
            dialog.locator("input[name=evidence_id]").fill("unrelated.json")
            expect(dialog.get_by_role("option")).to_have_count(0)
            j.click("button", "حفظ", dialog)
            expect(dialog).to_be_visible()
            assert not j.page.evaluate("id => api(`/api/cases/${id}/records?kind=root_cause`)", j.case_id)["items"]
            dialog.locator("input[name=evidence_id]").fill("")
            dialog.locator("input[name=evidence_id]").press("ArrowDown")
            dialog.get_by_role("option").filter(has_text="authorized.json").first.click()
            j.click("button", "حفظ", dialog)
            records = j.page.evaluate("id => api(`/api/cases/${id}/records?kind=root_cause`)", j.case_id)
            assert len(records["items"]) == 1 and records["items"][0]["payload"]["evidence_id"]
        else:
            j.click("link", "الاستجابة والتصعيد")
            form = j.page.locator("form").filter(has=j.page.locator("input[name=recipe_id]"))
            form.locator("input[name=recipe_id]").press("ArrowDown")
            form.get_by_role("option").first.click()
            form.locator("input[name=collector_id]").press("ArrowDown")
            form.get_by_role("option").filter(has_text=j.page.evaluate("state.user.name")).first.click()
            form.locator("textarea[name=reason]").fill("Retain identity records for the approved investigation window")
            j.click("button", "حفظ", form)
            manager.page.goto(j.case_url + "?tab=response")
            manager.settle()
            manager.click("button", "اعتماد نطاق الجمع")
            decision = manager.page.get_by_role("dialog")
            decision.locator("input[name=reason]").fill("Approved case scope and assigned collector")
            manager.click("button", "حفظ", decision)
            j.page.reload()
            j.settle()
            dialog = collection_form(j)
            j.click("button", "حفظ", dialog)
            expect(dialog).to_be_visible()
            assert workflow(j)["collections"][0]["payload"]["state"] == "approved"
            expect(dialog.locator("input[name=tool]")).to_have_value("Identity console export")
            j.page.once("dialog", lambda event: event.accept())
            j.click("button", "إغلاق", dialog)
            upload_logs(j, "collected.json", "Retained collection result")
            j.click("link", "الاستجابة والتصعيد")
            dialog = collection_form(j)
            dialog.locator("input[name=evidence_id]").press("ArrowDown")
            dialog.get_by_role("option").filter(has_text="collected.json").first.click()
            j.click("button", "حفظ", dialog)
            assert workflow(j)["collections"][0]["payload"]["state"] == "documented_with_gaps"
            expect(j.page.locator("main")).to_contain_text(j.text("وُثق الجمع جزئيًا"))
            expect(j.page.locator("main")).not_to_contain_text("documented_with_gaps")
            expect(j.page.get_by_role("columnheader", name=j.text("المصادر التي لم تُجمع"), exact=True)).to_be_visible()
            if scenario == "collection-gap-followup":
                j.click("button", "استكمال توثيق الجمع")
                dialog = j.page.get_by_role("dialog")
                expect(dialog.locator("input[name=tool]")).to_have_value("Identity console export")
                artifacts = dialog.locator("select[multiple]")
                artifacts.select_option([option.get_attribute("value") for option in artifacts.locator("option").all()])
                j.click("button", "حفظ", dialog)
                collection = workflow(j)["collections"][0]["payload"]
                assert collection["state"] == "documented" and collection["missing_artifacts"] == []
                expect(j.page.get_by_role("button", name=j.text("استكمال توثيق الجمع"), exact=True)).to_have_count(0)
        result["outcomes"] = [scenario, "unsupported evidence selection was not saved", "the intended task completed after retaining the correct evidence"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
@pytest.mark.parametrize("scenario", ["rule-negative-fixture-recovery", "rule-unsupported-source-recovery", "rule-preview-no-publication"])
def test_detection_author_can_verify_and_correct_before_publication(app, language, scenario):
    with review_session(app, language, scenario) as (_analyst, j, result):
        j.login("manager@socify.local")
        j.nav("مكتبة التحليل المحلي")
        area = panel(j, "اختبار قاعدة ونشرها")
        sigma = "title: Identity detection review\nlogsource:\n  category: socify_normalized\ndetection:\n  selected:\n    title|contains: Suspicious identity\n  condition: selected\nlevel: high\n"
        source = area.get_by_label(j.text("ملف Sigma"), exact=True)
        fixtures = area.locator("input[type=file]").nth(1)

        def attach(*, invalid_source=False, invalid_negative=False):
            source.set_input_files(
                {
                    "name": "identity.yml",
                    "mimeType": "text/yaml",
                    "buffer": (sigma.replace("title|contains:", "title|unsupported:") if invalid_source else sigma).encode(),
                }
            )
            content = {
                "positive": [{"title": "Suspicious identity review"}],
                "negative": [{"title": "Suspicious identity review" if invalid_negative else "Routine identity review"}],
            }
            fixtures.set_input_files({"name": "examples.json", "mimeType": "application/json", "buffer": json.dumps(content).encode()})

        attach(invalid_source=scenario == "rule-unsupported-source-recovery", invalid_negative=scenario == "rule-negative-fixture-recovery")
        area.locator("input[name=reason]").fill("Reviewed matching and non-matching identity records")
        before = j.page.evaluate("() => api('/api/autopsy/sigma/rules')")
        if scenario != "rule-preview-no-publication":
            j.click("button", "حفظ", area)
            expect(area.get_by_role("alert")).to_be_visible()
            expect(area.locator("input[name=reason]")).to_have_value("Reviewed matching and non-matching identity records")
            assert j.page.evaluate("() => api('/api/autopsy/sigma/rules')") == before
            attach()
        j.click("button", "تحقق من الترجمة والاختبارات دون نشر", area)
        expect(area).to_contain_text(j.text("اجتازت الأمثلة الإيجابية والسلبية. التحقق لا يثبت تغطية جميع التهديدات."))
        assert j.page.evaluate("() => api('/api/autopsy/sigma/rules')") == before
        j.click("button", "حفظ", area)
        expect(j.page.get_by_role("cell", name="Identity detection review", exact=True)).to_be_visible()
        after = j.page.evaluate("() => api('/api/autopsy/sigma/rules')")
        assert len(after["items"]) == len(before["items"]) + 1
        result["outcomes"] = [scenario, "preview left the rule library unchanged", "explicit publication saved exactly one reviewed rule"]


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_reprocessing_an_import_marks_its_previous_report_outdated(app, language):
    with review_session(app, language, "report-import-reprocessing") as (j, _manager, result):
        upload_logs(j, "identity.json", "Identity report evidence")
        j.click("link", "التقارير والمراجعة")
        j.click("button", "إعداد تقرير جديد")
        expect(j.page.locator(".report-revision")).to_have_count(1)
        report_id = j.state()["reports"][0]["id"]
        report_path = f"/api/cases/{j.case_id}/reports/{report_id}"
        before = j.page.evaluate("path => api(path)", report_path)
        j.click("link", "السجلات والأدلة")
        j.page.locator("summary").filter(has_text=j.text("خيارات الاستيراد")).click()
        j.page.locator("input[name=source_timezone]").fill("Asia/Riyadh")
        j.page.locator("input[name=file]").set_input_files(
            {
                "name": "identity.json",
                "mimeType": "application/json",
                "buffer": json.dumps([{"title": "Identity report evidence", "timestamp": "2026-11-02T09:00:00Z", "hostname": "REVIEW-SRV"}]).encode(),
            }
        )
        j.click("button", "استيراد وفحص فوري")
        imports = j.page.evaluate("id => api(`/api/cases/${id}/imports`)", j.case_id)
        assert len(imports["items"]) == 2
        assert sum(bool(row["active_version"]) for row in imports["items"]) == 1
        j.click("link", "التقارير والمراجعة")
        expect(j.page.locator(".report-revision")).to_contain_text(j.text("تغيرت القضية بعد إعداد هذا التقرير"))
        expect(j.page.get_by_role("button", name=j.text("مراجعة واعتماد النسخة"), exact=True)).to_have_count(0)
        after = j.page.evaluate("path => api(path)", report_path)
        assert after["payload"] == before["payload"] and after["source_version"] == before["source_version"]
        result["outcomes"] = [
            "reprocessed evidence replaced the active derivation",
            "previous report snapshot remained unchanged",
            "outdated report visibly identified",
        ]
