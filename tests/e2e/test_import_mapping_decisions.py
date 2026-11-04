"""Correct one mapping without hiding the other transformations applied to evidence."""

import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from flask import request as flask_request
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/import-mapping-decisions")
RAW = b"time_col,client_addr,server_addr,description\n2026-11-02T12:00:00,192.0.2.45,198.51.100.12,Gateway blocked request\n"
RETAINED = {"time_col": "event_time", "description": "title"}
CORRECTED = {**RETAINED, "client_addr": "source_ip", "server_addr": "destination_ip"}


def production_hash():
    return hashlib.sha256(Path("static/autopsy_data.js").read_bytes()).hexdigest()


def mapping_rows(group):
    return group.locator("bdi").all_text_contents()


def keyboard_mapping(j, group, source, target):
    for name, value in (("mapping_from", source), ("mapping_to", target)):
        control = group.locator(f"input[name={name}]")
        label = j.page.evaluate("value => autopsyLabel(value)", value)
        control.fill(label[:-1])
        control.press("ArrowDown")
        expect(group.get_by_role("option", name=label, exact=True)).to_be_focused()
        j.page.keyboard.press("Enter")
        expect(control).to_have_value(label)
    action = group.get_by_role("button", name=j.text("إضافة ربط حقل"), exact=True)
    action.focus()
    action.press("Enter")
    j.settle()


def preview(j, form, result, stage):
    path = f"/api/cases/{j.case_id}/imports/preview"
    with j.page.expect_response(lambda response: urlsplit(response.url).path == path and response.request.method == "POST") as pending:
        action = form.get_by_role("button", name=j.text("معاينة السجلات والبصمة"), exact=True)
        action.focus()
        action.press("Enter")
    response = pending.value
    assert response.status == 200, response.text()
    value = response.json()
    received = next(item for item in reversed(result["server_received"]) if item["path"] == path)
    result.setdefault("wire_previews", []).append({"stage": stage, "submitted_mapping": received["mapping"], "response": value})
    j.settle()
    return value, result["wire_previews"][-1]["submitted_mapping"]


def capture(j, form, folder, result, stage):
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        form.scroll_into_view_if_needed()
        fits = j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        path = folder / f"{stage}-{width}.png"
        bounds = form.evaluate("""form => {
            const box = el => { const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:r.width,scrollWidth:el.scrollWidth,clientWidth:el.clientWidth}; };
            return {viewport:innerWidth,form:box(form),group:box(form.querySelector('fieldset')),
                actions:[...form.querySelectorAll('.action-row button')].map(el=>({label:el.textContent,...box(el)})),
                controls:[...form.querySelectorAll('input,select,button')].filter(el=>el.getClientRects().length).map(el=>({name:el.name,label:el.getAttribute('aria-label')||el.textContent,...box(el)}))};
        }""")
        form.screenshot(path=str(path), animations="disabled")
        full = folder / f"{stage}-{width}-full.png"
        j.page.screenshot(path=str(full), full_page=True, animations="disabled")
        result.setdefault("layouts", []).append(
            {"stage": stage, "width": width, "page_fits": fits, "bounds": bounds, "screenshot": str(path), "full_screenshot": str(full)}
        )
        assert fits, "PRODUCT: import mapping form causes page overflow"
        for item in [bounds["group"], *bounds["controls"]]:
            assert item["left"] >= bounds["form"]["left"] - 1 and item["right"] <= bounds["form"]["right"] + 1, (
                f"PRODUCT: import control is clipped outside its form at {width}px: {item!r}; form={bounds['form']!r}"
            )
        form.locator("input[name=source_label]").focus()
        j.page.evaluate("window.scrollTo({top:0,behavior:'instant'})")
        source = form.locator("input[name=mapping_from]")
        source.focus()
        expect(source).to_be_focused()
        expect(source).to_be_in_viewport(ratio=1)
        focus_bounds = source.evaluate(
            "el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,height:innerHeight,width:innerWidth,scrollX,scrollY};}"
        )
        result.setdefault("keyboard_autoscroll", []).append({"stage": stage, "width": width, **focus_bounds})
        assert 0 <= focus_bounds["left"] < focus_bounds["right"] <= width
        assert 0 <= focus_bounds["top"] < focus_bounds["bottom"] <= focus_bounds["height"]
        j.page.keyboard.press("Tab")
        expect(source.locator("..").locator(".choice-toggle")).to_be_focused()
        j.page.keyboard.press("Shift+Tab")
        expect(source).to_be_focused()
    j.page.set_viewport_size({"width": 1440, "height": 1000})


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_remove_wrong_mapping_preserves_other_fields_and_requires_fresh_preview(app, monkeypatch, language):
    phase = os.environ.get("SOCIFY_MAPPING_PHASE", "verification")
    folder = ARTIFACTS / "attempts" / f"{phase}-{language}-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    scenario = "AFTER-43-import-mapping-removal-truth"
    received = []

    @app.before_request
    def observe_multipart_mapping():
        # Passive server receipt: no response interception or modification of the payload.
        if flask_request.method == "POST" and flask_request.path.endswith(("/imports", "/imports/preview")):
            received.append({"path": flask_request.path, "mapping": json.loads(flask_request.form.get("mapping", "{}"))})

    with review_session(app, language, scenario) as (j, _manager, result):
        result.update(
            plan_id="AFTER-43",
            phase=phase,
            human_participants=0,
            semantic_conditions=1,
            clean_round_claim=False,
            initial_interpretation=None,
            interpretation_kind="Scripted interface task and independent evidence checks; not a human comprehension study",
            setup_provenance="Isolated seeded analyst creates a case through the UI; import, mapping, corrections and original download use visible controls. API checks are read-only.",
            checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
            production_hash_before=production_hash(),
            stylesheet_hash_before=hashlib.sha256(Path("static/comic-workspace.css").read_bytes()).hexdigest(),
            test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            evidence_folder=str(folder),
            native_output_claim=False,
            server_received=received,
        )
        try:
            if j.page.locator("html").get_attribute("lang") != language:
                j.page.locator("[data-language-toggle]").click()
                j.settle()
            expect(j.page.locator("html")).to_have_attribute("lang", language)
            j.click("link", "السجلات والأدلة")
            form = j.page.get_by_role("form", name=j.text("استيراد أدلة القضية"), exact=True)
            form.locator("input[name=file]").set_input_files({"name": "firewall-fields.csv", "mimeType": "text/csv", "buffer": RAW})
            form.locator(".import-options > summary").click()
            form.locator("input[name=source_label]").fill("Authorized firewall export")
            form.locator("input[name=source_timezone]").fill("Asia/Riyadh")
            form.locator("input[name=source_timezone]").press("Tab")
            preview(j, form, result, "initial-columns")
            group = form.get_by_role("group", name=j.text("ربط حقول المصدر بالحقول الموحّدة"), exact=True)
            commit = form.get_by_role("button", name=j.text("اعتماد الاستيراد"), exact=True)
            for source, target in {**RETAINED, "client_addr": "destination_ip"}.items():
                keyboard_mapping(j, group, source, target)
            wrong, submitted = preview(j, form, result, "incorrect-address-mapping")
            assert submitted == {**RETAINED, "client_addr": "destination_ip"}
            assert wrong["preview"][0]["destination_ip"] == "192.0.2.45"
            expect(commit).to_be_enabled()
            result["rows_before_removal"] = mapping_rows(group)
            capture(j, form, folder, result, "before-removal")
            wrong_row = group.locator("p").filter(has_text="client_addr → destination_ip")
            remove = wrong_row.get_by_role("button", name=j.text("إزالة الربط"), exact=True)
            remove.focus()
            expect(remove).to_be_focused()
            remove.press("Enter")
            j.settle()
            result["rows_after_removal"] = mapping_rows(group)
            result["stale_confirmation_disabled"] = commit.is_disabled()
            result["focus_after_removal"] = j.page.locator(":focus").get_attribute("name")
            expect(group.locator("input[name=mapping_from]")).to_be_focused()
            capture(j, form, folder, result, "after-removal")
            expect(commit).to_be_disabled()

            submissions = []
            import_path = f"/api/cases/{j.case_id}/imports"

            def observe_submit(request):
                if request.method == "POST" and urlsplit(request.url).path == import_path:
                    submissions.append(urlsplit(request.url).path)

            j.page.on("request", observe_submit)
            form.locator("input[name=source_label]").press("Enter")
            j.settle()
            result["stale_keyboard_submission_count"] = len(submissions)
            assert submissions == [], "PRODUCT: stale import was submitted by Enter before a fresh preview"
            assert j.page.evaluate("id => api(`/api/cases/${id}/imports`)", j.case_id)["items"] == []
            _, effective = preview(j, form, result, "after-removal-effective-options")
            assert effective == RETAINED, "PRODUCT: removing one mapping changed other effective transformations"
            expected_rows = [f"{source} → {target}" for source, target in RETAINED.items()]
            assert result["rows_after_removal"] == expected_rows, (
                "PRODUCT: removing one mapping hid retained mappings while the next real preview still submitted them; "
                f"visible={result['rows_after_removal']!r}, effective={effective!r}"
            )

            keyboard_mapping(j, group, "client_addr", "source_ip")
            keyboard_mapping(j, group, "server_addr", "destination_ip")
            expect(commit).to_be_disabled()
            corrected, effective = preview(j, form, result, "corrected-final-preview")
            assert effective == CORRECTED
            assert corrected["content_hash"] == hashlib.sha256(RAW).hexdigest()
            actual = corrected["preview"][0]
            for name, expected in {
                "title": "Gateway blocked request",
                "event_time": "2026-11-02T09:00:00Z",
                "source_ip": "192.0.2.45",
                "destination_ip": "198.51.100.12",
            }.items():
                assert actual[name] == expected, (name, actual)
            expect(commit).to_be_enabled()
            capture(j, form, folder, result, "corrected-preview")
            preview_text = form.locator("pre")
            preview_text.focus()
            expect(preview_text).to_be_focused()
            preview_text.press("PageDown")
            j.page.wait_for_function("el=>el.scrollTop>0", arg=preview_text.element_handle())
            result["preview_keyboard_scroll"] = preview_text.evaluate(
                "el=>({scrollTop:el.scrollTop,scrollHeight:el.scrollHeight,clientHeight:el.clientHeight})"
            )
            assert_accessible(j.page)
            with j.page.expect_response(lambda response: urlsplit(response.url).path == import_path and response.request.method == "POST") as imported:
                commit.focus()
                commit.press("Enter")
            response = imported.value
            assert response.status == 201, response.text()
            result["import_response"] = response.json()
            result["submitted_import_mappings"] = [item["mapping"] for item in received if item["path"] == import_path]
            assert submissions == [import_path]
            assert result["submitted_import_mappings"] == [CORRECTED]
            j.settle()
            row = j.page.get_by_role("row").filter(has=j.page.get_by_role("cell", name="Gateway blocked request", exact=True))
            expect(row).to_be_visible()
            j.click("button", "تفاصيل السجل", row)
            dialog = j.page.get_by_role("dialog")
            retained = json.loads(dialog.locator("pre").inner_text())
            result["visible_record_detail"] = retained
            expect(dialog).to_contain_text("192.0.2.45")
            expect(dialog).to_contain_text("198.51.100.12")
            j.page.keyboard.press("Escape")
            j.settle()
            logs = j.page.evaluate("id => api(`/api/cases/${id}/logs`)", j.case_id)["items"]
            assert len(logs) == 1
            for name in ("title", "event_time", "source_ip", "destination_ip"):
                assert logs[0][name] == actual[name], (name, logs[0])
            result["stored_record"] = logs[0]
            originals = j.page.locator(".import-jobs")
            original = originals.get_by_role("link", name=j.text("تنزيل الأصل"), exact=True)
            for width in (1440, 390):
                j.page.set_viewport_size({"width": width, "height": 1000})
                original.focus()
                expect(original).to_be_focused()
                with j.page.expect_download() as pending:
                    original.press("Enter")
                downloaded = Path(pending.value.path()).read_bytes()
                assert downloaded == RAW, "PRODUCT: original evidence bytes changed after mapping correction"
                assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "PRODUCT: imported record page overflow"
                image = folder / f"retained-original-{width}.png"
                originals.locator("..").screenshot(path=str(image), animations="disabled")
                result.setdefault("original_downloads", []).append(
                    {"width": width, "sha256": hashlib.sha256(downloaded).hexdigest(), "filename": pending.value.suggested_filename, "screenshot": str(image)}
                )
            assert_accessible(j.page)
            result["outcomes"] = [
                "Removed one wrong mapping with the keyboard while both valid mappings remained visible and effective",
                "Stale preview confirmation and keyboard implicit submit could not commit altered options",
                "Corrected addresses, previewed again and committed exactly one import using visible controls",
                "Actual retained record has the mapped timestamp/title/addresses; original bytes downloaded unchanged at both widths",
            ]
            result["outcome_classification"] = "completed simulated user task"
        except Exception as error:
            result["outcome_classification"] = "product failure" if "PRODUCT:" in str(error) else "unclassified test or product failure pending review"
            raise
        finally:
            result["production_hash_after"] = production_hash()
            result["stylesheet_hash_after"] = hashlib.sha256(Path("static/comic-workspace.css").read_bytes()).hexdigest()
