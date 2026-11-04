"""Read overlapping location claims before saving a qualified evidence decision."""

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect

import tests.e2e.test_review_workflow as review_module
from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_case_continuity_journeys import panel, record_dialog
from tests.e2e.test_followup_handoff_journeys import manager_case
from tests.e2e.test_investigation_link_journeys import choose, records
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/usability_campaign/geoip-context-decisions")
SUBJECT = "192.0.2.45"
CONTROL = "198.51.100.72"
SOURCES = (
    ("Broad location estimate", "192.0.2.0/24", "SA", 64500),
    ("Narrow location estimate", "192.0.2.32/27", "DE", 64501),
)


def import_source(j, name, prefix, country, asn):
    j.nav("مكتبة التحليل المحلي")
    form = panel(j, "استيراد إصدار محلي جديد").locator("form")
    for key, value in {
        "name": name,
        "version": "1",
        "source": name + " provenance",
        "license": "Internal review data",
        "expires_at": "2030-01-01T00:00",
        "format": "geoip",
    }.items():
        form.locator(f"input[name={key}]").fill(value)
    raw = json.dumps([{"type": "cidr", "value": prefix, "country": country, "asn": asn, "verdict": "unknown", "confidence": 0}]).encode()
    form.locator("input[type=file]").set_input_files({"name": name + ".json", "mimeType": "application/json", "buffer": raw})
    j.click("button", "حفظ", form)
    row = panel(j, "إصدارات مصادر TI وGeoIP").locator("tr").filter(has=j.page.get_by_role("cell", name=name, exact=True))
    j.click("button", "تفعيل الإصدار", row)
    bundle = json.dumps({"format": "geoip", "content": json.loads(raw)}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(bundle).hexdigest()


def observable(j, value):
    return next(row for row in j.page.evaluate("id=>api(`/api/cases/${id}/observables`)", j.case_id)["items"] if row["value"] == value)


def details(j, value):
    row = panel(j, "الإثراء المحلي").locator("tr").filter(has=j.page.get_by_role("cell", name=value, exact=True))
    j.click("button", "تفاصيل الإثراء", row)
    return j.page.get_by_role("dialog")


def capture(j, dialog, folder, result, stage):
    result.setdefault("visible_observations", []).append({"stage": stage, "text": dialog.inner_text()})
    for width in (1440, 390):
        j.page.set_viewport_size({"width": width, "height": 1000})
        assert_accessible(j.page)
        boxes = dialog.locator("table").evaluate_all("""nodes=>nodes.map(el=>{
            const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:r.width,client:el.clientWidth,scroll:el.scrollWidth};
        })""")
        result.setdefault("layouts", []).append({"stage": stage, "width": width, "tables": boxes})
        path = folder / f"{stage}-{width}.png"
        dialog.evaluate("el=>el.scrollTo({top:0,behavior:'instant'})")
        dialog.screenshot(path=str(path), animations="disabled")
        result.setdefault("screenshots", []).append(str(path))
        assert dialog.evaluate("el=>el.scrollWidth<=el.clientWidth"), "PRODUCT: enrichment dialog clips its content"
        assert all(box["left"] >= 0 and box["right"] <= width + 1 and box["scroll"] <= box["client"] + 1 for box in boxes), (
            "PRODUCT: source tables do not fit the viewport"
        )
    j.page.set_viewport_size({"width": 1440, "height": 1000})


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_overlapping_geoip_claims_remain_context_not_a_security_verdict(app, monkeypatch, language):
    folder = ARTIFACTS / "attempts" / f"{language}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    folder.mkdir(parents=True)
    monkeypatch.setattr(review_module, "ARTIFACTS", folder)
    with review_session(app, language, "AFTER-44") as (j, manager, result):
        result.update(
            plan_id="AFTER-44",
            human_participants=0,
            interpretation_kind="Scripted decision hypothesis, not a human comprehension study",
            hypothesis="Conflicting location claims and an unmatched control can be inspected without a malicious/benign verdict; qualified note retains source provenance.",
            novelty="Overlapping geographic prefixes with unknown threat verdicts; earlier tests cover single-prefix service matching or conflicting threat verdicts.",
            native_export_claim=False,
            checked_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),  # noqa: S603,S607
            production_sha256=hashlib.sha256(Path("static/autopsy_operations.js").read_bytes()).hexdigest(),
            fixture_setup="Seeded isolated accounts only; case, source activation, evidence upload and note use UI; API reads verify persistence.",
        )
        external = []
        for actor in (j, manager):
            actor.page.on(
                "request", lambda request: external.append(request.url) if urlsplit(request.url).hostname not in {"localhost", "127.0.0.1", None} else None
            )
        manager_case(j, manager)
        source_hashes = {source[0]: import_source(manager, *source) for source in SOURCES}
        raw = json.dumps(
            [
                {"title": "Retained gateway connection", "source_ip": SUBJECT, "hostname": "gateway.example.test", "timestamp": "2026-11-02T09:00:00Z"},
                {"title": "Unmatched gateway connection", "source_ip": CONTROL, "hostname": "gateway.example.test", "timestamp": "2026-11-02T09:01:00Z"},
            ]
        ).encode()
        (folder / "gateway-context.json").write_bytes(raw)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        result["source_sha256"] = source_hashes
        j.page.goto(j.case_url + "?tab=logs")
        j.settle()
        j.page.locator("input[name=file]").set_input_files({"name": "gateway-context.json", "mimeType": "application/json", "buffer": raw})
        j.click("button", "استيراد وفحص فوري")
        expect(j.page.get_by_role("cell", name="Retained gateway connection", exact=True)).to_be_visible()
        j.nav("استخبارات التهديدات")
        dialog = details(j, SUBJECT)
        j.click("button", "إثراء محلي بالإصدارات الحالية", dialog)
        dialog = details(j, SUBJECT)
        value = observable(j, SUBJECT)["enrichment"]
        result["matched"] = value
        assert value["status"] == "matched" and value["verdict"] == "unknown"
        assert len(value["matches"]) == 2
        assert {match["country"] for match in value["matches"]} == {"SA", "DE"}
        for name, prefix, country, asn in SOURCES:
            table = dialog.get_by_role("table").filter(has=j.page.locator("caption", has_text=name))
            for text in (name + " provenance", prefix, country, str(asn), j.text("غير معروف")):
                expect(table).to_contain_text(text)
            digest = table.locator("xpath=following-sibling::details[1]")
            digest.locator("summary").click()
            expect(digest).to_contain_text(source_hashes[name])
        capture(j, dialog, folder, result, "overlapping-sources")
        j.page.keyboard.press("Escape")
        dialog = details(j, CONTROL)
        unmatched = observable(j, CONTROL)["enrichment"]
        assert unmatched["status"] == "no_match" and unmatched["verdict"] == "unknown" and not unmatched["matches"]
        expect(dialog).to_contain_text(j.text("لا يوجد تطابق"))
        expect(dialog).to_contain_text(j.text("غير معروف"))
        result["unmatched"] = unmatched
        capture(j, dialog, folder, result, "unmatched-control")
        j.page.keyboard.press("Escape")
        j.page.goto(j.case_url + "?tab=investigation")
        j.settle()
        dialog = record_dialog(j, "war_room")
        note = (
            f"The retained gateway-context.json contains {SUBJECT} and {CONTROL}. "
            "Broad location estimate provenance assigns 192.0.2.0/24 to SA / ASN 64500; "
            "Narrow location estimate provenance assigns 192.0.2.32/27 to DE / ASN 64501. "
            "Both sources report an unknown threat verdict. These conflicting geography claims do not establish malicious activity or a verified location. "
            "The unmatched control is unknown, not safe. Request gateway/session context before escalating. No external reputation lookup was performed."
        )
        dialog.locator("input[name=title]").fill("Qualified location assessment")
        dialog.locator("textarea[name=body]").fill(note)
        evidence = j.state()["evidence"]
        assert evidence, "Uploaded source evidence must be retained"
        linked = next(item for item in evidence if "gateway-context" in item["title"])
        choose(j, dialog, "evidence_id", linked["title"])
        j.click("button", "حفظ", dialog)
        saved = next(item for item in records(j, "war_room") if item["payload"]["title"] == "Qualified location assessment")
        assert saved["payload"]["body"] == note and saved["payload"]["evidence_id"] == linked["id"]
        result["saved_note"] = saved
        result["external_browser_requests"] = external
        assert not external
        assert j.state()["status"] != "closed"
        j.page.reload()
        j.settle()
        card = j.page.locator(".record-card").filter(has=j.page.get_by_role("heading", name="Qualified location assessment", exact=True))
        expect(card.get_by_text(note, exact=True)).to_be_visible()
        for width in (1440, 390):
            j.page.set_viewport_size({"width": width, "height": 1000})
            assert_accessible(j.page)
            assert j.page.evaluate("document.documentElement.scrollWidth<=innerWidth")
            j.page.screenshot(path=str(folder / f"saved-decision-{width}.png"), full_page=True, animations="disabled")
