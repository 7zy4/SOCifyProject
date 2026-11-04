"""Import actions remain readable and usable inside a scrollable originals table."""

import hashlib
import json
import os
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.test_browser import assert_accessible
from tests.e2e.test_review_workflow import review_session

ARTIFACTS = Path("artifacts/interface-final-review/import-actions")
WORD_LINES = """root => {
    const broken=[];
    for (const button of root.querySelectorAll('.button')) {
        const walker=document.createTreeWalker(button,NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
            const node=walker.currentNode;
            for (const match of node.textContent.matchAll(/\\S+/gu)) {
                const range=document.createRange();
                range.setStart(node,match.index);range.setEnd(node,match.index+match[0].length);
                const lines=new Set([...range.getClientRects()].map(rect=>Math.round(rect.top)));
                if(lines.size>1)broken.push({label:button.textContent,word:match[0],lines:lines.size});
            }
        }
    }
    return broken;
}"""


@pytest.mark.e2e
@pytest.mark.parametrize("language", ["ar", "en"])
def test_import_actions_wrap_between_words_and_download_the_retained_original(app, language):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    phase = os.environ.get("SOCIFY_IMPORT_ACTION_CAPTURE", "after")
    with review_session(app, language, f"import-actions-{phase}") as (j, _manager, result):
        originals = []
        for number in (1, 2):
            raw = json.dumps([{"title": f"Retained gateway event {number}", "timestamp": "2026-11-02T09:00:00Z", "hostname": "GATEWAY-REVIEW"}]).encode()
            originals.append(raw)
            j.click("link", "السجلات والأدلة")
            j.page.locator("input[name=file]").set_input_files({"name": f"gateway-{number}.json", "mimeType": "application/json", "buffer": raw})
            j.click("button", "استيراد وفحص فوري")
        table = j.page.locator(".import-jobs")
        expect(table.locator("tbody tr")).to_have_count(2)
        for width in (1440, 390):
            j.page.set_viewport_size({"width": width, "height": 1000})
            download_link = table.get_by_role("link", name=j.text("تنزيل الأصل"), exact=True).first
            download_link.focus()
            expect(download_link).to_be_focused()
            with j.page.expect_download() as pending:
                download_link.press("Enter")
            download = pending.value
            assert download.suggested_filename == "gateway-2.json"
            assert Path(download.path()).read_bytes() == originals[-1]
            status = table.get_by_role("button", name=j.text("حالة الاستيراد"), exact=True).first
            status.focus()
            status.press("Enter")
            j.settle()
            expect(j.page.get_by_role("dialog")).to_contain_text(hashlib.sha256(originals[-1]).hexdigest())
            j.page.keyboard.press("Escape")
            expect(j.page.get_by_role("dialog")).not_to_be_visible()
            j.settle()
            expect(status).to_be_focused()
            j.page.keyboard.press("Shift+Tab")
            expect(download_link).to_be_focused()
            j.page.get_by_role("heading", name=j.text("أصول الاستيراد والمعالجة"), exact=True).scroll_into_view_if_needed()
            broken = table.evaluate(WORD_LINES)
            bounds = download_link.evaluate("""el=>{
                const box=el.closest('.table-wrap'),a=el.getBoundingClientRect(),b=box.getBoundingClientRect();
                const range=document.createRange();range.selectNodeContents(el);const text=range.getBoundingClientRect();
                return {left:a.left,right:a.right,containerLeft:b.left,containerRight:b.right,active:el===document.activeElement,textLeft:text.left,textRight:text.right,scrollLeft:box.scrollLeft,scrollWidth:box.scrollWidth,clientWidth:box.clientWidth};
            }""")
            (ARTIFACTS / f"bounds-{language}-{width}.json").write_text(json.dumps(bounds, indent=2), encoding="utf-8")
            assert bounds["textLeft"] >= bounds["containerLeft"] and bounds["textRight"] <= bounds["containerRight"], json.dumps(bounds)
            assert j.page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            if width == 390:
                assert table.evaluate("el=>el.scrollWidth > el.clientWidth")
            shot = ARTIFACTS / f"{phase}-{language}-{width}.png"
            table.locator("..").screenshot(path=str(shot), animations="disabled")
            result.setdefault("layouts", []).append({"width": width, "broken_words": broken, "bounds": bounds, "screenshot": str(shot)})
            assert not broken, broken
        assert_accessible(j.page)
        result["outcomes"] = [
            "Imported two originals through the UI",
            "Downloaded exact retained bytes using Enter at both widths",
            "Opened import status using the keyboard and checked its hash",
            "Whole words in every import-table button",
            "Intentional table scrolling without page overflow",
        ]
        result["scope"] = "One simulated workflow per language; viewport checks are not additional users."
    (ARTIFACTS / f"{phase}-{language}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
