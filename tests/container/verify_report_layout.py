import argparse
import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree as ET

from scripts.benchmark_reference import git_revision
from socify.autopsy_worker import compute_report


def long_report_fixture():
    digest = hashlib.sha256(b"Synthetic bilingual report layout evidence").hexdigest()
    description = "دليل اصطناعي محفوظ داخل الشركة؛ يربط المحقق الملاحظة بمصدرها دون افتراض نجاح الهجوم. Evidence retained locally with an explicit source, outcome and uncertainty. "
    records = {
        "timeline": [
            {
                "id": index,
                "version": 1,
                "payload": {
                    "title": f"ملاحظة تحقيق رقم {index} / Investigation observation {index}",
                    "event_time": f"2026-10-20T10:{index:02d}:00Z",
                    "source": "Local synthetic logs / مصدر محلي اصطناعي",
                    "notes": description * 3,
                    "evidence_id": index,
                },
            }
            for index in range(1, 13)
        ],
        "root_cause": [
            {
                "payload": {
                    "title": "تحليل السبب الجذري / Root cause analysis",
                    "conclusion": description * 4,
                    "five_whys": [{"question": f"لماذا؟ / Why {index}?", "answer": description} for index in range(1, 6)],
                    "limitations_text": "بيانات اصطناعية؛ ليست نتيجة حادثة حقيقية. Synthetic fixture only.",
                }
            }
        ],
    }
    return {
        "case": {
            "title": ("تحقيق داخلي / Internal investigation — " * 7)[:255],
            "reference": "SOC-LAYOUT-SYNTHETIC-2026",
            "status": "investigating",
            "classification": "internal",
        },
        "revision": 1,
        "summary": {"title": "تقرير اصطناعي طويل / Synthetic bilingual report", "objective": description * 3},
        "context": {"objective": description, "attack_outcome": "undetermined", "alert_verdict": "unknown"},
        "records": records,
        "chronology": {
            "scope": "مراجع الأدلة المختارة وملاحظات التحقيق والإجراءات المشتركة فقط.",
            "entries": [
                {
                    "id": index,
                    "entry_type": "record",
                    "title": f"ترتيب زمني مشترك {index} / Shared chronology {index}",
                    "event_time": f"2026-10-20T10:{index:02d}:00Z",
                    "time_basis": "investigator_observation_time",
                    "evidence_id": index,
                }
                for index in range(1, 13)
            ],
        },
        "evidence": [{"id": index, "title": f"دليل {index} / Evidence {index}", "sha256": digest, "details": description} for index in range(1, 13)],
        "imports": [{"original_filename": "مصدر-محلي-local-evidence.jsonl", "sha256": digest, "accepted": 12, "rejected": 0}],
        "limitations": [
            "All content is synthetic. No data is transmitted outside the local analysis boundary.",
            "اختبار التفاف رابط طويل: https://evidence.example.test/" + "a" * 4096,
            "اختبار سلسلة غير مفصولة / Unbroken value: " + "B" * 2048,
            "SYNTHETIC_REPORT_END_MARKER",
        ],
    }


def check_geometry(xml_path):
    root = ET.parse(xml_path).getroot()
    pages = root.findall(".//{*}page")
    if len(pages) < 20:
        raise AssertionError("The long bilingual fixture must exercise at least twenty printed pages")
    violations, empty_pages, words = [], [], 0
    exact_clock_found = False
    for number, page in enumerate(pages, 1):
        width, height = float(page.attrib["width"]), float(page.attrib["height"])
        page_words = page.findall(".//{*}word")
        if number == 1 and not any("SOC-LAYOUT-SYNTHETIC-2026" in (word.text or "") for word in page_words):
            raise AssertionError("The case reference and long case title must fit together on the first cover page")
        if number == 1 and not any("SHA-256:" in (word.text or "") for word in page_words):
            raise AssertionError("The integrity notice and digest must fit on the cover without creating a mostly empty extra page")
        if not page_words:
            empty_pages.append(number)
        for word in page_words:
            exact_clock_found = exact_clock_found or "2026-10-20T10:01:00Z" in (word.text or "")
            words += 1
            x0, y0, x1, y1 = (float(word.attrib[key]) for key in ("xMin", "yMin", "xMax", "yMax"))
            if not (42 <= x0 <= x1 <= width - 42 and 35 <= y0 <= y1 <= height - 10):
                violations.append({"page": number, "box": [x0, y0, x1, y1], "text": word.text})
    if violations or empty_pages:
        raise AssertionError(json.dumps({"clipped_words": violations[:20], "empty_pages": empty_pages}, ensure_ascii=False))
    if not exact_clock_found:
        raise AssertionError("Mixed Arabic/English lines must preserve the exact left-to-right source timestamp")
    return {
        "pages": len(pages),
        "words_checked": words,
        "clipped_words": 0,
        "empty_pages": [],
        "scope": "Poppler word bounds on every page; visual review remains a separate recorded check.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bbox", type=Path)
    parser.add_argument("--unbroken-title", action="store_true")
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    manifest_path = options.output / "manifest.json"
    if options.bbox:
        manifest = json.loads(manifest_path.read_text())
        manifest["geometry"] = check_geometry(options.bbox)
    else:
        payload = long_report_fixture()
        if options.unbroken_title:
            payload["case"]["title"] = "W" * 255
        files = compute_report(payload)
        for kind, content in files.items():
            (options.output / ("long-report." + kind)).write_bytes(content)
        manifest = {
            "schema": "socify-bilingual-report-layout/1",
            "synthetic_only": True,
            "revision": git_revision(),
            "fixture": "255-character unbroken wide title" if options.unbroken_title else "255-character mixed Arabic/English title",
            "renderer_sources": {
                name: hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()
                for name in ("socify/autopsy_report_render.py", "socify/report_brand.py", "static/report.css")
            },
            "renderer": "Actual network-isolated analysis service, five output formats",
            "files": {kind: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()} for kind, content in files.items()},
            "visual_review": "PENDING",
        }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
