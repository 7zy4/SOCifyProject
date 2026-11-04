import copy
import io
import zipfile
from pathlib import Path
from uuid import UUID

from defusedxml import ElementTree as ET
from docx import Document

from socify.autopsy_report_render import render_docx

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main", "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}


def test_recipient_can_read_bilingual_report_with_fonts_embedded_and_evidence_unchanged():
    payload = {
        "case": {"title": "تحقيق / Investigation", "reference": "CASE-READABLE"},
        "revision": 4,
        "records": {"timeline": [{"id": 7, "version": 2, "payload": {"title": "Reviewed login", "event_time": "2026-11-02T09:00:00Z"}}]},
    }
    original = copy.deepcopy(payload)
    content = render_docx(payload)
    document = Document(io.BytesIO(content))
    text = "".join(document.element.xpath(".//w:t/text()"))
    assert "تحقيق / Investigation" in text and "2026-11-02T09:00:00Z" in text
    assert "Reviewed login" in text
    assert any([cell.text for cell in row.cells] == ["المعرف", "7"] for table in document.tables for row in table.rows)
    assert any([cell.text for cell in row.cells] == ["وقت الحدث", "2026-11-02T09:00:00Z"] for table in document.tables for row in table.rows)
    assert "الإصدار:" not in text and payload == original
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        table = ET.fromstring(archive.read("word/fontTable.xml"))
        relations = ET.fromstring(archive.read("word/_rels/fontTable.xml.rels"))
        destinations = {r.attrib["Id"]: r.attrib["Target"] for r in relations}
        embedded = [item for font in table for item in font if item.tag.endswith(("embedRegular", "embedBold"))]
        assert len(embedded) == 5
        for entry in embedded:
            target = destinations[entry.attrib[f"{{{NS['r']}}}id"]]
            obfuscated = bytearray(archive.read("word/" + target))
            mask = UUID(entry.attrib[f"{{{NS['w']}}}fontKey"]).bytes[::-1]
            for index in range(32):
                obfuscated[index] ^= mask[index % 16]
            filename = Path(target).stem + ".ttf"
            assert bytes(obfuscated) == (Path(__file__).resolve().parents[2] / "static/fonts/report" / filename).read_bytes()
        styles = ET.fromstring(archive.read("word/styles.xml"))
        for name in ("Normal", "Title", "Heading1", "Heading2"):
            style = styles.find(f"w:style[@w:styleId='{name}']", NS)
            assert style.find("w:pPr/w:pBdr", NS) is None
            fonts = style.find("w:rPr/w:rFonts", NS)
            assert not any(key.lower().endswith("theme") for key in fonts.attrib)
            assert fonts.attrib[f"{{{NS['w']}}}cs"] == "Cairo"
            assert style.find("w:rPr/w:sz", NS).attrib == style.find("w:rPr/w:szCs", NS).attrib
        assert not any(b'TargetMode="External"' in archive.read(name) for name in archive.namelist() if name.endswith(".rels"))


def test_docx_preserves_latin_fragments_in_rtl_paragraphs_and_keeps_digest_identity_in_same_row():
    url = "https://evidence.example.test/path/"
    payload = {
        "case": {"title": "تحقيق / Investigation", "reference": "CASE-DIRECTION"},
        "revision": 1,
        "records": {"root_cause": [{"payload": {"title": "تحليل / Analysis", "conclusion": "المصدر: " + url}}]},
        "evidence": [
            {"title": "Short evidence", "id": 2, "details": "ملاحظة قصيرة", "sha256": "a" * 64},
            {"title": "Long evidence", "id": 9, "details": "ملاحظة طويلة " * 150, "sha256": "b" * 64},
        ],
    }
    original = copy.deepcopy(payload)
    document = Document(io.BytesIO(render_docx(payload)))
    heading = next(paragraph for paragraph in document.paragraphs if "5 Whys" in paragraph.text)
    latin_run = next(run for run in heading.runs if run.text == "5 Whys")
    assert latin_run.font.rtl is False and latin_run.font.name == "IBM Plex Sans"
    url_run = next(
        run
        for table in document.tables
        for row in table.rows
        for cell in row.cells
        for paragraph in cell.paragraphs
        for run in paragraph.runs
        if run.text == url
    )
    assert url_run.font.rtl is False
    evidence_table = document.tables[-1]
    short_rows = list(evidence_table.rows)[:4]
    assert all(row.cells[0].paragraphs[0].paragraph_format.keep_with_next for row in short_rows[:-1])
    assert short_rows[-1].cells[0].paragraphs[0].paragraph_format.keep_with_next is False
    digest_row = next(row for row in evidence_table.rows if row.cells[-1].text == "b" * 64)
    assert "Long evidence" in digest_row.cells[0].text
    assert digest_row._tr.xpath("./w:trPr/w:cantSplit")
    long_notes = next(row for row in evidence_table.rows if row.cells[-1].text == payload["evidence"][1]["details"])
    assert long_notes.cells[0].paragraphs[0].paragraph_format.keep_with_next is False
    assert not long_notes._tr.xpath("./w:trPr/w:cantSplit")
    assert payload == original
