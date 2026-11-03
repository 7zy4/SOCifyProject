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
    text = "\n".join(document.element.xpath(".//w:t/text()"))
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
