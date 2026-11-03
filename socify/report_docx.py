"""Portable typography and direction for retained investigation documents."""

import hashlib
from pathlib import Path
from uuid import UUID

from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.opc.packuri import PackURI
from docx.opc.part import Part
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn
from docx.oxml.xmlchemy import serialize_for_reading


def embed_report_fonts(document):
    font_table = document.part.part_related_by(RT.FONT_TABLE)
    root = parse_xml(font_table.blob)
    directory = Path(__file__).resolve().parents[1] / "static" / "fonts" / "report"
    for family, filename, style in [
        ("Cairo", "Cairo-Regular.ttf", "Regular"),
        ("Cairo", "Cairo-Bold.ttf", "Bold"),
        ("IBM Plex Sans", "IBMPlexSans-Regular.ttf", "Regular"),
        ("IBM Plex Sans", "IBMPlexSans-Bold.ttf", "Bold"),
        ("Bangers", "Bangers-Regular.ttf", "Regular"),
    ]:
        content = bytearray((directory / filename).read_bytes())
        key = UUID(bytes=hashlib.sha256(content).digest()[:16])
        mask = key.bytes[::-1]
        for index in range(32):
            content[index] ^= mask[index % 16]
        part = Part(
            PackURI(f"/word/fonts/{filename.removesuffix('.ttf')}.odttf"),
            "application/vnd.openxmlformats-officedocument.obfuscatedFont",
            bytes(content),
            document.part.package,
        )
        relation = font_table.relate_to(part, RT.FONT)
        entry = next((item for item in root if item.get(qn("w:name")) == family), None)
        if entry is None:
            entry = OxmlElement("w:font")
            entry.set(qn("w:name"), family)
            root.append(entry)
        embedded = OxmlElement(f"w:embed{style}")
        embedded.set(qn("r:id"), relation)
        embedded.set(qn("w:fontKey"), "{" + str(key).upper() + "}")
        embedded.set(qn("w:subsetted"), "0")
        entry.append(embedded)
    font_table._blob = serialize_for_reading(root).encode("utf-8")
    for name, value in [("embedTrueTypeFonts", "1"), ("doNotEmbedSystemFonts", "0"), ("saveSubsetFonts", "0")]:
        element = OxmlElement("w:" + name)
        element.set(qn("w:val"), value)
        document.settings.element.append(element)


def set_direction(paragraph, rtl=True):
    bidi = OxmlElement("w:bidi")
    bidi.set(qn("w:val"), "1" if rtl else "0")
    paragraph._p.get_or_add_pPr().append(bidi)


def add_report_run(paragraph, text, bold=False):
    run = paragraph.add_run(text)
    run.bold = run.font.cs_bold = bold
    arabic = any("\u0600" <= character <= "\u06ff" for character in text)
    run.font.name = "Cairo" if arabic else "IBM Plex Sans"
    run._r.get_or_add_rPr().get_or_add_rFonts().set(qn("w:cs"), run.font.name)
    run.font.complex_script = run.font.rtl = arabic


def configure_style(style, family, arabic_family, size, ink, bold=False):
    from docx.shared import Pt, RGBColor

    style.font.name, style.font.size = family, Pt(size)
    style.font.color.rgb = RGBColor.from_string(ink)
    style.font.bold = style.font.cs_bold = bold
    properties = style.element.get_or_add_rPr()
    fonts = properties.get_or_add_rFonts()
    for attribute in list(fonts.attrib):
        if attribute.lower().endswith("theme"):
            del fonts.attrib[attribute]
    fonts.set(qn("w:cs"), arabic_family)
    fonts.set(qn("w:eastAsia"), family)
    for previous in properties.findall(qn("w:szCs")):
        properties.remove(previous)
    complex_size = OxmlElement("w:szCs")
    complex_size.set(qn("w:val"), str(size * 2))
    properties.append(complex_size)
    for borders in style.element.xpath("./w:pPr/w:pBdr"):
        borders.getparent().remove(borders)
    style.paragraph_format.line_spacing = 1.3
    style.paragraph_format.space_after = Pt(8)
