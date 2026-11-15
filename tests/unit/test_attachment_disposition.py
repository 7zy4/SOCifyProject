import pytest
from werkzeug.http import parse_options_header

from socify.file_names import attachment_disposition


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("evidence-12.txt", 'attachment; filename="evidence-12.txt"'),
        ("INC-2026-0001.html", 'attachment; filename="INC-2026-0001.html"'),
        ("SOCify-case-3-metadata_only_v1.zip", 'attachment; filename="SOCify-case-3-metadata_only_v1.zip"'),
    ],
)
def test_plain_names_are_quoted_unchanged(name, expected):
    assert attachment_disposition(name) == expected


@pytest.mark.parametrize(
    "name",
    ['report"; filename="evil.exe', "line\r\nSet-Cookie: x=1", r"back\slash.txt", "تقرير الحادثة.pdf", "", ".."],
)
def test_unsafe_or_non_ascii_names_cannot_break_the_header(name):
    value = attachment_disposition(name)
    assert "\r" not in value and "\n" not in value
    disposition, options = parse_options_header(value)
    assert disposition == "attachment"
    plain = value.split('filename="', 1)[1].split('"', 1)[0]
    assert plain and all(character.isalnum() or character in "._ -" for character in plain)
    if name:
        # The original name is still offered, percent-encoded, so nothing is lost for a browser that reads it.
        assert "filename*=UTF-8''" in value and options["filename"] == name


def test_non_ascii_name_survives_in_the_utf8_form():
    _, options = parse_options_header(attachment_disposition("تقرير الحادثة.pdf"))
    assert options["filename"] == "تقرير الحادثة.pdf"
