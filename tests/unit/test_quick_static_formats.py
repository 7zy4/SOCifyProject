"""Safe synthetic inputs for file-type spoofing, archives and bounded triage."""

import hashlib
import io
import zipfile

import pytest

from socify.autopsy_static_analysis import inspect_static_bytes


@pytest.mark.parametrize(
    ("filename", "content", "magic"),
    [
        ("fake.pdf", b"\x7fELF\x00inert", "elf_executable"),
        ("fake.jpg", b"\xfe\xed\xfa\xcfinert", "mach_o_executable"),
        ("legacy.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1inert", "ole2_compound"),
        ("archive.rar", b"Rar!\x1a\x07inert", "rar_archive"),
        ("archive.7z", b"7z\xbc\xaf\x27\x1cinert", "7z_archive"),
        ("archive.gz", b"\x1f\x8b\x08inert", "gzip_archive"),
        ("fake.txt", b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 20, "lnk_shortcut"),
        ("data.xml", b"<?xml version='1.0'?><data>inert</data>", "xml_document"),
        ("data.bin", b"\x00\x01\x02\x03", "unknown_binary"),
    ],
)
def test_magic_signatures_preserve_digest_and_never_execute(filename, content, magic):
    result = inspect_static_bytes(filename, content)
    assert result["detected_magic"] == magic
    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    assert result["execution"] == "never executed"
    assert result["network"] == "no network queries"


@pytest.mark.parametrize(
    ("filename", "content", "flag"),
    [
        ("invoice\u202e.pdf.exe", b"MZ inert", "filename_bidi_spoofing"),
        ("invoice.pdf.exe", b"MZ inert", "double_extension"),
        ("document.txt", b"%PDF-1.7 inert", "magic_extension_mismatch"),
        ("image.png", b"<html>inert</html>", "magic_extension_mismatch"),
        ("document.rtf", b"{\\rtf1 \\objdata inert}", "rtf_embedded_object"),
        ("archive.zip", b"PK\x03\x04invalid", "corrupt_zip_container"),
        ("packed.bin", bytes(range(256)) * 8, "high_entropy_packed_or_encrypted"),
        ("text.html", b"<html>" + bytes(range(256)) * 8, "high_window_entropy_embedded_blob"),
        ("eicar.txt", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "yara_rule_match"),
    ],
)
def test_static_risk_markers(filename, content, flag):
    result = inspect_static_bytes(filename, content)
    assert flag in {item["code"] for item in result["flags"]}
    assert 0 < result["risk_score"] <= 100


def test_archive_bounds_and_dangerous_members_without_extraction(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../outside.exe", b"inert")
        for index in range(1024):
            archive.writestr(f"item-{index}.txt", b"inert")
    result = inspect_static_bytes("archive.zip", stream.getvalue())
    assert result["archive_summary"]["entries_inspected"] == 1024
    assert result["archive_summary"]["total_entries"] == 1025
    codes = {item["code"] for item in result["flags"]}
    assert {"zip_bomb_ratio_warning", "archive_contains_executable_or_script"} <= codes
    assert not list(tmp_path.iterdir())


def test_static_limits_and_invalid_optional_yara():
    for content in (b"", b"x" * (10 * 1024 * 1024 + 1)):
        with pytest.raises(ValueError):
            inspect_static_bytes("sample.bin", content)
    for source in ("invalid yara source", "x" * 65537):
        result = inspect_static_bytes("note.txt", b"Inert evidence with no executable content", yara_source=source)
        assert result["yara_matches"] == []
        assert result["verdict"] == "low_signal_static_only"
