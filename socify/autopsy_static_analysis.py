import base64
import contextlib
import hashlib
import io
import math
import re
import struct
import zipfile
from collections import Counter
from pathlib import PurePosixPath

import yara

BUILTIN_RULES = 'rule SOCify_EICAR_Test_Marker { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }'


def validate_yara(payload):
    source, fixtures = payload["rules"], payload["fixtures"]
    if not isinstance(source, str) or len(source.encode()) > 65536:
        raise ValueError("YARA rules exceed the local limit")
    digest = hashlib.sha256(source.encode()).hexdigest()
    try:
        compiled = yara.compile(source=source, includes=False, error_on_warning=True)
        rules = [rule.identifier for rule in compiled]
        if not 1 <= len(rules) <= 100 or any(len(name) > 256 for name in rules):
            raise ValueError("YARA rule count or identifier exceeds limits")
        passed = {}
        for kind in ("positive", "negative"):
            items = fixtures[kind]
            if not isinstance(items, list) or not 1 <= len(items) <= 10:
                raise ValueError("YARA fixture count exceeds limits")
            for encoded in items:
                content = base64.b64decode(encoded, validate=True)
                if not 1 <= len(content) <= 65536 or bool(compiled.match(data=content, timeout=1)) != (kind == "positive"):
                    raise ValueError("YARA fixture mismatch")
            passed[kind] = len(items)
        return {
            "valid": True,
            "sha256": digest,
            "engine_version": yara.__version__,
            "rules": rules,
            "fixtures_passed": passed,
            "fixtures_sha256": hashlib.sha256(json_fixtures(fixtures)).hexdigest(),
            "limitations": "Provided synthetic fixtures only; no malware-free verdict",
        }
    except (yara.Error, ValueError):
        return {"valid": False, "sha256": digest}


def json_fixtures(fixtures):
    from .autopsy_domain import canonical

    return canonical(fixtures).encode()


def analyze_sample(payload):
    content = base64.b64decode(payload["content"], validate=True)
    if not content or len(content) > 10 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != payload["sha256"]:
        raise ValueError("Sample size or digest is invalid")
    counts = Counter(content)
    entropy = -sum((count / len(content)) * math.log2(count / len(content)) for count in counts.values())
    kind = "unrecognized binary or text"
    pe = None
    if content.startswith(b"MZ"):
        kind = "DOS signature; PE not yet verified"
        if len(content) >= 64:
            offset = struct.unpack_from("<I", content, 60)[0]
            if offset <= len(content) - 24 and content[offset : offset + 4] == b"PE\x00\x00":
                machine, sections, timestamp = struct.unpack_from("<HHI", content, offset + 4)
                pe = {"machine": machine, "sections": sections, "coff_timestamp_untrusted": timestamp}
                kind = "PE header verified; content never executed"
    elif content.startswith(b"\x7fELF"):
        kind = "ELF signature; content never executed"
    elif content.startswith(b"PK\x03\x04"):
        kind = "ZIP-compatible container; not extracted or executed"
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{6,256}", content):
        strings.append(match[0].decode("ascii"))
        if len(strings) >= 100:
            break
    source = payload.get("rules", BUILTIN_RULES)
    if not isinstance(source, str) or len(source.encode()) > 65536:
        raise ValueError("YARA rules exceed the local limit")
    compiled = yara.compile(source=source, includes=False, error_on_warning=True)
    matches = compiled.match(data=content, timeout=5)
    return {
        "engine": "SOCify local static analysis/1",
        "yara_version": yara.__version__,
        "sample_id": payload["sample_id"],
        "evidence_id": payload["evidence_id"],
        "sha256": payload["sha256"],
        "sha1": hashlib.sha1(content, usedforsecurity=False).hexdigest(),
        "md5": hashlib.md5(content, usedforsecurity=False).hexdigest(),
        "hash_purpose": "MD5/SHA-1 identify existing forensic artifacts; only SHA-256 verifies integrity",
        "size": len(content),
        "entropy_bits_per_byte": round(entropy, 4),
        "file_type_observation": kind,
        "pe_header": pe,
        "printable_strings_first_100": strings,
        "yara_rules_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "yara_rules_source": payload.get("rules_source", "Bundled EICAR test marker only"),
        "yara_pack": payload.get(
            "yara_pack", {"name": "SOCify EICAR test marker", "version": 1, "license": "SOCify project license; synthetic test marker only"}
        ),
        "yara_matches": [{"rule": match.rule, "tags": match.tags} for match in matches[:100]],
        "network": "no network queries",
        "execution": "never executed",
        "limitations": [
            "تحليل ساكن محدود وليس sandbox ديناميكيًا أو حكمًا بخلو الملف من المالوير.",
            "الـYARA الافتراضي يكتشف علامة اختبار EICAR فقط؛ غياب التطابق لا يثبت سلامة العينة.",
            "الامتداد والتوقيع والطابع الزمني والسلاسل ملاحظات غير موثوقة. لا فك أرشيف أو اتصال بالعناوين المستخرجة.",
        ],
    }


EXECUTABLE_EXTS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".pif",
    ".msi",
    ".msp",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".lnk",
    ".jar",
    ".elf",
    ".apk",
}
BENIGN_DOC_EXTS = {
    ".pdf",
    ".txt",
    ".csv",
    ".log",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".webp",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".rtf",
    ".mp3",
    ".mp4",
}
MACRO_OOXML_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
ARCHIVE_DANGEROUS_EXTS = EXECUTABLE_EXTS | {".iso", ".img", ".vhd", ".vhdx", ".chm", ".cpl", ".reg"}
URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]{4,512}", re.IGNORECASE)
IPV4_EXTRACT_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_EXTRACT_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b")


def _shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    total = len(buf)
    counts = Counter(buf)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _max_sliding_entropy(content: bytes, window: int = 256, stride: int = 64, cap: int = 262144) -> float:
    sample = content[:cap]
    if len(sample) <= window:
        return _shannon_entropy(sample)
    best = 0.0
    for idx in range(0, len(sample) - window + 1, stride):
        score = _shannon_entropy(sample[idx : idx + window])
        if score > best:
            best = score
    return best


def _detect_magic(content: bytes) -> tuple[str, str, dict | None]:
    pe_info = None
    if content.startswith(b"MZ"):
        if len(content) >= 64:
            offset = struct.unpack_from("<I", content, 60)[0]
            if offset <= len(content) - 24 and content[offset : offset + 4] == b"PE\x00\x00":
                machine, sections, timestamp = struct.unpack_from("<HHI", content, offset + 4)
                pe_info = {"machine": machine, "sections": sections, "coff_timestamp_untrusted": timestamp}
                return "pe_executable", "Windows PE executable (MZ/PE)", pe_info
        return "dos_executable", "DOS MZ header (unverified PE)", None
    if content.startswith(b"\x7fELF"):
        return "elf_executable", "Linux/Unix ELF binary", None
    if content[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        return "mach_o_executable", "macOS Mach-O binary", None
    if content.startswith(b"%PDF-"):
        return "pdf", "PDF document", None
    if content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole2_compound", "OLE2 Compound Document (legacy Office / MSI / MSG)", None
    if content.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip_container", "ZIP / OOXML container", None
    if content.startswith(b"Rar!\x1a\x07"):
        return "rar_archive", "RAR archive", None
    if content.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z_archive", "7-Zip archive", None
    if content.startswith(b"\x1f\x8b\x08"):
        return "gzip_archive", "GZIP archive", None
    if content.startswith(b"{\\rtf"):
        return "rtf_document", "Rich Text Format (RTF) document", None
    if len(content) >= 20 and content.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk_shortcut", "Windows Shell Link (.LNK) shortcut", None
    head = content[:2048].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<script", b"<!--")) or b"<script" in head:
        return "html_document", "HTML / script-bearing markup", None
    if head.startswith(b"<?xml") or head.startswith(b"<"):
        return "xml_document", "XML document", None
    if all(b in b"\t\r\n" or 32 <= b <= 126 or b >= 128 for b in content[:512]):
        return "text_or_script", "UTF-8 / ASCII text or script", None
    return "unknown_binary", "Unrecognized binary data", None


def inspect_static_bytes(
    filename: str,
    content: bytes,
    declared_mime: str | None = None,
    yara_source: str | None = None,
) -> dict:
    if not content:
        raise ValueError("الملف فارغ ولا يمكن فحصه")
    if len(content) > 10 * 1024 * 1024:
        raise ValueError("يتجاوز حجم الملف الحد الأقصى للفحص الساكن السريع (10 MiB)")

    raw_name = (filename or "sample.bin").strip()
    clean_name = raw_name.replace("\\", "/").rsplit("/", 1)[-1]
    suffixes = [s.lower() for s in PurePosixPath(clean_name).suffixes]
    declared_ext = suffixes[-1] if suffixes else ""
    has_bidi_override = any(ch in raw_name for ch in ("\u202e", "\u202d", "\u202a", "\u202b", "\u200e", "\u200f"))
    double_extension = len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTS and suffixes[-2] in (BENIGN_DOC_EXTS | MACRO_OOXML_EXTS)

    magic_code, magic_desc, pe_header = _detect_magic(content)
    overall_entropy = round(_shannon_entropy(content), 4)
    window_entropy = round(_max_sliding_entropy(content), 4)

    flags: list[dict] = []
    risk_score = 0

    def add_flag(code: str, severity: str, points: int, detail: str) -> None:
        nonlocal risk_score
        if not any(f["code"] == code for f in flags):
            flags.append({"code": code, "severity": severity, "detail": detail})
            risk_score = min(100, risk_score + points)

    if has_bidi_override:
        add_flag("filename_bidi_spoofing", "critical", 55, "اسم الملف يحتوي محارف عكس اتجاه النص (RTLO) لانتحال الامتداد.")
    if double_extension:
        add_flag("double_extension", "high", 45, f"امتداد مزدوج مضلل في اسم الملف ({''.join(suffixes[-2:])}).")

    # Magic vs declared extension mismatch
    extension_mismatch = False
    is_exec_magic = magic_code in {"pe_executable", "dos_executable", "elf_executable", "mach_o_executable", "lnk_shortcut"}
    if is_exec_magic and declared_ext and declared_ext not in EXECUTABLE_EXTS:
        extension_mismatch = True
        add_flag(
            "magic_extension_mismatch",
            "critical",
            60,
            f"بصمة الملف الفعلية ({magic_desc}) تتعارض مع الامتداد المعلن ({declared_ext}).",
        )
    elif magic_code == "pdf" and declared_ext and declared_ext not in {".pdf", ".bin"}:
        extension_mismatch = True
        add_flag("magic_extension_mismatch", "medium", 25, f"ترويسة PDF فعلية بامتداد مختلف ({declared_ext}).")
    elif magic_code == "html_document" and declared_ext in {".pdf", ".docx", ".xlsx", ".jpg", ".png"}:
        extension_mismatch = True
        add_flag("magic_extension_mismatch", "high", 45, f"صفحة HTML/Script متنكرة بامتداد مستند أو صورة ({declared_ext}).")

    if is_exec_magic:
        add_flag("executable_binary", "high", 35, f"ملف تنفيذي ثنائي ({magic_desc}) — لم يُشغّل نهائيًا.")

    # ZIP / OOXML bounded central-directory inspection (never extracted to disk)
    archive_summary: dict | None = None
    if magic_code == "zip_container":
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                infos = zf.infolist()
                entry_names = [info.filename for info in infos[:1024]]
                total_uncompressed = sum(max(0, info.file_size) for info in infos[:1024])
                total_compressed = max(1, sum(max(0, info.compress_size) for info in infos[:1024]))
                ratio = round(total_uncompressed / total_compressed, 2)
                is_ooxml = "[Content_Types].xml" in entry_names
                if is_ooxml:
                    magic_code = "ooxml_document"
                    magic_desc = "OOXML Office Document (Word/Excel/PowerPoint)"
                archive_summary = {
                    "entries_inspected": min(len(infos), 1024),
                    "total_entries": len(infos),
                    "total_uncompressed_bytes": total_uncompressed,
                    "compression_ratio": ratio,
                    "is_ooxml": is_ooxml,
                    "sample_entries": entry_names[:25],
                }
                if len(infos) > 1024 or (ratio > 100 and total_uncompressed > 50 * 1024 * 1024):
                    add_flag("zip_bomb_ratio_warning", "high", 45, f"نسبة ضغط مرتفعة جدًا ({ratio}x) أو عدد ملفات ضخم داخل الأرشيف.")
                macro_entries = [
                    info
                    for info in infos[:1024]
                    if info.filename.lower().endswith(("vbaproject.bin", "vbadata.xml")) or "/macrosheets/" in info.filename.lower()
                ]
                if macro_entries:
                    macro_keywords: list[str] = []
                    for m_info in macro_entries[:3]:
                        try:
                            with zf.open(m_info) as m_stream:
                                macro_buf = m_stream.read(262144).lower()
                            for kw in (
                                b"autoopen",
                                b"document_open",
                                b"workbook_open",
                                b"wscript.shell",
                                b"powershell",
                                b"createobject",
                                b"urldownloadtofile",
                                b"shell",
                            ):
                                if kw in macro_buf:
                                    macro_keywords.append(kw.decode("ascii"))
                        except (RuntimeError, zipfile.BadZipFile, OSError):
                            pass
                    kw_note = f" ({', '.join(dict.fromkeys(macro_keywords))})" if macro_keywords else ""
                    add_flag(
                        "vba_macro_detected",
                        "critical" if macro_keywords else "high",
                        70 if macro_keywords else 50,
                        f"تم رصد مشروع ماكرو VBA مضمّن داخل مستند Office{kw_note}.",
                    )
                risky_members = [name for name in entry_names if PurePosixPath(name).suffix.lower() in ARCHIVE_DANGEROUS_EXTS]
                if risky_members:
                    add_flag(
                        "archive_contains_executable_or_script",
                        "high",
                        55,
                        f"يحتوي الأرشيف على ملفات تنفيذية أو سكربتات مضمّنة: {', '.join(risky_members[:5])}",
                    )
        except zipfile.BadZipFile:
            add_flag("corrupt_zip_container", "medium", 20, "ترويسة PK غير صالحة أو أرشيف ZIP تالف/مشفر.")

    # PDF active content inspection
    lower_window = content[:524288].lower()
    if magic_code == "pdf":
        pdf_hits = [
            token.decode("ascii")
            for token in (b"/javascript", b"/js", b"/openaction", b"/aa", b"/launch", b"/embeddedfile", b"/richmedia")
            if token in lower_window
        ]
        if pdf_hits:
            add_flag(
                "pdf_active_content",
                "high",
                65,
                f"يحتوي ملف PDF على أوامر نشطة أو كود مضمّن: {', '.join(pdf_hits)}",
            )

    # RTF exploit markers
    if magic_code == "rtf_document" and any(tok in lower_window for tok in (b"\\objdata", b"\\objupdate", b"equation.3")):
        add_flag("rtf_embedded_object", "high", 65, "يحتوي مستند RTF على كائن OLE مضمّن شائع في استغلال المستندات.")

    # HTML smuggling & script execution indicators
    smuggling_hits = [
        tok.decode("ascii") for tok in (b"atob(", b"new blob(", b"blob([", b"mssaveoropenblob", b"createobjecturl(", b"fromcharcode(") if tok in lower_window
    ]
    if (magic_code in {"html_document", "text_or_script"} or declared_ext in {".html", ".htm", ".svg"}) and len(smuggling_hits) >= 2:
        add_flag(
            "html_smuggling_indicator",
            "high",
            55,
            f"مؤشرات HTML Smuggling لبناء ملف ثنائي في المتصفح: {', '.join(smuggling_hits)}",
        )

    suspicious_apis = [
        tok.decode("ascii")
        for tok in (
            b"createremotethread",
            b"virtualallocex",
            b"writeprocessmemory",
            b"urldownloadtofile",
            b"wscript.shell",
            b"powershell",
            b"cmd.exe /c",
            b"frombase64string",
            b"invoke-expression",
        )
        if tok in lower_window
    ]
    if suspicious_apis:
        add_flag(
            "suspicious_execution_strings",
            "high",
            35,
            f"سلاسل نصية مرتبطة بالتنفيذ أو الحقن: {', '.join(suspicious_apis[:6])}",
        )

    if overall_entropy >= 7.2 and magic_code in {"pe_executable", "dos_executable", "elf_executable", "unknown_binary"}:
        add_flag("high_entropy_packed_or_encrypted", "medium", 25, f"إنتروبيا كلية مرتفعة ({overall_entropy} bits/byte) قد تشير لضغط أو تشفير.")
    elif window_entropy >= 6.8 and magic_code in {"html_document", "text_or_script"}:
        add_flag("high_window_entropy_embedded_blob", "medium", 25, f"كتلة عالية الإنتروبيا داخل نص/سكربت ({window_entropy} bits/byte).")

    # Printable strings & IOC extraction
    strings: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{6,256}", content[:1048576]):
        strings.append(match[0].decode("ascii", errors="ignore"))
        if len(strings) >= 120:
            break
    joined_strings = "\n".join(strings)
    extracted_urls = list(dict.fromkeys(URL_EXTRACT_RE.findall(joined_strings)))[:50]
    extracted_ips = [ip for ip in dict.fromkeys(IPV4_EXTRACT_RE.findall(joined_strings)) if not ip.startswith(("0.", "127.", "255."))][:50]
    extracted_emails = list(dict.fromkeys(e.lower() for e in EMAIL_EXTRACT_RE.findall(joined_strings)))[:50]

    # Local YARA check (graceful pure-Python safety)
    rules_text = yara_source if isinstance(yara_source, str) and yara_source.strip() else BUILTIN_RULES
    yara_matches: list[dict] = []
    with contextlib.suppress(yara.Error, ValueError, OSError):
        if len(rules_text.encode("utf-8")) <= 65536:
            compiled = yara.compile(source=rules_text, includes=False, error_on_warning=True)
            for m in compiled.match(data=content, timeout=3)[:50]:
                yara_matches.append({"rule": m.rule, "tags": list(m.tags)})
    if yara_matches:
        add_flag("yara_rule_match", "critical", 75, f"تطابق مع قواعد YARA المحلية: {', '.join(m['rule'] for m in yara_matches[:5])}")

    verdict = "high_risk" if risk_score >= 65 else "suspicious" if risk_score >= 30 else "low_signal_static_only"
    return {
        "engine": "SOCify Quick Static Triage/1",
        "filename": clean_name,
        "declared_extension": declared_ext or None,
        "declared_mime": (declared_mime or "")[:100] or None,
        "detected_magic": magic_code,
        "file_type_observation": magic_desc,
        "extension_mismatch": extension_mismatch,
        "double_extension": double_extension,
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha1": hashlib.sha1(content, usedforsecurity=False).hexdigest(),
        "md5": hashlib.md5(content, usedforsecurity=False).hexdigest(),
        "size": len(content),
        "entropy_bits_per_byte": overall_entropy,
        "max_window_entropy_256b": window_entropy,
        "pe_header": pe_header,
        "archive_summary": archive_summary,
        "flags": flags,
        "risk_score": risk_score,
        "verdict": verdict,
        "yara_matches": yara_matches,
        "extracted_urls": extracted_urls,
        "extracted_ips": extracted_ips,
        "extracted_emails": extracted_emails,
        "printable_strings_first_100": strings[:100],
        "network": "no network queries",
        "execution": "never executed",
        "limitations": [
            "فحص ساكن أولي آمن دون تشغيل الملف أو فك تشفيره على القرص.",
            "غياب المؤشرات الساكنة لا يعني سلامة الملف نهائيًا؛ عند الاشتباه العميق انقل العينة لبيئة Sandbox معزولة.",
        ],
    }
