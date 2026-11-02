"""Bounded, deterministic inspection of retained text; never executes or fetches it."""

import base64
import binascii
import json
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import unquote

ENGINE = "socify-content-1"
RESERVED_FIELDS = {"content_inspection", "exposed_secret_count", "sensitive_data_count", "decoded_threat_count"}
TEXT_LIMIT = 32768
FINDING_LIMIT = 40
TOKEN_LIMIT = 12
DEPTH_LIMIT = 4
SECRET_NAME = re.compile(r"(?:password|passwd|pwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key)", re.I)
ASSIGNMENT = re.compile(r"\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key)\s*[=:]\s*[\"']?([^\s\"'&,;]{8,256})", re.I)
BEARER = re.compile(r"\bBearer[ \t]+([A-Za-z0-9_.~+/-]{20,512}=*)", re.I)
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|$)"
)
CARD = re.compile(r"(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])")
IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\b")
TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,4096}={0,6}(?![A-Za-z0-9+/=_-])")
POWERSHELL = re.compile(r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?).*?\s-(?:e|en|enc|enco|encodedcommand)\s+[\"']?([A-Za-z0-9+/]{8,4096}={0,2})", re.I)
THREAT = re.compile(r"downloadstring\s*\(|invoke-expression\b|\biex\s*\(|/etc/(?:passwd|shadow)\b|vssadmin\s+delete\s+shadows|sekurlsa\b", re.I)


def entropy(value):
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in Counter(value).values()) if value else 0.0


def plausible_secret(value):
    lowered = value.lower()
    return (
        len(value) >= 8
        and entropy(value) >= 3
        and not lowered.startswith(("${", "<", "example", "changeme", "redacted"))
        and not re.fullmatch(r"[xX*•.]+", value)
    )


def card_checksum(value):
    digits = re.sub(r"[ -]", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 2 or not digits.isascii() or not digits.isdecimal():
        return False
    total = 0
    for position, character in enumerate(reversed(digits)):
        digit = int(character) * (2 if position % 2 else 1)
        total += digit - 9 if digit > 9 else digit
    return total % 10 == 0 and digits[0] in "3456"


def iban_checksum(value):
    compact = value.replace(" ", "")
    if not 15 <= len(compact) <= 34 or not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+", compact):
        return False
    remainder = 0
    for character in compact[4:] + compact[:4]:
        for digit in str(ord(character) - 55) if character.isalpha() else character:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def sensitive_matches(text, field=""):
    matches = []
    for pattern, kind, check, group in (
        (ASSIGNMENT, "credential_assignment", plausible_secret, 1),
        (BEARER, "bearer_token", plausible_secret, 1),
        (PRIVATE_KEY, "private_key", lambda value: True, 0),
        (CARD, "payment_card", card_checksum, 0),
        (IBAN, "iban", iban_checksum, 0),
    ):
        for match in pattern.finditer(text):
            value = match.group(group)
            if check(value):
                matches.append((match.start(group), match.end(group), kind))
            if len(matches) > FINDING_LIMIT:
                break
    if SECRET_NAME.fullmatch(field.rsplit(".", 1)[-1]) and plausible_secret(text.strip()):
        matches.append((0, len(text), "credential_assignment"))
    return sorted(set(matches))[: FINDING_LIMIT + 1]


def mask_text(text, matches):
    intervals: list[tuple[int, int]] = []
    for start, end, _ in sorted(matches):
        if intervals and start <= intervals[-1][1]:
            intervals[-1] = (intervals[-1][0], max(end, intervals[-1][1]))
        else:
            intervals.append((start, end))
    masked = text
    for start, end in reversed(intervals):
        masked = masked[:start] + "[REDACTED]" + masked[end:]
    return masked


def readable(content, powershell=False):
    encodings = ["utf-16-le"] if powershell else ["utf-8"]
    for encoding in encodings:
        try:
            text = content.decode(encoding)
        except UnicodeError:
            continue
        if text and all(character.isprintable() or character in "\r\n\t" for character in text):
            return text
    return None


def decode_layer(text, powershell=False):
    if re.search(r"%[0-9a-fA-F]{2}", text):
        decoded = unquote(text, errors="strict")
        if decoded != text and all(character.isprintable() or character in "\r\n\t" for character in decoded):
            return "url", decoded
    raw = text.strip()
    variants = []
    if len(raw) >= 16 and len(raw) % 2 == 0 and re.fullmatch(r"[a-fA-F0-9]+", raw):
        variants.append(("hex", lambda: bytes.fromhex(raw)))
    if len(raw) >= 16 and re.fullmatch(r"[A-Z2-7]+={0,6}", raw):
        variants.append(("base32", lambda: base64.b32decode(raw + "=" * (-len(raw) % 8))))
    if len(raw) >= 8 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", raw):
        variants.append(
            ("base64url" if "-" in raw or "_" in raw else "base64", lambda: base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True))
        )
    for kind, decoder in variants:
        try:
            result = readable(decoder(), powershell)
            if result is not None and result != text:
                return kind + ("_utf16le" if powershell else ""), result
        except (ValueError, binascii.Error, UnicodeError):
            continue
    return None


def inspect_content(source):
    fields: list[tuple[str, str]] = []
    remaining = TEXT_LIMIT
    truncated = False

    def visit(value, path="", depth=0):
        nonlocal remaining, truncated
        if depth > 12 or len(fields) >= 64 or remaining <= 0:
            truncated = True
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if key not in RESERVED_FIELDS and key != "normalized_fields":
                    visit(item, f"{path}.{key}".strip("."), depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value[:64]):
                visit(item, f"{path}.{index}", depth + 1)
            truncated |= len(value) > 64
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text = str(value)
            truncated |= len(text) > remaining
            fields.append((path[:200], text[:remaining]))
            remaining -= min(len(text), remaining)

    visit(source)
    findings: list[dict[str, Any]] = []
    decoded = []
    candidates_used = 0
    threats = 0
    for field, text in fields:
        matches = sensitive_matches(text, field)

        def retain(items, layer=0, source_field=field):
            nonlocal truncated
            for start, end, kind in items:
                if len(findings) >= FINDING_LIMIT:
                    truncated = True
                    break
                findings.append({"kind": kind, "field": source_field, "offset": start, "length": end - start, "layer": layer, "value": "[REDACTED]"})

        retain(matches)
        candidates = [(text, 0, False)] if re.search(r"%[0-9a-fA-F]{2}", text) else []
        ps = POWERSHELL.search(text)
        if ps:
            candidates.append((ps.group(1), ps.start(1), True))
        else:
            candidates.extend(
                (match.group(), match.start(), False)
                for match in TOKEN.finditer(text)
                if not any(start < match.end() and end > match.start() for start, end, _ in matches)
            )
        for value, offset, is_ps in candidates:
            if candidates_used >= TOKEN_LIMIT:
                truncated = True
                break
            candidates_used += 1
            layers: list[dict[str, Any]] = []
            for depth in range(DEPTH_LIMIT):
                try:
                    result = decode_layer(value, powershell=is_ps and depth == 0)
                except (UnicodeError, ValueError):
                    result = None
                if result is None:
                    break
                kind, value = result
                detected = sensitive_matches(value, field)
                retain(detected, depth + 1)
                threats += bool(THREAT.search(value))
                # Do not leave a reversible encoded copy of a discovered secret in earlier layers.
                if detected:
                    for previous in layers:
                        previous["text"] = "[REDACTED]"
                # A bounded detector must not display unchecked remainder as safe content.
                display = "[REDACTED]" if len(detected) > FINDING_LIMIT else mask_text(value, detected)
                layers.append({"encoding": kind, "text": display, "depth": depth + 1})
            if layers:
                decoded.append({"field": field, "offset": offset, "layers": layers, "depth_limit_reached": len(layers) == DEPTH_LIMIT})
    return {"engine": ENGINE, "findings": findings, "decoded": decoded, "truncated": truncated, "decoded_threat_count": threats}


def normalized_inspection(source):
    result = inspect_content(source)
    if not result["findings"] and not result["decoded"] and not result["truncated"]:
        return {}
    secrets = sum(item["kind"] in {"credential_assignment", "bearer_token", "private_key"} for item in result["findings"])
    return {
        "content_inspection": result,
        "exposed_secret_count": secrets,
        "sensitive_data_count": len(result["findings"]) - secrets,
        "decoded_threat_count": result["decoded_threat_count"],
    }


def inspect_event_fields(raw_data, fields, description=""):
    """Replace only engine-owned fields; preserve raw evidence and extracted facts."""
    source = json.loads(raw_data)
    cleaned = {key: value for key, value in fields.items() if key not in RESERVED_FIELDS}
    if not isinstance(source, dict):
        source = {"content": source}
    for key, value in (("description", description), ("command_line", cleaned.get("command_line"))):
        if isinstance(value, str) and value and value not in source.values():
            source[key] = value
    return {**cleaned, **normalized_inspection(source)}


def inspection_snapshot(connection, case_id, workspace_id):
    """Called only after full case authorization, with explicit export limits."""
    rows = connection.execute(
        "SELECT id,raw_hash,normalized_fields FROM security_events WHERE owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND json_extract(normalized_fields,'$.content_inspection.engine')=? ORDER BY id LIMIT 2001",
        (case_id, workspace_id, ENGINE),
    ).fetchall()
    if len(rows) > 2000:
        raise ValueError("تجاوز فحص المحتوى حد التقرير: ٢٠٠٠ سجل")
    results = []
    size = 0
    for row in rows:
        inspection = json.loads(row["normalized_fields"])["content_inspection"]
        size += len(json.dumps(inspection, ensure_ascii=False).encode())
        if size > 4 * 1024 * 1024:
            raise ValueError("تجاوز حجم نتائج فحص المحتوى حد التقرير")
        results.append({"event_id": row["id"], "raw_hash": row["raw_hash"], **inspection})
    return results
