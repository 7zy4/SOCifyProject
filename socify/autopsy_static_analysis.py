import base64
import hashlib
import math
import re
import struct
from collections import Counter

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
