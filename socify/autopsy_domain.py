import hashlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from .audit import record_audit
from .cases import _case_row
from .db import get_db
from .operational import case_visible
from .security import actor_id, has_permission
from .timeutils import iso_now, iso_timestamp, parse_timestamp

ASSET_TYPES = [
    "web_server",
    "application_server",
    "database",
    "workstation",
    "router",
    "switch",
    "firewall",
    "security_appliance",
    "container",
    "cloud_asset",
    "other",
    "unknown",
]
ASSET_ROLES = ["suspected_attacker", "defender", "affected", "intermediary", "unknown"]
KINDS: dict[str, dict[str, dict[str, Any]]] = {
    "bookmark": {
        "event_id": {"event": True, "required": True},
        "title": {"max": 255, "required": True},
        "color": {"choices": ["blue", "orange", "gold"]},
        "tags": {"list": True},
        "notes": {"max": 2000},
        "visibility": {"choices": ["team", "private"], "required": True},
    },
    "timeline_view": {
        "title": {"max": 160, "required": True},
        "query": {"max": 200},
        "severity": {"choices": ["critical", "high", "medium", "low"]},
        "start": {"timestamp": True},
        "end": {"timestamp": True},
        "visibility": {"choices": ["team", "private"], "required": True},
    },
    "asset": {
        "name": {"required": True, "max": 255},
        "type": {"choices": ASSET_TYPES, "required": True},
        "role": {"choices": ASSET_ROLES, "required": True},
        "address": {"max": 512},
        "owner": {"max": 255},
        "operating_system": {"max": 255},
        "importance": {"choices": ["critical", "high", "medium", "low", "unknown"]},
        "assessment": {"choices": ["confirmed", "suspected", "checked_clear", "unexamined"]},
        "details": {"max": 2000},
    },
    "indicator": {
        "type": {"required": True, "choices": ["ip", "domain", "url", "email", "hostname", "file_path", "md5", "sha1", "sha256"]},
        "value": {"required": True, "max": 2048},
        "classification": {"required": True, "choices": ["observable", "ioc"]},
        "status": {"choices": ["active", "expired", "revoked", "undetermined"]},
        "confidence": {"integer": True, "min": 0, "max": 100},
        "source": {"required": True, "max": 500},
        "expires_at": {"timestamp": True},
        "description": {"max": 2000},
    },
    "timeline": {
        "title": {"required": True, "max": 255},
        "event_time": {"required": True, "timestamp": True},
        "category": {"required": True, "choices": ["observed", "hypothesis", "action"]},
        "source": {"required": True, "max": 500},
        "confidence": {"integer": True, "min": 0, "max": 100},
        "tags": {"list": True},
        "details": {"max": 4000},
    },
    "war_room": {
        "title": {"required": True, "max": 255},
        "body": {"required": True, "max": 6000},
        "visibility": {"choices": ["team", "private"]},
        "decision": {"max": 2000},
        "task_id": {"task": True},
    },
    "hypothesis": {
        "title": {"required": True, "max": 255},
        "statement": {"required": True, "max": 4000},
        "assessment": {"required": True, "choices": ["open", "supported", "refuted"]},
        "confidence": {"integer": True, "min": 0, "max": 100},
    },
    "response": {
        "title": {"required": True, "max": 255},
        "phase": {"required": True, "choices": ["acknowledgement", "triage", "detection", "containment", "eradication", "recovery", "validation"]},
        "status": {"required": True, "choices": ["planned", "in_progress", "succeeded", "failed", "not_applicable"]},
        "performed_by": {"user": True},
        "performed_at": {"timestamp": True},
        "details": {"required": True, "max": 4000},
    },
    "corrective": {
        "title": {"required": True, "max": 255},
        "owner_id": {"required": True, "user": True},
        "due_at": {"required": True, "timestamp": True},
        "status": {"required": True, "choices": ["open", "in_progress", "completed", "validated"]},
        "validation": {"max": 4000},
        "root_cause_id": {"record_kind": "root_cause"},
        "why_id": {"max": 64},
    },
    "foothold": {
        "title": {"required": True, "max": 255},
        "asset_id": {"required": True, "asset": True},
        "first_observed_at": {"required": True, "timestamp": True},
        "confidence": {"required": True, "integer": True, "min": 0, "max": 100},
        "limitations": {"required": True, "max": 4000},
    },
    "root_cause": {
        "category": {
            "required": True,
            "choices": [
                "compromised_credentials",
                "misconfiguration",
                "exploited_vulnerability",
                "phishing",
                "excessive_privileges",
                "monitoring_gap",
                "supply_chain",
                "unknown",
                "other",
            ],
        },
        "conclusion": {"required": True, "max": 4000},
        "confidence": {"integer": True, "min": 0, "max": 100},
        "whys": {"whys": True},
    },
    "escalation": {
        "to_user": {"required": True, "user": True},
        "from_level": {"required": True, "choices": ["monitoring", "l1", "l2", "investigation", "management"]},
        "to_level": {"required": True, "choices": ["l1", "l2", "investigation", "management"]},
        "reason": {"required": True, "max": 2000},
        "priority": {"required": True, "choices": ["urgent", "high", "medium", "low"]},
        "status": {"required": True, "choices": ["raised", "acknowledged", "returned", "resolved"]},
        "response": {"max": 4000},
    },
}


def text_value(value: object, maximum: int, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("يلزم نص صالح")
    result = value.strip()
    if len(result) > maximum or required and not result:
        raise ValueError("طول النص غير صالح")
    try:
        result.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("ترميز النص غير صالح") from exc
    if any(ord(char) < 32 and char not in "\n\t" for char in result):
        raise ValueError("النص يحتوي محارف تحكم غير مسموحة")
    return result


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def custody(case_id: int, action: str, details: dict[str, Any], actor: int | None = None) -> None:
    previous = get_db().execute("SELECT entry_hash FROM autopsy_custody WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    previous_hash = previous[0] if previous else "0" * 64
    now = iso_now()
    principal = actor if actor is not None else actor_id()
    clean = canonical(details)
    digest = hashlib.sha256(canonical([case_id, principal, action, clean, previous_hash, now]).encode()).hexdigest()
    get_db().execute(
        "INSERT INTO autopsy_custody(case_id, actor_id, action, details, previous_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, principal, action, clean, previous_hash, digest, now),
    )
    owner = get_db().execute("SELECT workspace_id FROM incident_cases WHERE id = ?", (case_id,)).fetchone()
    record_audit(get_db(), action, "autopsy_case", case_id, details=details, actor=principal, workspace=owner["workspace_id"])


def touch_case(case_id: int) -> None:
    get_db().execute("UPDATE incident_cases SET updated_at = ?, version = version + 1 WHERE id = ?", (iso_now(), case_id))


def validate_record(case_id: int, kind: str, payload: object) -> dict[str, Any]:
    if kind not in KINDS or not isinstance(payload, dict):
        raise ValueError("نوع السجل أو بنيته غير صالح")
    schema = {**KINDS[kind], "evidence_id": {"evidence": True}}
    if set(payload) - set(schema):
        raise ValueError("الطلب يحتوي حقولًا غير معروفة")
    result: dict[str, Any] = {}
    case = _case_row(case_id)
    if not case:
        raise ValueError("القضية غير متاحة")
    for key, spec in schema.items():
        value = payload.get(key)
        if value is None or value == "":
            if spec.get("required"):
                raise ValueError(f"الحقل {key} مطلوب")
            continue
        if spec.get("user"):
            if (
                type(value) is not int
                or not get_db().execute("SELECT 1 FROM users WHERE id = ? AND workspace_id = ? AND is_active = 1", (value, case["workspace_id"])).fetchone()
            ):
                raise ValueError("المستخدم المحدد غير متاح")
        elif spec.get("evidence"):
            if type(value) is not int or not get_db().execute("SELECT 1 FROM case_evidence WHERE id = ? AND case_id = ?", (value, case_id)).fetchone():
                raise ValueError("الدليل لا ينتمي إلى القضية")
        elif spec.get("asset"):
            if (
                type(value) is not int
                or not get_db().execute("SELECT 1 FROM autopsy_records WHERE id = ? AND case_id = ? AND kind = 'asset'", (value, case_id)).fetchone()
            ):
                raise ValueError("الأصل لا ينتمي إلى القضية")
        elif spec.get("event"):
            if type(value) is not int or not get_db().execute("SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", (case_id, value)).fetchone():
                raise ValueError("السجل لا ينتمي إلى القضية")
        elif spec.get("task"):
            if type(value) is not int or not get_db().execute("SELECT 1 FROM case_tasks WHERE id=? AND case_id=?", (value, case_id)).fetchone():
                raise ValueError("المهمة لا تنتمي إلى القضية")
        elif spec.get("record_kind"):
            if (
                type(value) is not int
                or not get_db()
                .execute("SELECT 1 FROM autopsy_records WHERE id = ? AND case_id = ? AND kind = ?", (value, case_id, spec["record_kind"]))
                .fetchone()
            ):
                raise ValueError("مرجع نتيجة التحقيق لا ينتمي إلى القضية")
        elif spec.get("integer"):
            if type(value) is not int or not spec.get("min", 0) <= value <= spec["max"]:
                raise ValueError(f"قيمة {key} غير صالحة")
        elif spec.get("list"):
            if not isinstance(value, list) or len(value) > 30:
                raise ValueError("قائمة الوسوم غير صالحة")
            value = [text_value(entry, 80, True) for entry in value]
        elif spec.get("whys"):
            if not isinstance(value, list) or len(value) > 10:
                raise ValueError("سلسلة الأسباب تتجاوز الحدود")
            chain = []
            for index, step in enumerate(value, 1):
                if not isinstance(step, dict) or set(step) - {"question", "answer", "evidence_id", "id", "parent_id", "assessment"}:
                    raise ValueError("خطوة تحليل السبب غير صالحة")
                item: dict[str, Any] = {"question": text_value(step.get("question"), 500, True), "answer": text_value(step.get("answer"), 2000, True)}
                identifier = text_value(step.get("id", f"why-{index}"), 64, True)
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier):
                    raise ValueError("معرف فرع السبب غير صالح")
                item["id"] = identifier
                parent = step.get("parent_id")
                if parent is not None:
                    item["parent_id"] = text_value(parent, 64, True)
                assessment = step.get("assessment", "supported" if step.get("evidence_id") else "unverified")
                if not isinstance(assessment, str) or assessment not in {"unverified", "hypothesis", "supported", "refuted"}:
                    raise ValueError("حدد ما إذا كان السبب فرضية أو نتيجة مدعومة أو غير متحققة")
                item["assessment"] = assessment
                if step.get("evidence_id") is not None:
                    evidence = step["evidence_id"]
                    if (
                        type(evidence) is not int
                        or not get_db().execute("SELECT 1 FROM case_evidence WHERE id = ? AND case_id = ?", (evidence, case_id)).fetchone()
                    ):
                        raise ValueError("دليل السبب غير متاح")
                    item["evidence_id"] = evidence
                if assessment in {"supported", "refuted"} and not item.get("evidence_id"):
                    raise ValueError("تأييد سبب أو نفيه يتطلب دليلًا من القضية")
                chain.append(item)
            identifiers = {step["id"] for step in chain}
            if len(identifiers) != len(chain):
                raise ValueError("معرف فرع السبب مكرر")
            parents = {step["id"]: step.get("parent_id") for step in chain}
            for starting_id in identifiers:
                cursor_id: str | None = starting_id
                seen = set()
                while cursor_id is not None:
                    if cursor_id not in identifiers or cursor_id in seen:
                        raise ValueError("شجرة الأسباب تحتوي مرجعًا مفقودًا أو حلقة")
                    seen.add(cursor_id)
                    cursor_id = parents[cursor_id]
            value = chain
        elif spec.get("timestamp"):
            if not isinstance(value, str) or not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value):
                raise ValueError("حدد الوقت مع منطقته الزمنية")
            value = iso_timestamp(value)
        else:
            value = text_value(value, spec.get("max", 100), spec.get("required", False))
            if spec.get("choices") and value not in spec["choices"]:
                raise ValueError(f"اختيار {key} غير صالح")
        result[key] = value
    if kind == "indicator":
        result["value"] = normalize_indicator(result["type"], result["value"])
        if result["classification"] == "ioc" and not result.get("evidence_id"):
            raise ValueError("تصنيف IOC يتطلب دليلًا مرتبطًا")
    if kind == "timeline_view" and result.get("start") and result.get("end") and parse_timestamp(result["start"]) > parse_timestamp(result["end"]):
        raise ValueError("بداية الفترة تتجاوز نهايتها")
    if kind == "corrective" and result["status"] == "validated" and not result.get("validation"):
        raise ValueError("توثيق التحقق من فاعلية الإجراء مطلوب")
    if kind == "corrective" and result.get("why_id"):
        cause = (
            get_db()
            .execute("SELECT payload FROM autopsy_records WHERE id = ? AND case_id = ? AND kind = 'root_cause'", (result.get("root_cause_id"), case_id))
            .fetchone()
        )
        if cause is None or not any(
            step.get("id", f"why-{index}") == result["why_id"] for index, step in enumerate(json.loads(cause["payload"]).get("whys", []), 1)
        ):
            raise ValueError("فرع السبب المرتبط بالإجراء التصحيحي غير متاح")
    if kind == "corrective":
        principal = dict(get_db().execute("SELECT id,role,workspace_id FROM users WHERE id=?", (result["owner_id"],)).fetchone())
        policy = (
            get_db()
            .execute("SELECT permissions FROM team_role_permissions WHERE workspace_id=? AND role=?", (case["workspace_id"], principal["role"]))
            .fetchone()
        )
        if policy:
            principal["role_permissions"] = json.loads(policy[0])
        if not case_visible(case_id, principal) or not has_permission(principal, "cases.read") or not has_permission(principal, "cases.update"):
            raise ValueError("مسؤول الإجراء يحتاج عضوية القضية وصلاحية قراءتها وتحديثها؛ أضفه عبر المدير قبل إسناد الإجراء")
    if (
        kind == "foothold"
        or kind == "hypothesis"
        and result.get("assessment") in {"supported", "refuted"}
        or kind == "root_cause"
        and result.get("category") != "unknown"
    ) and not result.get("evidence_id"):
        raise ValueError("الاستنتاج المؤكد يتطلب دليلًا مرتبطًا")
    if (
        kind == "response"
        and result["status"] == "succeeded"
        and (not result.get("performed_by") or not result.get("performed_at") or not result.get("evidence_id"))
    ):
        raise ValueError("الإجراء الناجح يتطلب منفذًا ووقتًا ودليلًا")
    return result


def normalize_indicator(kind: str, value: str) -> str:
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if kind in {"md5", "sha1", "sha256"}:
        if not re.fullmatch(rf"[0-9a-fA-F]{{{ {'md5': 32, 'sha1': 40, 'sha256': 64}[kind] }}}", value):
            raise ValueError("بصمة الملف غير صالحة")
        return value.lower()
    if kind in {"domain", "hostname"}:
        normalized = value.rstrip(".").encode("idna").decode().lower()
        if len(normalized) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in normalized.split(".")):
            raise ValueError("اسم المضيف أو النطاق غير صالح")
        return normalized
    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("عنوان URL غير صالح")
    if kind == "email" and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("البريد الإلكتروني غير صالح")
    return value
