import hashlib
import json
import math
import re
import statistics
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Blueprint, jsonify, request

from .autopsy_api import insert_record, manager, record_view
from .autopsy_domain import canonical, custody, text_value, touch_case
from .cases import _case_row
from .db import get_db, transaction
from .operational import case_scope
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now, parse_timestamp, utc_now

autopsy_workflow_api = Blueprint("autopsy_workflow", __name__)
RECIPES = {
    "windows_auth": {
        "title": "مصادر مصادقة Windows",
        "purpose": "فحص الحسابات والدخول والتصعيد مع حفظ السياق الأصلي",
        "artifacts": ["security_evtx", "sysmon_evtx", "collection_manifest"],
        "guidance": "يجمع موظف الشركة المخول نسخ EVTX الأصلية وفق سياسة الشركة. يسجل الأداة وإصدارها والمنطقة الزمنية والنطاق؛ لا تنفذ المنصة أوامر أو VQL على الجهاز.",
    },
    "linux_auth": {
        "title": "مصادر مصادقة Linux",
        "purpose": "ربط جلسات المصادقة وsudo وأحداث النظام",
        "artifacts": ["auth_logs", "system_logs", "collection_manifest"],
        "guidance": "احتفظ بنسخ auth/secure وjournal المصرح بها وبالوقت الأصلي وإعدادات timezone. لا تفترض السنة في سجل بلا سنة دون توثيق الافتراض.",
    },
    "web_access": {
        "title": "سجلات تطبيق ويب",
        "purpose": "ربط طلبات التطبيق بسجلات الخادم والضوابط الأمنية",
        "artifacts": ["access_logs", "application_logs", "security_control_logs", "collection_manifest"],
        "guidance": "حدّد الفترة والمضيف والمسار المنطقي ومصدر الجمع المخول؛ احفظ الأصل واحجب البيانات في النسخ المشتركة فقط وفق السياسة.",
    },
    "network_evidence": {
        "title": "حزمة أدلة شبكة موجودة",
        "purpose": "مراجعة تدفقات واتصالات من أدلة محفوظة مسبقًا",
        "artifacts": ["pcap_or_pcapng", "sensor_metadata", "collection_manifest"],
        "guidance": "استورد التسجيل المحفوظ من مستشعر الشركة المخول مع نطاقه وفقد الحزم المعروف وحدود TLS. لا تلتقط المنصة مرورًا حيًا ولا تزور العناوين المستخرجة.",
    },
}


def _body(allowed, required=()):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - set(allowed) or not set(required) <= set(data):
        raise ValueError("الطلب يحتوي حقولًا مفقودة أو غير معروفة")
    return data


def _case_version(case, version):
    if type(version) is not int or version != case["version"]:
        raise ValueError("تغير إصدار القضية؛ حدّث البيانات قبل الحفظ")


def _active_member(case_id, user_id):
    if type(user_id) is not int:
        return False
    return (
        get_db()
        .execute(
            "SELECT 1 FROM users u JOIN incident_cases c ON c.workspace_id = u.workspace_id WHERE c.id = ? AND u.id = ? AND u.is_active = 1 AND (u.role IN ('admin', 'soc_manager') OR c.assignee = u.id OR c.creator = u.id OR EXISTS (SELECT 1 FROM autopsy_case_members m WHERE m.case_id = c.id AND m.user_id = u.id))",
            (case_id, user_id),
        )
        .fetchone()
        is not None
    )


def _revise(row, payload):
    serialized, version, now = canonical(payload), row["version"] + 1, iso_now()
    get_db().execute(
        "UPDATE autopsy_records SET payload = ?, version = ?, updated_by = ?, updated_at = ? WHERE id = ?", (serialized, version, actor_id(), now, row["id"])
    )
    get_db().execute(
        "INSERT INTO autopsy_record_revisions(record_id, version, payload, actor_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (row["id"], version, serialized, actor_id(), now),
    )
    custody(
        row["case_id"],
        "workflow_record_updated",
        {"record_id": row["id"], "kind": row["kind"], "version": version, "sha256": hashlib.sha256(serialized.encode()).hexdigest()},
    )
    touch_case(row["case_id"])
    return {"id": row["id"], "version": version, "payload": payload}


def validate_calendar(value):
    if (
        not isinstance(value, dict)
        or set(value) - {"mode", "timezone", "weekdays", "start_hour", "end_hour", "holidays"}
        or not isinstance(value.get("mode"), str)
        or value.get("mode") not in {"24x7", "business"}
    ):
        raise ValueError("تقويم SLA غير صالح")
    name = text_value(value.get("timezone", "UTC"), 100, True)
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("المنطقة الزمنية للتقويم غير صالحة") from exc
    if value["mode"] == "24x7":
        return {"mode": "24x7", "timezone": name}
    days, start, end, holidays = value.get("weekdays"), value.get("start_hour"), value.get("end_hour"), value.get("holidays", [])
    if not isinstance(days, list) or not 1 <= len(days) <= 7 or any(type(day) is not int or not 0 <= day <= 6 for day in days) or len(set(days)) != len(days):
        raise ValueError("أيام العمل غير صالحة؛ الاثنين 0 والأحد 6")
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= 24:
        raise ValueError("ساعات العمل من بداية اليوم حتى نهايته؛ النهاية بعد البداية")
    if not isinstance(holidays, list) or len(holidays) > 100:
        raise ValueError("قائمة أيام الإجازة تتجاوز الحد")
    for holiday in holidays:
        if not isinstance(holiday, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", holiday):
            raise ValueError("تاريخ الإجازة غير صالح")
        date.fromisoformat(holiday)
    return {"mode": "business", "timezone": name, "weekdays": sorted(days), "start_hour": start, "end_hour": end, "holidays": sorted(set(holidays))}


def _windows(start, end, calendar):
    if end <= start:
        return
    if calendar["mode"] == "24x7":
        yield start, end
        return
    zone = ZoneInfo(calendar["timezone"])
    day, final = start.astimezone(zone).date(), end.astimezone(zone).date()
    if (final - day).days > 3660:
        raise ValueError("الفترة تتجاوز عشر سنوات؛ يلزم مراجعة نطاق SLA")
    holidays = set(calendar["holidays"])
    while day <= final:
        if day.weekday() in calendar["weekdays"] and day.isoformat() not in holidays:
            opening = datetime.combine(day, time(hour=calendar["start_hour"]), zone).replace(fold=0).astimezone(UTC)
            closing = (
                datetime.combine(day + timedelta(days=calendar["end_hour"] // 24), time(hour=calendar["end_hour"] % 24), zone).replace(fold=1).astimezone(UTC)
            )
            left, right = max(start, opening), min(end, closing)
            if right > left:
                yield left, right
        day += timedelta(days=1)


def business_seconds(start, end, calendar):
    return sum((right - left).total_seconds() for left, right in _windows(start, end, calendar))


def _project_due(now, remaining, calendar):
    if remaining <= 0:
        return now.isoformat().replace("+00:00", "Z")
    for left, right in _windows(now, now + timedelta(days=366), calendar):
        length = (right - left).total_seconds()
        if remaining <= length:
            return (left + timedelta(seconds=remaining)).isoformat().replace("+00:00", "Z")
        remaining -= length
    return None


def sla_status(case, now=None):
    now = now or utc_now()
    row = get_db().execute("SELECT * FROM autopsy_records WHERE case_id = ? AND kind = 'workflow_sla' ORDER BY id DESC LIMIT 1", (case["id"],)).fetchone()
    if not row:
        return {"configured": False, "status": "not_configured", "notification": "لم يحدد المدير سياسة SLA لهذه القضية"}
    policy = json.loads(row["payload"])
    start, end = parse_timestamp(case["created_at"]), min(now, parse_timestamp(case["closed_at"])) if case["closed_at"] else now
    changes = get_db().execute("SELECT payload FROM autopsy_records WHERE case_id = ? AND kind = 'workflow_sla_action' ORDER BY id", (case["id"],)).fetchall()
    paused, total_paused = None, 0.0
    for item in changes:
        action = json.loads(item["payload"])
        moment = min(end, parse_timestamp(action["at"]))
        if action["action"] == "pause" and paused is None:
            paused = moment
        elif action["action"] == "resume" and paused is not None:
            total_paused += business_seconds(paused, moment, policy["calendar"])
            paused = None
    if paused is not None:
        total_paused += business_seconds(paused, end, policy["calendar"])
    elapsed = max(0, business_seconds(start, end, policy["calendar"]) - total_paused)
    remaining = policy["minutes"] * 60 - elapsed
    status = "closed" if case["status"] == "closed" else "paused" if paused is not None else "breached" if remaining < 0 else "running"
    return {
        "configured": True,
        "status": status,
        "policy": policy,
        "elapsed_work_seconds": elapsed,
        "paused_work_seconds": total_paused,
        "remaining_work_seconds": remaining,
        "projected_due_at": None if paused is not None or status == "closed" or remaining <= 0 else _project_due(now, remaining, policy["calendar"]),
        "notification": "تجاوزت القضية ميزانية SLA" if remaining < 0 else None,
        "basis": "الوقت المحتسب وفق تقويم القضية؛ توقفات المدير موثقة. الطي الزمني يحتسب أول بداية وآخر نهاية محليتين، ولا يرسل تنبيهًا خارجيًا.",
    }


@autopsy_workflow_api.post("/api/cases/<int:case_id>/sla")
@require_permission("cases.assign")
def configure_sla(case_id: int):
    try:
        data = _body({"version", "minutes", "calendar", "reason"}, {"version", "minutes", "calendar", "reason"})
        if type(data["minutes"]) is not int or not 1 <= data["minutes"] <= 525600:
            raise ValueError("ميزانية SLA من دقيقة إلى سنة")
        calendar, reason = validate_calendar(data["calendar"]), text_value(data["reason"], 1000, True)
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            _case_version(case, data["version"])
            if case["status"] == "closed":
                return error_response("CASE_CLOSED", "القضية مغلقة", 409)
            policy_version = get_db().execute("SELECT COUNT(*) + 1 FROM autopsy_records WHERE case_id = ? AND kind = 'workflow_sla'", (case_id,)).fetchone()[0]
            payload = {
                "minutes": data["minutes"],
                "calendar": calendar,
                "reason": reason,
                "policy_version": policy_version,
                "severity_at_configuration": case["severity"],
                "configured_by": actor_id(),
                "configured_at": iso_now(),
            }
            record_id = insert_record(case_id, "workflow_sla", payload)
    except ValueError as exc:
        return error_response("INVALID_SLA_POLICY", str(exc), 422)
    return jsonify({"id": record_id, "policy": payload}), 201


@autopsy_workflow_api.post("/api/cases/<int:case_id>/sla/<action>")
@require_permission("cases.assign")
def sla_action(case_id: int, action: str):
    if action not in {"pause", "resume"}:
        return error_response("SLA_ACTION_NOT_FOUND", "الإجراء غير متاح", 404)
    try:
        data = _body({"version", "reason"}, {"version", "reason"})
        reason = text_value(data["reason"], 1000, True)
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            _case_version(case, data["version"])
            status = sla_status(case)
            if case["status"] == "closed" or not status["configured"] or (action == "pause") == (status["status"] == "paused"):
                return error_response("SLA_STATE_CONFLICT", "تغيرت حالة SLA أو لا تنطبق العملية", 409)
            identifier = insert_record(case_id, "workflow_sla_action", {"action": action, "reason": reason, "at": iso_now(), "actor_id": actor_id()})
    except ValueError as exc:
        return error_response("INVALID_SLA_ACTION", str(exc), 422)
    return jsonify({"id": identifier, "action": action}), 201


def factual_metrics(case, records, now=None):
    now = now or utc_now()
    moments = {}
    issues = []

    def eligible(value, label):
        try:
            moment = parse_timestamp(value)
            if moment > now:
                issues.append(f"{label}: future timestamp")
                return None
            return moment
        except (ValueError, TypeError, OverflowError):
            issues.append(f"{label}: missing or invalid timestamp")
            return None

    starts = [eligible(item.get("first_observed_at"), "first_evidenced_activity") for item in records.get("foothold", []) if item.get("evidence_id")]
    first = min((item for item in starts if item), default=None)
    for phase in ("detection", "acknowledgement", "containment", "recovery"):
        choices = [
            eligible(item.get("performed_at"), phase)
            for item in records.get("response", [])
            if item.get("phase") == phase and item.get("status") == "succeeded" and item.get("evidence_id")
        ]
        moments[phase] = min((item for item in choices if item), default=None)
    responses = [
        eligible(item.get("performed_at"), "first_response")
        for item in records.get("response", [])
        if item.get("phase") != "detection" and item.get("status") == "succeeded" and item.get("evidence_id")
    ]
    moments["first_response"] = min((item for item in responses if item), default=None)
    closed = eligible(case["closed_at"], "closure") if case["closed_at"] else None

    def interval(start, end, name):
        if start is None or end is None:
            return None
        difference = (end - start).total_seconds()
        if difference < 0:
            issues.append(f"{name}: negative interval excluded")
            return None
        return difference

    metrics = {
        "detection_delay_seconds": interval(first, moments["detection"], "detection"),
        "first_response_delay_seconds": interval(moments["detection"], moments["first_response"], "first_response"),
        "acknowledgement_delay_seconds": interval(moments["detection"], moments["acknowledgement"], "acknowledgement"),
        "containment_delay_seconds": interval(moments["detection"], moments["containment"], "containment"),
        "recovery_delay_seconds": interval(moments["detection"], moments["recovery"], "recovery"),
        "closure_delay_seconds": interval(moments["detection"], closed, "closure"),
    }
    return {
        **metrics,
        "milestones": {
            "first_evidenced_activity": first.isoformat() if first else None,
            **{key: value.isoformat() if value else None for key, value in moments.items()},
        },
        "issues": issues,
        "basis": "فروق أوقات ناجحة موثقة بدليل فقط. أقدم نشاط مثبت ليس بالضرورة بداية الهجوم. يستبعد المستقبل والفروق السالبة؛ لا تستخدم أوقات رفع الملفات كرصد فعلي.",
    }


def workflow_snapshot(case):
    records: dict[str, list] = {}
    for row in get_db().execute(
        "SELECT kind, payload FROM autopsy_records WHERE case_id = ? AND kind IN ('response', 'foothold', 'asset') ORDER BY id", (case["id"],)
    ):
        records.setdefault(row["kind"], []).append(json.loads(row["payload"]))
    from .autopsy_scope import investigation_scope

    return {"sla": sla_status(case), "metrics": factual_metrics(case, records), "scope": investigation_scope(records)}


@autopsy_workflow_api.get("/api/cases/<int:case_id>/workflow")
@require_permission("cases.read")
def workflow_view(case_id: int):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    result = workflow_snapshot(case)
    result["collections"] = [
        record_view(row)
        for row in get_db().execute("SELECT * FROM autopsy_records WHERE case_id = ? AND kind = 'collection_request' ORDER BY id DESC LIMIT 100", (case_id,))
    ]
    result["postmortems"] = [
        record_view(row)
        for row in get_db().execute("SELECT * FROM autopsy_records WHERE case_id = ? AND kind = 'postmortem' ORDER BY id DESC LIMIT 50", (case_id,))
    ]
    result["recipes"] = RECIPES
    return jsonify(result)


@autopsy_workflow_api.get("/api/workflow/metrics")
@require_permission("cases.read")
def team_metrics():
    from .autopsy_pipeline import case_full_access

    scope, args = case_scope(current_user() or {})
    total = get_db().execute(f"SELECT COUNT(*) FROM incident_cases c WHERE c.workspace_id = ?{scope}", (workspace_id(), *args)).fetchone()[0]
    cases = (
        get_db().execute(f"SELECT c.* FROM incident_cases c WHERE c.workspace_id = ?{scope} ORDER BY c.id DESC LIMIT 1000", (workspace_id(), *args)).fetchall()
    )
    measurements: dict[str, list] = {}
    excluded_scope = 0
    for case in cases:
        if not case_full_access(case["id"]):
            excluded_scope += 1
            continue
        for key, value in workflow_snapshot(case)["metrics"].items():
            if key.endswith("_seconds"):
                measurements.setdefault(key, []).append(value)
    result = {}
    for key, values in measurements.items():
        included = sorted(value for value in values if value is not None)
        result[key] = {
            "included_cases": len(included),
            "excluded_cases": len(cases) - len(included),
            "mean_seconds": statistics.mean(included) if included else None,
            "median_seconds": statistics.median(included) if included else None,
            "p95_seconds": included[max(0, math.ceil(len(included) * 0.95) - 1)] if included else None,
        }
    return jsonify(
        {
            "metrics": result,
            "visible_cases": total,
            "sampled_cases": len(cases),
            "excluded_batch_scope": excluded_scope,
            "truncated": total > len(cases),
            "basis": "آخر 1000 قضية مرئية كحد أقصى. المقام معلن لكل مقياس؛ القيم غير القابلة للحساب لا تحسب صفرًا، ولا تعادل مقارنة عادلة بين فرق مختلفة الأعباء.",
        }
    )


@autopsy_workflow_api.post("/api/cases/<int:case_id>/postmortems")
@require_permission("cases.update")
def create_postmortem(case_id: int):
    try:
        data = _body({"version"}, {"version"})
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            _case_version(case, data["version"])
            if case["status"] not in {"closed", "awaiting_review", "recovered", "remediated", "contained"}:
                return error_response("POSTMORTEM_NOT_READY", "أكمل الفرز والاستجابة قبل إعداد مراجعة ما بعد الحادثة", 409)
            rows = (
                get_db()
                .execute(
                    "SELECT id, kind, payload, version, created_by, created_at FROM autopsy_records WHERE case_id = ? AND kind IN ('timeline', 'response', 'escalation', 'root_cause', 'corrective', 'foothold', 'war_room') AND COALESCE(json_extract(payload, '$.visibility'), 'team') != 'private' ORDER BY id LIMIT 1001",
                    (case_id,),
                )
                .fetchall()
            )
            if len(rows) > 1000:
                return error_response("POSTMORTEM_TOO_LARGE", "تتجاوز المراجعة 1000 سجل؛ استخدم حزمة القضية وراجع نطاق التقرير", 422)
            facts = [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]
            evidence_count = get_db().execute("SELECT COUNT(*) FROM case_evidence WHERE case_id = ?", (case_id,)).fetchone()[0]
            context = (
                get_db()
                .execute("SELECT reason, objective, classification, attack_outcome, alert_verdict FROM autopsy_case_context WHERE case_id = ?", (case_id,))
                .fetchone()
            )
            payload = {
                "state": "draft",
                "source_version": case["version"] + 1,
                "generated_at": iso_now(),
                "generated_by": actor_id(),
                "case_reference": case["reference"],
                "status_at_preparation": case["status"],
                "context": dict(context) if context else {},
                "evidence_count": evidence_count,
                "facts": facts,
                "facts_sha256": hashlib.sha256(canonical(facts).encode()).hexdigest(),
                "metrics": workflow_snapshot(case)["metrics"],
                "executive_summary": f"مراجعة {case['reference']}: {case['title']}. الأدلة المحفوظة: {evidence_count}. السجلات الموثقة في هذه النسخة: {len(facts)}.",
                "lessons": "",
                "limitations": "مسودة آلية من الحقائق الموثقة فقط. يلزم مراجعة المحقق للدروس والقيود والأسباب؛ لا تثبت غياب أدلة إضافية.",
                "reviewed_by": None,
                "reviewed_at": None,
            }
            identifier = insert_record(case_id, "postmortem", payload)
    except ValueError as exc:
        return error_response("INVALID_POSTMORTEM", str(exc), 422)
    return jsonify({"id": identifier, "version": 1, "payload": payload}), 201


@autopsy_workflow_api.post("/api/cases/<int:case_id>/postmortems/<int:record_id>/review")
@require_permission("reports.approve")
def review_postmortem(case_id: int, record_id: int):
    try:
        data = _body(
            {"version", "case_version", "executive_summary", "lessons", "limitations", "override_reason"},
            {"version", "case_version", "executive_summary", "lessons", "limitations"},
        )
        summary, lessons, limitations = (text_value(data[name], 5000, True) for name in ("executive_summary", "lessons", "limitations"))
        override = text_value(data.get("override_reason", ""), 1000)
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            _case_version(case, data["case_version"])
            row = get_db().execute("SELECT * FROM autopsy_records WHERE id = ? AND case_id = ? AND kind = 'postmortem'", (record_id, case_id)).fetchone()
            if not row:
                return error_response("POSTMORTEM_NOT_FOUND", "المراجعة غير متاحة", 404)
            payload = json.loads(row["payload"])
            if (
                type(data["version"]) is not int
                or row["version"] != data["version"]
                or payload["state"] != "draft"
                or payload["source_version"] != case["version"]
            ):
                return error_response("STALE_POSTMORTEM", "أعد مسودة تطابق آخر بيانات القضية بدل تغيير نسخة تاريخية", 409)
            if row["created_by"] == actor_id() and not (manager() and len(override) >= 10):
                return error_response("INDEPENDENT_REVIEW_REQUIRED", "يلزم مراجع آخر أو استثناء مدير مسبب لا يقل عن عشرة أحرف", 403)
            payload.update(
                state="reviewed",
                executive_summary=summary,
                lessons=lessons,
                limitations=limitations,
                reviewed_by=actor_id(),
                reviewed_at=iso_now(),
                review_override_reason=override,
            )
            result = _revise(row, payload)
    except ValueError as exc:
        return error_response("INVALID_POSTMORTEM_REVIEW", str(exc), 422)
    return jsonify(result)


@autopsy_workflow_api.post("/api/cases/<int:case_id>/collections")
@require_permission("cases.update")
def request_collection(case_id: int):
    try:
        data = _body({"version", "recipe_id", "collector_id", "reason"}, {"version", "recipe_id", "collector_id", "reason"})
        if not isinstance(data["recipe_id"], str) or data["recipe_id"] not in RECIPES:
            raise ValueError("اختر وصفة جمع محلية معروفة")
        reason = text_value(data["reason"], 2000, True)
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            _case_version(case, data["version"])
            if case["status"] == "closed":
                return error_response("CASE_CLOSED", "القضية مغلقة", 409)
            if not _active_member(case_id, data["collector_id"]):
                raise ValueError("الجامع يجب أن يكون عضوًا نشطًا مخولًا في القضية")
            payload = {
                "state": "pending_approval",
                "recipe_id": data["recipe_id"],
                "recipe_version": 1,
                "recipe_snapshot": RECIPES[data["recipe_id"]],
                "collector_id": data["collector_id"],
                "reason": reason,
                "requested_by": actor_id(),
                "requested_at": iso_now(),
                "execution_mode": "manual_documentation_only",
            }
            identifier = insert_record(case_id, "collection_request", payload)
    except ValueError as exc:
        return error_response("INVALID_COLLECTION_REQUEST", str(exc), 422)
    return jsonify({"id": identifier, "version": 1, "payload": payload}), 201


@autopsy_workflow_api.post("/api/cases/<int:case_id>/collections/<int:record_id>/<action>")
@require_permission("cases.update")
def update_collection(case_id: int, record_id: int, action: str):
    if action not in {"approve", "reject", "document"}:
        return error_response("COLLECTION_ACTION_NOT_FOUND", "الإجراء غير متاح", 404)
    try:
        data = _body({"version", "case_version", "reason", "evidence_id", "tool", "collected_at", "source", "artifacts"}, {"version", "case_version"})
        with transaction():
            case = _case_row(case_id)
            if not case:
                return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
            _case_version(case, data["case_version"])
            if case["status"] == "closed":
                return error_response("CASE_CLOSED", "القضية مغلقة", 409)
            row = (
                get_db().execute("SELECT * FROM autopsy_records WHERE id = ? AND case_id = ? AND kind = 'collection_request'", (record_id, case_id)).fetchone()
            )
            if not row:
                return error_response("COLLECTION_NOT_FOUND", "طلب الجمع غير متاح", 404)
            if type(data["version"]) is not int or row["version"] != data["version"]:
                return error_response("RECORD_VERSION_CONFLICT", "تغير الطلب؛ حدّث البيانات", 409)
            payload = json.loads(row["payload"])
            if action in {"approve", "reject"}:
                if not manager() or not has_permission(current_user(), "cases.assign"):
                    return error_response("PERMISSION_DENIED", "اعتماد نطاق الجمع أو رفضه للمدير فقط", 403)
                if payload["state"] != "pending_approval":
                    return error_response("COLLECTION_STATE_CONFLICT", "طلب الجمع ليس بانتظار الاعتماد", 409)
                payload.update(
                    state="approved" if action == "approve" else "rejected",
                    approval_reason=text_value(data.get("reason"), 1000, True),
                    approved_by=actor_id(),
                    approved_at=iso_now(),
                )
            else:
                if payload["state"] != "approved":
                    return error_response("COLLECTION_STATE_CONFLICT", "يلزم اعتماد النطاق قبل توثيق الجمع", 409)
                if payload["collector_id"] != actor_id() and not manager():
                    return error_response("PERMISSION_DENIED", "توثيق الجمع للجامع المحدد أو المدير", 403)
                evidence = data.get("evidence_id")
                row_evidence = (
                    get_db()
                    .execute("SELECT sha256 FROM case_evidence WHERE id = ? AND case_id = ?", (evidence if type(evidence) is int else None, case_id))
                    .fetchone()
                )
                if not row_evidence:
                    raise ValueError("اربط دليلًا محفوظًا من القضية")
                stamp = data.get("collected_at")
                if not isinstance(stamp, str) or not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", stamp):
                    raise ValueError("وقت الجمع يتطلب المنطقة الزمنية")
                moment = parse_timestamp(stamp)
                if moment > utc_now():
                    raise ValueError("لا توثق عملية جمع فعلية في المستقبل")
                artifacts = data.get("artifacts")
                if (
                    not isinstance(artifacts, list)
                    or not artifacts
                    or any(not isinstance(item, str) or item not in payload["recipe_snapshot"]["artifacts"] for item in artifacts)
                    or len(set(artifacts)) != len(artifacts)
                ):
                    raise ValueError("حدد مصادر الوصفة التي جُمعت فعليًا")
                missing = sorted(set(payload["recipe_snapshot"]["artifacts"]) - set(artifacts))
                payload.update(
                    state="documented_with_gaps" if missing else "documented",
                    evidence_id=evidence,
                    sha256=row_evidence["sha256"],
                    collected_at=moment.isoformat().replace("+00:00", "Z"),
                    tool=text_value(data.get("tool"), 255, True),
                    source=text_value(data.get("source"), 500, True),
                    artifacts=artifacts,
                    missing_artifacts=missing,
                    documented_by=actor_id(),
                    documented_at=iso_now(),
                )
            result = _revise(row, payload)
    except (ValueError, TypeError, OverflowError) as exc:
        return error_response("INVALID_COLLECTION_UPDATE", str(exc), 422)
    return jsonify(result)
