import hashlib
import json
import re
from datetime import timedelta

from flask import Blueprint, jsonify, request

from .audit import record_audit
from .autopsy_domain import canonical, custody, text_value, touch_case
from .cases import _case_row
from .db import get_db, inserted_id, transaction
from .detection import evaluate_rules
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .sigma_subset import CAPABILITIES, compile_sigma, validate_fixtures
from .timeutils import iso_now, iso_timestamp, parse_timestamp, utc_now
from .validation import ValidationError, public_error_message

autopsy_detection_api = Blueprint("autopsy_detection", __name__)


def migrate(connection):
    connection.execute(
        "CREATE TABLE IF NOT EXISTS sigma_publication_receipts(workspace_id INTEGER NOT NULL REFERENCES training_workspaces(id), actor_id INTEGER NOT NULL REFERENCES users(id), request_key TEXT NOT NULL, request_hash TEXT NOT NULL, response TEXT NOT NULL CHECK(json_valid(response)), created_at TEXT NOT NULL, PRIMARY KEY(workspace_id,actor_id,request_key))"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS autopsy_sigma_sources(rule_id INTEGER NOT NULL REFERENCES rules(id), version INTEGER NOT NULL, source TEXT NOT NULL, sha256 TEXT NOT NULL, compiler TEXT NOT NULL, fixtures TEXT NOT NULL, PRIMARY KEY(rule_id,version))"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS autopsy_alert_reviews(alert_id INTEGER PRIMARY KEY REFERENCES alerts(id), case_id INTEGER NOT NULL REFERENCES incident_cases(id), version INTEGER NOT NULL DEFAULT 1, payload TEXT NOT NULL CHECK(json_valid(payload)), changed_by INTEGER NOT NULL, changed_at TEXT NOT NULL)"
    )
    for action in ("UPDATE", "DELETE"):
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS autopsy_sigma_immutable_{action.lower()} BEFORE {action} ON autopsy_sigma_sources BEGIN SELECT RAISE(ABORT, 'Sigma source versions are immutable'); END"
        )


@autopsy_detection_api.get("/api/autopsy/detection/builtin-rules")
@require_permission("cases.read")
def builtin_rules_list():
    from .builtin_rules import seed_builtin_rules

    seed_builtin_rules(get_db())
    rows = (
        get_db()
        .execute(
            "SELECT id, name, description, version, is_active, deployment_state, action_value, match_count, last_triggered_at FROM rules WHERE workspace_id = ? AND archived_at IS NULL AND name LIKE '[SOCify]%' ORDER BY id",
            (workspace_id(),),
        )
        .fetchall()
    )
    items = [{**dict(row), "action": json.loads(row["action_value"] or "{}")} for row in rows]
    return jsonify({"items": items, "total": len(items)})


@autopsy_detection_api.get("/api/autopsy/detection/capabilities")
@require_permission("cases.read")
def detection_capabilities():
    return jsonify(
        {
            "sigma": CAPABILITIES,
            "scan_batch": 1000,
            "anomaly": "rare source_ip/hostname pairs compared with preceding case events; minimum 20 baseline events",
            "network": "offline-only",
        }
    )


@autopsy_detection_api.get("/api/autopsy/sigma/rules")
@require_permission("rules.manage")
def sigma_rules():
    found = (
        get_db()
        .execute(
            "SELECT r.id,r.name,r.description,r.version,r.is_active,r.deployment_state,s.source,s.sha256,s.compiler,s.fixtures FROM rules r JOIN autopsy_sigma_sources s ON s.rule_id=r.id AND s.version=r.version WHERE r.workspace_id=? ORDER BY r.id DESC LIMIT 100",
            (workspace_id(),),
        )
        .fetchall()
    )
    return jsonify({"items": [{**dict(row), "fixtures": json.loads(row["fixtures"])} for row in found], "capabilities": CAPABILITIES})


@autopsy_detection_api.post("/api/autopsy/sigma/<action>")
@require_permission("rules.manage")
def sigma_action(action):
    if action not in {"compile", "publish"}:
        return error_response("SIGMA_ACTION_NOT_FOUND", "إجراء Sigma غير متاح", 404)
    data = request.get_json(silent=True)
    request_key = request.headers.get("Idempotency-Key") if action == "publish" else None
    try:
        if not isinstance(data, dict) or set(data) - {"source", "fixtures", "rule_id", "version", "reason"}:
            raise ValidationError("حقول Sigma غير معروفة")
        if request_key is not None and not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", request_key):
            raise ValidationError("معرف إعادة المحاولة غير صالح")
        request_hash = hashlib.sha256(canonical(data).encode()).hexdigest()
        if request_key is not None:
            receipt = _sigma_receipt(request_key, request_hash)
            if receipt is not None:
                return receipt
        compiled = compile_sigma(data.get("source"))
        validate_fixtures(compiled, data.get("fixtures"))
        if any(
            not get_db().execute("SELECT 1 FROM attack_techniques WHERE technique_id=?", (technique,)).fetchone() for technique in compiled["dsl"]["mitre_ids"]
        ):
            raise ValidationError("تقنية MITRE غير موجودة في الكتالوج المحلي")
        if action == "compile":
            return jsonify({"compiled": compiled, "fixtures_passed": True, "published": False})
        reason = text_value(data.get("reason"), 1000, True)
        rule_id = data.get("rule_id")
        if rule_id is not None and (type(rule_id) is not int or not 1 <= rule_id <= 2**63 - 1 or type(data.get("version")) is not int):
            raise ValidationError("معرف القاعدة وإصدارها غير صالحين")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        return error_response("INVALID_SIGMA_SUBSET", public_error_message(exc, "قاعدة الكشف غير صالحة"), 422)
    with transaction():
        # Repeat after acquiring the write lock: concurrent retries must share one commit.
        if request_key is not None:
            receipt = _sigma_receipt(request_key, request_hash)
            if receipt is not None:
                return receipt
        dsl, now = canonical(compiled["dsl"]), iso_now()
        alert_action = canonical({"severity": compiled["level"], "confidence": 0.5})
        if rule_id is None:
            if get_db().execute("SELECT COUNT(*) FROM rules WHERE workspace_id=? AND is_active=1", (workspace_id(),)).fetchone()[0] >= 100:
                return error_response("RULE_CAPACITY", "حد النشر المحلي 100 قاعدة فعالة", 409)
            version = 1
            rule_id = inserted_id(
                get_db().execute(
                    "INSERT INTO rules(name,description,condition_type,condition_value,dsl_json,action_type,action_value,is_active,version,deployment_state,workspace_id,created_by,deployed_by,created_at,updated_at) VALUES (?,?,'dsl',?,?,'create_alert',?,1,1,'published',?,?,?,?,?)",
                    (compiled["title"], compiled["description"], dsl, dsl, alert_action, workspace_id(), actor_id(), actor_id(), now, now),
                )
            )
        else:
            row = (
                get_db()
                .execute(
                    "SELECT r.* FROM rules r WHERE r.id=? AND r.workspace_id=? AND EXISTS (SELECT 1 FROM autopsy_sigma_sources s WHERE s.rule_id=r.id)",
                    (rule_id, workspace_id()),
                )
                .fetchone()
            )
            if not row:
                return error_response("RULE_NOT_FOUND", "القاعدة غير متاحة", 404)
            if row["version"] != data["version"]:
                return error_response("RULE_VERSION_CONFLICT", "تغيرت القاعدة قبل النشر", 409)
            version = row["version"] + 1
            get_db().execute(
                "UPDATE rules SET name=?,description=?,condition_value=?,dsl_json=?,action_value=?,version=?,is_active=1,deployment_state='published',deployed_by=?,updated_at=? WHERE id=?",
                (compiled["title"], compiled["description"], dsl, dsl, alert_action, version, actor_id(), now, rule_id),
            )
        get_db().execute(
            "INSERT INTO rule_versions(rule_id,version,dsl_json,action_json,change_summary,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
            (rule_id, version, dsl, alert_action, reason, actor_id(), now),
        )
        get_db().execute(
            "INSERT INTO autopsy_sigma_sources(rule_id,version,source,sha256,compiler,fixtures) VALUES (?,?,?,?,?,?)",
            (rule_id, version, data["source"], compiled["source_sha256"], compiled["compiler"], canonical(data["fixtures"])),
        )
        record_audit(
            get_db(),
            "publish",
            "sigma_rule",
            rule_id,
            details={"version": version, "sha256": compiled["source_sha256"], "compiler": compiled["compiler"], "reason": reason},
        )
        result = {"id": rule_id, "version": version, "fixtures_passed": True, "compiled": compiled}
        if request_key is not None:
            get_db().execute(
                "INSERT INTO sigma_publication_receipts(workspace_id,actor_id,request_key,request_hash,response,created_at) VALUES (?,?,?,?,?,?)",
                (workspace_id(), actor_id(), request_key, request_hash, canonical(result), now),
            )
    return jsonify(result), 201


def _sigma_receipt(request_key, request_hash):
    receipt = (
        get_db()
        .execute(
            "SELECT request_hash,response FROM sigma_publication_receipts WHERE workspace_id=? AND actor_id=? AND request_key=?",
            (workspace_id(), actor_id(), request_key),
        )
        .fetchone()
    )
    if receipt is None:
        return None
    if receipt["request_hash"] != request_hash:
        return error_response("RULE_REQUEST_CONFLICT", "تغير محتوى الطلب؛ أعد المحاولة كعملية جديدة", 409)
    return jsonify(json.loads(receipt["response"])), 201


def detection_job_view(job, case):
    from .autopsy_api import manager

    parameters = json.loads(job["parameters"])
    result = {
        key: job[key] for key in ("id", "kind", "state", "error_code", "attempts", "created_by", "created_at", "started_at", "completed_at", "available_at")
    }
    control = job["created_by"] == actor_id() or manager()
    result.update(
        mode=parameters["mode"],
        result_record_id=json.loads(job["result"] or "{}").get("record_id"),
        can_cancel=control and job["state"] in {"queued", "processing"},
        can_retry=control
        and job["state"] in {"cancelled", "failed"}
        and job["attempts"] < 3
        and case["status"] != "closed"
        and has_permission(current_user(), "cases.update")
        and case["version"] == parameters["case_version"],
        scope_changed=case["version"] != parameters["case_version"] and job["state"] != "completed",
    )
    return result


@autopsy_detection_api.get("/api/cases/<int:case_id>/detection")
@require_permission("cases.read")
def list_detection_jobs(case_id):
    case = _case_row(case_id)
    if not case:
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        page = int(request.args.get("page", 1))
        if set(request.args) - {"page"} or not 1 <= page <= 1000000:
            raise ValueError
    except ValueError:
        return error_response("INVALID_DETECTION_PAGE", "صفحة الفحوص خارج النطاق", 422)
    rows = (
        get_db()
        .execute("SELECT * FROM autopsy_jobs WHERE case_id=? AND kind='detection' ORDER BY id DESC LIMIT 26 OFFSET ?", (case_id, (page - 1) * 25))
        .fetchall()
    )
    return jsonify({"items": [detection_job_view(row, case) for row in rows[:25]], "page": page, "has_next": len(rows) > 25})


@autopsy_detection_api.post("/api/cases/<int:case_id>/detection")
@require_permission("cases.update")
def queue_detection(case_id):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) - {"version", "mode", "after_id"}
        or type(data.get("version")) is not int
        or data.get("mode") not in ("rules", "anomaly")
        or type(data.get("after_id", 0)) is not int
        or not 0 <= data.get("after_id", 0) <= 2**63 - 1
    ):
        return error_response("INVALID_DETECTION_SCAN", "حدد إصدار القضية ونوع التحليل ومؤشر الاستكمال", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["version"] != data["version"] or case["status"] == "closed":
            return error_response("CASE_VERSION_CONFLICT", "حدّث إصدار القضية أو أعد فتحها قبل التحليل", 409)
        if (
            get_db()
            .execute(
                "SELECT COUNT(*) FROM autopsy_jobs j JOIN incident_cases c ON c.id=j.case_id WHERE c.workspace_id=? AND j.state IN ('queued','processing')",
                (workspace_id(),),
            )
            .fetchone()[0]
            >= 20
        ):
            return error_response("JOB_QUEUE_FULL", "طابور التحليل ممتلئ", 429)
        ceiling = get_db().execute("SELECT COALESCE(MAX(id),0) FROM security_events WHERE owner_case_id=? AND autopsy_active=1", (case_id,)).fetchone()[0]
        parameters = {"mode": data["mode"], "after_id": data.get("after_id", 0), "through_id": ceiling, "case_version": case["version"]}
        identifier = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_jobs(case_id,kind,parameters,created_by,created_at) VALUES (?,'detection',?,?,?)",
                (case_id, canonical(parameters), actor_id(), iso_now()),
            )
        )
    return jsonify({"id": identifier, "state": "queued", "batch_limit": 1000}), 202


def run_detection_job(job):
    from .autopsy_worker import job_authorized

    parameters = json.loads(job["parameters"])
    with transaction():
        case = get_db().execute("SELECT * FROM incident_cases WHERE id=?", (job["case_id"],)).fetchone()
        if not job_authorized(job) or case["status"] == "closed" or case["version"] != parameters["case_version"]:
            raise PermissionError("Detection scope changed before execution")
        events = (
            get_db()
            .execute(
                "SELECT id,source_ip,hostname FROM security_events WHERE owner_case_id=? AND autopsy_active=1 AND source!='rules_engine' AND id>? AND id<=? ORDER BY id LIMIT 1001",
                (job["case_id"], parameters["after_id"], parameters["through_id"]),
            )
            .fetchall()
        )
        batch, alerts, findings = events[:1000], [], []
        baseline = []
        if parameters["mode"] == "rules":
            from .content_inspection import inspect_event_fields

            for event in batch:
                retained = get_db().execute("SELECT raw_data,normalized_fields,description FROM security_events WHERE id=?", (event["id"],)).fetchone()
                fields = inspect_event_fields(retained["raw_data"], json.loads(retained["normalized_fields"]), retained["description"])
                get_db().execute("UPDATE security_events SET normalized_fields=? WHERE id=?", (canonical(fields), event["id"]))
                alerts.extend(evaluate_rules(get_db(), event["id"]))
            for alert_id in alerts:
                get_db().execute(
                    "INSERT OR IGNORE INTO case_alerts(case_id,alert_id,attached_by,attached_at) VALUES (?,?,?,?)",
                    (job["case_id"], alert_id, job["created_by"], iso_now()),
                )
        elif batch:
            baseline = (
                get_db()
                .execute(
                    "SELECT id,source_ip,hostname FROM security_events WHERE owner_case_id=? AND autopsy_active=1 AND source!='rules_engine' AND id<? AND source_ip IS NOT NULL AND hostname IS NOT NULL ORDER BY id DESC LIMIT 10000",
                    (job["case_id"], batch[0]["id"]),
                )
                .fetchall()
            )
            pairs = {(row["source_ip"], row["hostname"]) for row in baseline}
            if len(baseline) >= 20:
                findings = [
                    {
                        "event_id": event["id"],
                        "source_ip": event["source_ip"],
                        "hostname": event["hostname"],
                        "reason": "pair absent from preceding bounded case baseline",
                        "baseline_occurrences": 0,
                    }
                    for event in batch
                    if event["source_ip"] and event["hostname"] and (event["source_ip"], event["hostname"]) not in pairs
                ][:100]
    return {
        "analysis_type": "local_detection",
        "engine": "SOCify bounded local detection/1",
        "mode": parameters["mode"],
        "evaluated_events": len(batch),
        "after_id": parameters["after_id"],
        "through_id": parameters["through_id"],
        "next_after_id": batch[-1]["id"] if len(events) > 1000 else None,
        "alert_ids": alerts,
        "findings": findings,
        "baseline_events": len(baseline),
        "baseline_version": hashlib.sha256(canonical([dict(row) for row in baseline]).encode()).hexdigest(),
        "baseline_scope": {
            "case_version": parameters["case_version"],
            "before_event_id": batch[0]["id"] if batch else None,
            "limit": 10000,
            "order": "id_desc",
            "first_id": baseline[-1]["id"] if baseline else None,
            "last_id": baseline[0]["id"] if baseline else None,
        },
        "status": "insufficient_baseline" if parameters["mode"] == "anomaly" and len(baseline) < 20 else "evaluated",
        "limitations": "النطاق هو النسخ المشتقة الفعالة فقط. الشذوذ مقارنة بترتيب السجلات المستوردة وليس إثباتًا زمنيًا للهجوم أو حكمًا خبيثًا. نتائج الشذوذ محدودة بأول 100 finding؛ القواعد ضمن Sigma subset المعلن فقط.",
    }


@autopsy_detection_api.get("/api/cases/<int:case_id>/alerts")
@require_permission("cases.read")
def case_alerts(case_id):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        page = int(request.args.get("page", 1))
        if not 1 <= page <= 1000000 or set(request.args) - {"page"}:
            raise ValueError
    except ValueError:
        return error_response("INVALID_PAGE", "الصفحة غير صالحة", 422)
    found = (
        get_db()
        .execute(
            "SELECT a.*,r.payload AS review,r.version AS review_version FROM alerts a LEFT JOIN autopsy_alert_reviews r ON r.alert_id=a.id WHERE a.owner_case_id=? ORDER BY a.id DESC LIMIT 100 OFFSET ?",
            (case_id, (page - 1) * 100),
        )
        .fetchall()
    )
    items = []
    for row in found:
        item = dict(row)
        entity = (
            get_db()
            .execute(
                "SELECT e.source_ip,e.hostname FROM alert_events ae JOIN security_events e ON e.id=ae.event_id WHERE ae.alert_id=? AND e.owner_case_id=? ORDER BY e.id LIMIT 1",
                (row["id"], case_id),
            )
            .fetchone()
        )
        basis = {"rule_id": row["rule_id"], "rule_version": row["rule_version"], "first_evidence_entity": dict(entity) if entity else None}
        automatic_group = "auto-" + hashlib.sha256(canonical(basis).encode()).hexdigest()[:20]
        item["group_basis"] = basis
        item["group_source"] = "manual_review" if row["review"] else "automatic_first_evidence_entity"
        item["review"] = (
            json.loads(row["review"])
            if row["review"]
            else {"verdict": "undetermined", "attack_outcome": "unknown", "group": automatic_group, "suppressed_until": None}
        )
        item["review_version"] = row["review_version"] or 0
        item["evidence"] = json.loads(row["evidence"] or "{}")
        item["trace"] = json.loads(row["trace"] or "{}")
        item["historical_derivation"] = not bool(
            get_db()
            .execute("SELECT 1 FROM alert_events ae JOIN security_events e ON e.id=ae.event_id WHERE ae.alert_id=? AND e.autopsy_active=1", (row["id"],))
            .fetchone()
        )
        until = item["review"].get("suppressed_until")
        item["suppressed"] = bool(until and parse_timestamp(until) > utc_now())
        items.append(item)
    return jsonify(
        {
            "items": items,
            "page": page,
            "total": get_db().execute("SELECT COUNT(*) FROM alerts WHERE owner_case_id=?", (case_id,)).fetchone()[0],
            "policy": "grouping and suppression are review metadata; all original alerts and their evidence remain visible",
        }
    )


@autopsy_detection_api.patch("/api/cases/<int:case_id>/alerts/<int:alert_id>")
@require_permission("cases.update")
def review_alert(case_id, alert_id):
    data = request.get_json(silent=True)
    try:
        if (
            not isinstance(data, dict)
            or set(data) != {"version", "verdict", "attack_outcome", "group", "suppressed_until", "reason"}
            or type(data["version"]) is not int
        ):
            raise ValidationError("حدد إصدار المراجعة وقرار التنبيه ونتيجة الهجوم والمجموعة وسبب التغيير")
        verdict = text_value(data["verdict"], 30, True)
        outcome = text_value(data["attack_outcome"], 30, True)
        if verdict not in {"undetermined", "malicious", "benign", "false_positive"} or outcome not in {"unknown", "successful", "blocked", "partial"}:
            raise ValidationError("قرار التنبيه أو نتيجة الهجوم غير صالحة")
        group, reason = text_value(data["group"], 100), text_value(data["reason"], 2000, True)
        until = data["suppressed_until"]
        if until is not None:
            if not isinstance(until, str) or not until.endswith("Z"):
                raise ValidationError("نهاية suppression تتطلب UTC")
            until = iso_timestamp(until)
            if not utc_now() < parse_timestamp(until) <= utc_now() + timedelta(days=30):
                raise ValidationError("مدة suppression من الآن وحتى 30 يومًا")
    except (ValueError, TypeError, UnicodeError) as exc:
        return error_response("INVALID_ALERT_REVIEW", public_error_message(exc, "مراجعة التنبيه غير صالحة"), 422)
    with transaction():
        case = _case_row(case_id)
        row = (
            get_db()
            .execute(
                "SELECT a.id,COALESCE(r.version,0) AS version FROM alerts a LEFT JOIN autopsy_alert_reviews r ON r.alert_id=a.id WHERE a.id=? AND a.owner_case_id=?",
                (alert_id, case_id),
            )
            .fetchone()
        )
        if not case or not row:
            return error_response("ALERT_NOT_FOUND", "التنبيه غير متاح", 404)
        if case["status"] == "closed" or row["version"] != data["version"]:
            return error_response("ALERT_VERSION_CONFLICT", "تغيرت المراجعة أو أغلقت القضية", 409)
        payload = {"verdict": verdict, "attack_outcome": outcome, "group": group, "suppressed_until": until, "reason": reason}
        version = row["version"] + 1
        get_db().execute(
            "INSERT INTO autopsy_alert_reviews(alert_id,case_id,version,payload,changed_by,changed_at) VALUES (?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET version=excluded.version,payload=excluded.payload,changed_by=excluded.changed_by,changed_at=excluded.changed_at",
            (alert_id, case_id, version, canonical(payload), actor_id(), iso_now()),
        )
        custody(
            case_id,
            "alert_reviewed",
            {"alert_id": alert_id, "version": version, "review": payload, "sha256": hashlib.sha256(canonical(payload).encode()).hexdigest()},
        )
        touch_case(case_id)
    return jsonify({"id": alert_id, "version": version, "review": payload})
