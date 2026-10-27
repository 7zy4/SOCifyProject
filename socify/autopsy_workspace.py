"""Case authorization, manager review and explicit investigation selection."""

from flask import Blueprint, current_app, jsonify, request, session

from .audit import record_audit
from .db import get_db, transaction
from .security import actor_id, current_user, error_response, has_permission, require_permission, workspace_id
from .timeutils import iso_now

autopsy_workspace_api = Blueprint("autopsy_workspace", __name__)


def migrate(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS case_approvals (
        case_id INTEGER PRIMARY KEY REFERENCES incident_cases(id),
        state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected')),
        version INTEGER NOT NULL DEFAULT 1, requested_by INTEGER REFERENCES users(id),
        reviewed_by INTEGER REFERENCES users(id), reviewed_at TEXT, reason TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'v4_request')""")
    connection.execute("""CREATE TABLE IF NOT EXISTS case_relationships (
        first_id INTEGER NOT NULL REFERENCES incident_cases(id), second_id INTEGER NOT NULL REFERENCES incident_cases(id),
        reason TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
        PRIMARY KEY(first_id,second_id), CHECK(first_id < second_id))""")
    connection.execute("""CREATE TABLE IF NOT EXISTS demo_accounts (
        user_id INTEGER PRIMARY KEY REFERENCES users(id))""")
    # Only rows present during migration are grandfathered. Every subsequent create records a pending request.
    if not connection.execute("SELECT 1 FROM schema_meta WHERE key='v4_case_approval_migrated'").fetchone():
        connection.execute("""INSERT OR IGNORE INTO case_approvals(case_id,state,requested_by,source,reason)
            SELECT id,'approved',creator,'v3_migration','Retained V3 case access' FROM incident_cases""")
        connection.execute("INSERT INTO schema_meta(key,value,updated_at) VALUES ('v4_case_approval_migrated','1',?)", (iso_now(),))


def approval(case_id):
    row = get_db().execute("SELECT * FROM case_approvals WHERE case_id=?", (case_id,)).fetchone()
    return dict(row) if row else {"case_id": case_id, "state": "pending", "version": 1, "source": "missing_review"}


def case_approved(case_id):
    return not current_app.config["REQUIRE_CASE_APPROVAL"] or approval(case_id)["state"] == "approved"


def can_review():
    return (current_user() or {}).get("role") in {"soc_manager", "admin"} and has_permission(current_user(), "cases.override")


def selected_ids():
    from .operational import case_visible

    identifiers = session.get("investigation_cases", [])
    user = current_user()
    if not user or not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 2:
        return []
    if any(type(value) is not int or not 1 <= value <= 9223372036854775807 or not case_visible(value, user) or not case_approved(value) for value in identifiers):
        session.pop("investigation_cases", None)
        return []
    if len(identifiers) == 2 and not related(*identifiers):
        session.pop("investigation_cases", None)
        return []
    return identifiers


def related(first, second):
    return get_db().execute("SELECT 1 FROM case_relationships WHERE first_id=? AND second_id=?", tuple(sorted((first, second)))).fetchone() is not None


def selection_scope_sql(alias="c"):
    if not current_app.config["REQUIRE_INVESTIGATION_SELECTION"]:
        return "", []
    identifiers = selected_ids()
    return f" AND {alias}.id IN (" + (",".join("?" for _ in identifiers) or "NULL") + ")", identifiers


def guard_workspace():
    from .cases import _case_row

    case_id = (request.view_args or {}).get("case_id")
    if request.endpoint == "teams.assign_logs":
        data = request.get_json(silent=True)
        candidate = data.get("case_id") if isinstance(data, dict) else None
        if type(candidate) is int and 1 <= candidate <= 9223372036854775807:
            case_id = candidate
    elif request.endpoint == "teams.update_assignment":
        row = get_db().execute("SELECT case_id FROM team_log_assignments WHERE id=? AND workspace_id=?", ((request.view_args or {})["assignment_id"], workspace_id())).fetchone()
        if row:
            case_id = row["case_id"]
    if not case_id or not current_user() or not _case_row(case_id):
        return None
    if request.blueprint == "ui":
        return None
    if request.endpoint in {"autopsy.case_get", "cases.case_detail"} and request.method == "GET":
        return None
    if request.blueprint == "autopsy_workspace":
        return None
    if not case_approved(case_id):
        return error_response("CASE_APPROVAL_REQUIRED", "بانتظار اعتماد المدير؛ أعمال القضية مقفلة", 409)
    if current_app.config["REQUIRE_INVESTIGATION_SELECTION"] and case_id not in selected_ids():
        return error_response("CASE_SELECTION_REQUIRED", "اختر هذه القضية من صفحة القضايا قبل استخدام أدواتها", 403)
    return None


@autopsy_workspace_api.get("/api/investigation-selection")
@require_permission("cases.read")
def selection_get():
    ids = selected_ids()
    rows = [dict(get_db().execute("SELECT id,reference,title FROM incident_cases WHERE id=?", (value,)).fetchone()) for value in ids]
    return jsonify({"case_ids": ids, "items": rows, "required": current_app.config["REQUIRE_INVESTIGATION_SELECTION"]})


@autopsy_workspace_api.post("/api/investigation-selection")
@require_permission("cases.read")
def selection_set():
    from .cases import _case_row

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"case_ids"}:
        return error_response("INVALID_SELECTION", "حدد قائمة القضايا فقط", 422)
    ids = data["case_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 2 or any(type(value) is not int or not 1 <= value <= 9223372036854775807 for value in ids) or len(set(ids)) != len(ids):
        return error_response("INVALID_SELECTION", "اختر قضية واحدة أو قضيتين مرتبطتين فقط", 422)
    if any(not _case_row(value) for value in ids):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if any(not case_approved(value) for value in ids):
        return error_response("CASE_APPROVAL_REQUIRED", "اختر قضايا معتمدة فقط", 409)
    if len(ids) == 2 and not related(*ids):
        return error_response("CASES_NOT_RELATED", "يجب أن يعتمد المدير علاقة القضيتين أولًا", 422)
    session["investigation_cases"] = ids
    record_audit(get_db(), "selection_changed", "investigation", ids[0], details={"case_ids": ids})
    return selection_get()


@autopsy_workspace_api.post("/api/cases/<int:case_id>/approval")
@require_permission("cases.override")
def review_case(case_id):
    from .autopsy_domain import custody, text_value
    from .cases import _case_row, _history

    if not can_review():
        return error_response("PERMISSION_DENIED", "اعتماد القضية مخصص للمدير", 403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"decision", "version", "reason"} or not isinstance(data.get("decision"), str) or data["decision"] not in {"approved", "rejected"}:
        return error_response("INVALID_REVIEW", "حدد قرار الاعتماد وإصداره وسببه", 422)
    if type(data["version"]) is not int or not isinstance(data["reason"], str) or not 3 <= len(data["reason"].strip()) <= 1000:
        return error_response("INVALID_REVIEW", "سبب القرار مطلوب مع إصدار صحيح", 422)
    try:
        data["reason"] = text_value(data["reason"], 1000, True)
    except ValueError as exc:
        return error_response("INVALID_REVIEW", str(exc), 422)
    with transaction():
        if not _case_row(case_id):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        row = approval(case_id)
        if row["source"] == "missing_review" or row["state"] != "pending" or row["version"] != data["version"]:
            return error_response("REVIEW_CONFLICT", "سبق اتخاذ القرار أو تغير إصدار الطلب", 409)
        get_db().execute("UPDATE case_approvals SET state=?,version=version+1,reviewed_by=?,reviewed_at=?,reason=? WHERE case_id=? AND version=?", (data["decision"], actor_id(), iso_now(), data["reason"].strip(), case_id, data["version"]))
        _history(get_db(), case_id, "case_" + data["decision"], "pending", data["decision"], data["reason"].strip())
        custody(case_id, "case_" + data["decision"], {"reason": data["reason"].strip()})
        record_audit(get_db(), "review", "case", case_id, details={"decision": data["decision"]})
    return jsonify(approval(case_id))


@autopsy_workspace_api.post("/api/cases/<int:case_id>/relationships")
@require_permission("cases.override")
def link_cases(case_id):
    from .autopsy_domain import text_value
    from .cases import _case_row

    if not can_review():
        return error_response("PERMISSION_DENIED", "ربط القضايا مخصص للمدير", 403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"related_case_id", "reason"} or type(data.get("related_case_id")) is not int:
        return error_response("INVALID_RELATIONSHIP", "حدد القضية المرتبطة والسبب", 422)
    target = data["related_case_id"]
    if target == case_id or not 1 <= target <= 9223372036854775807 or not isinstance(data["reason"], str) or not 3 <= len(data["reason"].strip()) <= 1000:
        return error_response("INVALID_RELATIONSHIP", "علاقة القضية أو سببها غير صالح", 422)
    try:
        data["reason"] = text_value(data["reason"], 1000, True)
    except ValueError as exc:
        return error_response("INVALID_RELATIONSHIP", str(exc), 422)
    with transaction():
        if not _case_row(case_id) or not _case_row(target):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if not case_approved(case_id) or not case_approved(target):
            return error_response("CASE_APPROVAL_REQUIRED", "اعتمد القضيتين قبل الربط", 409)
        get_db().execute("INSERT OR IGNORE INTO case_relationships(first_id,second_id,reason,created_by,created_at) VALUES (?,?,?,?,?)", (*sorted((case_id, target)), data["reason"].strip(), actor_id(), iso_now()))
        record_audit(get_db(), "case_linked", "case", case_id, details={"related_case_id": target, "reason": data["reason"].strip()})
    return jsonify({"linked": True})


def demo_enabled():
    return current_app.config["DEMO_MODE"] and current_app.config["ENV_NAME"] == "development"


@autopsy_workspace_api.get("/api/demo/accounts")
@require_permission("cases.read")
def demo_accounts():
    if not demo_enabled() or not get_db().execute("SELECT 1 FROM demo_accounts WHERE user_id=?", (actor_id(),)).fetchone():
        return jsonify({"enabled": False, "items": []})
    rows = get_db().execute("SELECT u.id,u.name,u.role FROM users u JOIN demo_accounts d ON d.user_id=u.id WHERE u.workspace_id=? AND u.is_active=1 ORDER BY u.id", (workspace_id(),))
    return jsonify({"enabled": True, "items": [dict(row) for row in rows]})


@autopsy_workspace_api.post("/api/demo/switch")
@require_permission("cases.read")
def demo_switch():
    import hashlib

    from .auth import _start_session

    if not demo_enabled() or not get_db().execute("SELECT 1 FROM demo_accounts WHERE user_id=?", (actor_id(),)).fetchone():
        return error_response("DEMO_DISABLED", "تبديل حساب التجربة غير متاح", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"user_id"} or type(data["user_id"]) is not int or not 1 <= data["user_id"] <= 9223372036854775807:
        return error_response("INVALID_ACCOUNT", "حدد حساب تجربة صالح", 422)
    with transaction():
        user = get_db().execute("SELECT u.* FROM users u JOIN demo_accounts d ON d.user_id=u.id WHERE u.id=? AND u.workspace_id=? AND u.is_active=1 AND NOT EXISTS(SELECT 1 FROM mfa_enrollments m WHERE m.user_id=u.id AND m.enabled=1)", (data["user_id"], workspace_id())).fetchone()
        if not user:
            return error_response("ACCOUNT_UNAVAILABLE", "حساب التجربة غير متاح", 404)
        record_audit(get_db(), "demo_account_switch", "auth", data["user_id"])
        raw = session.get("session_id")
        if raw:
            get_db().execute("UPDATE auth_sessions SET revoked_at=? WHERE session_hash=?", (iso_now(), hashlib.sha256(raw.encode()).hexdigest()))
        result = _start_session(user)
    return jsonify(result)
