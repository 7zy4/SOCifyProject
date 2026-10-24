import json

from flask import Blueprint, jsonify, request

from .autopsy_api import insert_record, manager, record_view
from .autopsy_domain import canonical, custody, text_value, touch_case
from .cases import _case_row
from .db import get_db, inserted_id, transaction
from .security import actor_id, current_user, error_response, require_permission, workspace_id
from .timeutils import iso_now

autopsy_procedures_api = Blueprint("autopsy_procedures", __name__)
PHASES = {"triage", "analysis", "containment", "eradication", "recovery", "validation", "review"}
STEP_ROLES = {"any", "l1", "l2", "investigator", "reviewer", "manager"}


def validate_steps(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 30:
        raise ValueError("يتطلب القالب من خطوة إلى 30 خطوة")
    steps = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) - {"title", "description", "phase", "role", "required", "approval_required"}:
            raise ValueError("حقول الخطوة غير معروفة")
        if (
            not isinstance(entry.get("phase", "analysis"), str)
            or not isinstance(entry.get("role", "any"), str)
            or entry.get("phase", "analysis") not in PHASES
            or entry.get("role", "any") not in STEP_ROLES
        ):
            raise ValueError("مرحلة أو دور الخطوة غير صالح")
        if type(entry.get("required", True)) is not bool or type(entry.get("approval_required", False)) is not bool:
            raise ValueError("الإلزام والموافقة يتطلبان قيمة منطقية")
        steps.append(
            {
                "title": text_value(entry.get("title"), 255, True),
                "description": text_value(entry.get("description", ""), 2000),
                "phase": entry.get("phase", "analysis"),
                "role": entry.get("role", "any"),
                "required": entry.get("required", True),
                "approval_required": entry.get("approval_required", False),
            }
        )
    return steps


@autopsy_procedures_api.get("/api/autopsy/procedures")
@require_permission("cases.read")
def templates_list():
    scope = "" if manager() else " AND state = 'published'"
    rows = (
        get_db().execute(f"SELECT * FROM autopsy_templates WHERE workspace_id = ?{scope} ORDER BY name, version DESC LIMIT 200", (workspace_id(),)).fetchall()
    )
    return jsonify({"items": [{**dict(row), "steps": json.loads(row["steps"])} for row in rows], "can_manage": manager()})


@autopsy_procedures_api.post("/api/autopsy/procedures")
@require_permission("playbooks.manage")
def template_create():
    data = request.get_json(silent=True)
    try:
        if not isinstance(data, dict) or set(data) != {"name", "steps"}:
            raise ValueError("أرسل اسم القالب وخطواته فقط")
        name, steps = text_value(data["name"], 160, True), validate_steps(data["steps"])
    except (ValueError, TypeError) as exc:
        return error_response("INVALID_PROCEDURE", str(exc), 422)
    with transaction():
        version = (
            get_db()
            .execute("SELECT COALESCE(MAX(version), 0) + 1 FROM autopsy_templates WHERE workspace_id = ? AND name = ?", (workspace_id(), name))
            .fetchone()[0]
        )
        identifier = inserted_id(
            get_db().execute(
                "INSERT INTO autopsy_templates(workspace_id, name, version, steps, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (workspace_id(), name, version, canonical(steps), actor_id(), iso_now()),
            )
        )
    return jsonify({"id": identifier, "version": version, "state": "draft"}), 201


@autopsy_procedures_api.post("/api/autopsy/procedures/<int:template_id>/publish")
@require_permission("playbooks.manage")
def template_publish(template_id: int):
    with transaction():
        row = get_db().execute("SELECT * FROM autopsy_templates WHERE id = ? AND workspace_id = ?", (template_id, workspace_id())).fetchone()
        if not row:
            return error_response("PROCEDURE_NOT_FOUND", "القالب غير متاح", 404)
        if row["state"] != "draft":
            return error_response("PROCEDURE_STATE_CONFLICT", "انشر إصدارًا جديدًا بدل تغيير المنشور", 409)
        get_db().execute(
            "UPDATE autopsy_templates SET state = 'superseded' WHERE workspace_id = ? AND name = ? AND state = 'published'", (workspace_id(), row["name"])
        )
        get_db().execute("UPDATE autopsy_templates SET state = 'published' WHERE id = ?", (template_id,))
        from .audit import record_audit

        record_audit(get_db(), "publish", "autopsy_procedure", template_id, details={"version": row["version"]})
    return jsonify({"id": template_id, "state": "published"})


@autopsy_procedures_api.post("/api/autopsy/procedures/seed")
@require_permission("playbooks.manage")
def seed_templates():
    names = [
        "مراجعة حساب مخترق",
        "التحقيق في التصيد",
        "فحص نشاط مالوير",
        "التحقيق في هجوم تطبيق ويب",
        "فحص اتصال شبكي مشبوه",
        "التحقيق في تسرب بيانات مشتبه به",
    ]
    steps = validate_steps(
        [
            {"title": "حفظ الأصل والتحقق من البصمة", "phase": "triage"},
            {"title": "ربط المؤشرات وتحديد نطاق الأثر", "phase": "analysis"},
            {"title": "توثيق قرار الاحتواء ونتيجته أو سبب عدم انطباقه", "phase": "containment", "approval_required": True},
            {"title": "التحقق من النتيجة وتوثيق التقرير", "phase": "validation"},
        ]
    )
    added = 0
    with transaction():
        for name in names:
            if not get_db().execute("SELECT 1 FROM autopsy_templates WHERE workspace_id = ? AND name = ?", (workspace_id(), name)).fetchone():
                get_db().execute(
                    "INSERT INTO autopsy_templates(workspace_id, name, version, steps, created_by, created_at) VALUES (?, ?, 1, ?, ?, ?)",
                    (workspace_id(), name, canonical(steps), actor_id(), iso_now()),
                )
                added += 1
    return jsonify({"added": added, "state": "draft", "review_required": True})


@autopsy_procedures_api.post("/api/cases/<int:case_id>/procedures")
@require_permission("playbooks.request")
def apply_template(case_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"template_id"} or type(data["template_id"]) is not int:
        return error_response("INVALID_PROCEDURE", "حدد القالب المنشور", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "القضية مغلقة", 409)
        row = (
            get_db()
            .execute("SELECT * FROM autopsy_templates WHERE id = ? AND workspace_id = ? AND state = 'published'", (data["template_id"], workspace_id()))
            .fetchone()
        )
        if not row:
            return error_response("PROCEDURE_NOT_FOUND", "القالب المنشور غير متاح", 404)
        prior = (
            get_db()
            .execute(
                "SELECT * FROM autopsy_records WHERE case_id = ? AND kind = 'playbook' AND json_extract(payload, '$.template_id') = ?", (case_id, row["id"])
            )
            .fetchone()
        )
        if prior:
            return jsonify({**record_view(prior), "duplicate": True})
        payload = {
            "template_id": row["id"],
            "template_name": row["name"],
            "template_version": row["version"],
            "execution_mode": "documentation_only",
            "steps": [{**step, "status": "pending", "evidence_id": None, "notes": ""} for step in json.loads(row["steps"])],
        }
        record_id = insert_record(case_id, "playbook", payload)
    return jsonify({"id": record_id, "version": 1, "payload": payload}), 201


@autopsy_procedures_api.patch("/api/cases/<int:case_id>/procedures/<int:record_id>/steps/<int:step_id>")
@require_permission("cases.update")
def update_step(case_id: int, record_id: int, step_id: int):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) - {"version", "status", "evidence_id", "notes"}
        or type(data.get("version")) is not int
        or not isinstance(data.get("status"), str)
        or data.get("status") not in {"pending", "in_progress", "completed", "failed", "not_applicable"}
    ):
        return error_response("INVALID_PROCEDURE_STEP", "حدد الإصدار والحالة والدليل والملاحظة", 422)
    with transaction():
        case = _case_row(case_id)
        if not case:
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if case["status"] == "closed":
            return error_response("CASE_CLOSED", "القضية مغلقة", 409)
        row = get_db().execute("SELECT * FROM autopsy_records WHERE id = ? AND case_id = ? AND kind = 'playbook'", (record_id, case_id)).fetchone()
        if not row:
            return error_response("PROCEDURE_NOT_FOUND", "إجراء القضية غير متاح", 404)
        if row["version"] != data["version"]:
            return error_response("RECORD_VERSION_CONFLICT", "تغير إجراء القضية؛ حدّث البيانات", 409)
        payload = json.loads(row["payload"])
        if not 1 <= step_id <= len(payload["steps"]):
            return error_response("STEP_NOT_FOUND", "الخطوة غير متاحة", 404)
        step = payload["steps"][step_id - 1]
        if step["status"] in {"completed", "not_applicable"} and not manager():
            return error_response("APPROVAL_REQUIRED", "إعادة فتح خطوة معتمدة تتطلب المدير", 403)
        role = {"analyst": "l1", "l1_analyst": "l1", "l2_responder": "l2", "investigator": "investigator", "reviewer": "reviewer"}.get(
            str((current_user() or {}).get("role"))
        )
        if not manager() and step["role"] not in {"any", role}:
            return error_response("PERMISSION_DENIED", "الخطوة مخصصة لدور آخر", 403)
        try:
            notes = text_value(data.get("notes", ""), 2000)
            evidence = data.get("evidence_id")
            if evidence is not None and (
                type(evidence) is not int or not get_db().execute("SELECT 1 FROM case_evidence WHERE id = ? AND case_id = ?", (evidence, case_id)).fetchone()
            ):
                raise ValueError("الدليل غير متاح في القضية")
            if data["status"] == "completed" and step["required"] and not evidence:
                raise ValueError("إكمال خطوة إلزامية يتطلب دليلًا")
            if data["status"] in {"failed", "not_applicable"} and len(notes) < 3:
                raise ValueError("سجل سبب الفشل أو عدم الانطباق")
            if data["status"] == "not_applicable" and step["required"] and not manager():
                return error_response("APPROVAL_REQUIRED", "تجاوز خطوة إلزامية يتطلب اعتماد المدير", 403)
        except ValueError as exc:
            return error_response("INVALID_PROCEDURE_STEP", str(exc), 422)
        target = "awaiting_approval" if data["status"] == "completed" and step["approval_required"] and not manager() else data["status"]
        step.update(status=target, evidence_id=evidence, notes=notes, updated_by=actor_id(), updated_at=iso_now())
        for key in ("completed_by", "completed_at", "approved_by"):
            step.pop(key, None)
        if target in {"completed", "not_applicable"}:
            step.update(completed_by=actor_id(), completed_at=iso_now(), approved_by=actor_id() if manager() else None)
        version, serialized = row["version"] + 1, canonical(payload)
        get_db().execute(
            "UPDATE autopsy_records SET payload = ?, version = ?, updated_by = ?, updated_at = ? WHERE id = ?",
            (serialized, version, actor_id(), iso_now(), record_id),
        )
        get_db().execute(
            "INSERT INTO autopsy_record_revisions(record_id, version, payload, actor_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (record_id, version, serialized, actor_id(), iso_now()),
        )
        custody(case_id, "procedure_step_updated", {"record_id": record_id, "step_id": step_id, "status": target, "version": version})
        touch_case(case_id)
    return jsonify({"id": record_id, "version": version, "payload": payload})
