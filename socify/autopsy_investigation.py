import json

from flask import Blueprint, jsonify, request

from .attack import _metadata
from .autopsy_api import records_for_case
from .autopsy_ingestion import log_query, metadata_scope
from .autopsy_pipeline import case_full_access
from .cases import _case_row, annotate_technique
from .db import get_db
from .security import error_response, require_permission
from .visualization import build_graph

autopsy_investigation_api = Blueprint("autopsy_investigation", __name__)


@autopsy_investigation_api.get("/api/cases/<int:case_id>/timeline")
@require_permission("cases.read")
def case_timeline(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"q", "severity", "start", "end", "page", "limit", "job_id"}:
            raise ValueError("مرشح غير معروف")
        page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 50))
        if not 1 <= page <= 1000000 or not 1 <= limit <= 100:
            raise ValueError("الترقيم خارج النطاق")
        where, args = log_query(case_id)
    except ValueError as exc:
        return error_response("INVALID_TIMELINE_FILTER", str(exc), 422)
    source, where, total, relation = metadata_scope(where, args)
    rows = (
        get_db()
        .execute(
            f"WITH page AS MATERIALIZED (SELECT ce.event_id,ce.time_known,ce.event_time FROM {source} WHERE {where} ORDER BY ce.time_known DESC,ce.event_time,ce.event_id LIMIT ? OFFSET ?) SELECT e.id,e.title,e.event_time,e.ingested_at,e.source,e.event_type,e.severity,e.provenance,e.normalized_fields FROM page JOIN security_events e ON e.id=page.event_id ORDER BY page.time_known DESC,page.event_time,page.event_id",
            (*args, limit + 1, (page - 1) * limit),
        )
        .fetchall()
    )
    items = []
    for row in rows[:limit]:
        normalized, provenance = json.loads(row["normalized_fields"] or "{}"), json.loads(row["provenance"] or "{}")
        known = normalized.get("event_time_known") is True
        items.append(
            {
                **{key: value for key, value in dict(row).items() if key not in {"normalized_fields", "provenance"}},
                "event_time": row["event_time"] if known else None,
                "time_basis": provenance.get("event_time_basis", "legacy_timestamp_not_verified"),
                "observed_time_known": known,
            }
        )
    return jsonify(
        {
            "items": items,
            "total": total,
            "total_relation": relation,
            "has_next": len(rows) > limit,
            "page": page,
            "limit": limit,
            "annotations": records_for_case(case_id, "timeline", 100) if case_full_access(case_id) else [],
            "bookmarks": records_for_case(case_id, "bookmark", 500) if case_full_access(case_id) else [],
            "views": records_for_case(case_id, "timeline_view", 100) if case_full_access(case_id) else [],
            "limits": "القائمة المطبعّة مرقمة؛ التعليقات والمناظر محدودة مع ترقيم مستقل في API السجلات",
        }
    )


@autopsy_investigation_api.get("/api/cases/<int:case_id>/graph")
@require_permission("cases.read")
def case_graph(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if not case_full_access(case_id):
        return error_response("BATCH_ACCESS_REQUIRED", "الرسم الكامل يحتاج نطاق القضية الكامل؛ السجلات المصرح بها متاحة في الخط الزمني", 403)
    try:
        if set(request.args) - {"limit", "severity", "start", "end"}:
            raise ValueError("مرشح الرسم غير معروف")
        limit = int(request.args.get("limit", 30))
        if not 1 <= limit <= 100:
            raise ValueError("حد الرسم من 1 إلى 100 سجل")
        return jsonify(
            {
                **build_graph(limit, case_id),
                "case_id": case_id,
                "limitations": "علاقات ملاحظة في السجلات المحددة؛ لا تثبت سببية الهجوم أو نجاحه. الرسم محدود ولا يمثل كل سجلات القضية.",
            }
        )
    except ValueError as exc:
        return error_response("INVALID_GRAPH_FILTER", str(exc), 422)


@autopsy_investigation_api.get("/api/cases/<int:case_id>/attack")
@require_permission("cases.read")
def case_attack(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    if not case_full_access(case_id):
        return error_response("BATCH_ACCESS_REQUIRED", "توثيق MITRE الكامل يحتاج نطاق القضية الكامل", 403)
    query = request.args.get("q", "").strip()
    if len(query) > 100 or set(request.args) - {"q"}:
        return error_response("INVALID_ATTACK_SEARCH", "البحث يتجاوز الحدود أو يحتوي مرشحًا غير معروف", 422)
    techniques = (
        get_db()
        .execute(
            "SELECT technique_id, name, tactic, attack_version, deprecated, revoked FROM attack_techniques WHERE technique_id LIKE ? OR name LIKE ? ORDER BY technique_id LIMIT 50",
            (f"%{query}%", f"%{query}%"),
        )
        .fetchall()
    )
    annotations = (
        get_db()
        .execute(
            "SELECT a.*, t.name FROM case_technique_annotations a LEFT JOIN attack_techniques t ON t.technique_id = a.technique_id WHERE a.case_id = ? ORDER BY a.id DESC LIMIT 200",
            (case_id,),
        )
        .fetchall()
    )
    return jsonify({"items": [dict(row) for row in techniques], "annotations": [dict(row) for row in annotations], "limit": 50, **_metadata()})


@autopsy_investigation_api.post("/api/cases/<int:case_id>/attack")
@require_permission("cases.update")
def case_attack_annotate(case_id: int):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {"technique_id", "reason", "assessment", "event_id"}:
        return error_response("INVALID_TECHNIQUE_ANNOTATION", "أرسل التقنية والحكم والسبب وسجل الدليل فقط", 422)
    return annotate_technique(case_id)
