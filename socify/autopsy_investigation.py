import json

from flask import Blueprint, jsonify, request

from .attack import _metadata
from .autopsy_api import records_for_case
from .autopsy_ingestion import log_query
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
        if set(request.args) - {"q", "severity", "start", "end", "page", "limit"}:
            raise ValueError("مرشح غير معروف")
        page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 50))
        if not 1 <= page <= 1000000 or not 1 <= limit <= 100:
            raise ValueError("الترقيم خارج النطاق")
        where, args = log_query(case_id)
    except ValueError as exc:
        return error_response("INVALID_TIMELINE_FILTER", str(exc), 422)
    total = get_db().execute(f"SELECT COUNT(*) FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE {where}", args).fetchone()[0]
    rows = (
        get_db()
        .execute(
            f"SELECT e.id, e.title, e.event_time, e.ingested_at, e.source, e.event_type, e.severity, e.provenance, e.normalized_fields FROM case_events ce JOIN security_events e ON e.id = ce.event_id WHERE {where} ORDER BY COALESCE(json_extract(e.normalized_fields, '$.event_time_known'), 0) DESC, e.event_time, e.id LIMIT ? OFFSET ?",
            (*args, limit, (page - 1) * limit),
        )
        .fetchall()
    )
    items = []
    for row in rows:
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
            "page": page,
            "limit": limit,
            "annotations": records_for_case(case_id, "timeline", 100),
            "bookmarks": records_for_case(case_id, "bookmark", 500),
            "views": records_for_case(case_id, "timeline_view", 100),
            "limits": "القائمة المطبعّة مرقمة؛ التعليقات والمناظر محدودة مع ترقيم مستقل في API السجلات",
        }
    )


@autopsy_investigation_api.get("/api/cases/<int:case_id>/graph")
@require_permission("cases.read")
def case_graph(case_id: int):
    if not _case_row(case_id):
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
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
