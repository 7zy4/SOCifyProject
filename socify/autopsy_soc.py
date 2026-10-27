from flask import Blueprint, current_app, jsonify, request

from .autopsy_pipeline import full_case_scope_sql
from .case_counts import consistent_read
from .db import get_db
from .operational import case_scope
from .security import current_user, error_response, require_permission, training_scope_sql, workspace_id
from .timeutils import iso_now

autopsy_soc_api = Blueprint("autopsy_soc", __name__)
CHANNEL = "CASE WHEN c.status IN ('closed','cancelled') THEN 'closed' WHEN c.status IN ('new','open','triaged') THEN 'main' ELSE 'investigation' END"


@autopsy_soc_api.get("/api/soc/monitoring")
@require_permission("cases.read")
@consistent_read
def monitoring():
    try:
        allowed = {"channel", "page", "page_size", "q", "severity", "mine", "sort", "direction"}
        if set(request.args) - allowed or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ValueError
        channel = request.args.get("channel", "main")
        page, size = int(request.args.get("page", 1)), int(request.args.get("page_size", 25))
        query, severity = request.args.get("q", "").strip(), request.args.get("severity", "")
        mine, direction = request.args.get("mine", "0"), request.args.get("direction", "desc")
        sort = request.args.get("sort", "detected_at")
        sorts = {
            "detected_at": "a.detected_at",
            "severity": "CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END",
            "rule_name": "r.name",
        }
        if channel not in {"main", "investigation", "closed"} or not 1 <= page <= 1000000 or not 1 <= size <= 50:
            raise ValueError
        if len(query) > 200 or severity not in {"", "critical", "high", "medium", "low"} or mine not in {"0", "1"}:
            raise ValueError
        if sort not in sorts or direction not in {"asc", "desc"}:
            raise ValueError
    except ValueError:
        return error_response("INVALID_MONITORING_FILTER", "تحقق من مرشحات المراقبة وقيم الترقيم", 422)
    user = current_user() or {}
    where = "c.workspace_id=? AND a.workspace_id=c.workspace_id AND c.archived_at IS NULL"
    args: list[object] = [workspace_id()]
    if current_app.config["REQUIRE_INVESTIGATION_SELECTION"]:
        from .autopsy_workspace import selected_ids

        ids = selected_ids()
        where += " AND c.id IN (" + (",".join("?" for _ in ids) or "NULL") + ")"
        args.extend(ids)
    if current_app.config["REQUIRE_CASE_APPROVAL"]:
        where += " AND EXISTS(SELECT 1 FROM case_approvals ap WHERE ap.case_id=c.id AND ap.state='approved')"
    for clause, parameters in (case_scope(user), full_case_scope_sql(user), training_scope_sql("c.training_run_id")):
        where += clause
        args.extend(parameters)
    if query:
        where += " AND (a.alert_id LIKE ? ESCAPE '\\' OR r.name LIKE ? ESCAPE '\\' OR c.reference LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\')"
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args.extend([like] * 4)
    if severity:
        where += " AND a.severity=?"
        args.append(severity)
    if mine == "1":
        where += " AND c.assignee=?"
        args.append(user["id"])
    source = "alerts a JOIN incident_cases c ON c.id=a.owner_case_id LEFT JOIN rules r ON r.id=a.rule_id LEFT JOIN users u ON u.id=c.assignee"
    counts = {key: 0 for key in ("main", "investigation", "closed")}
    for row in get_db().execute(f"SELECT {CHANNEL} AS channel,COUNT(*) AS total FROM {source} WHERE {where} GROUP BY channel", args):
        counts[row["channel"]] = row["total"]
    rows = (
        get_db()
        .execute(
            f"""SELECT a.id,a.alert_id,a.severity,a.detected_at,a.reason,a.rule_version,r.name AS rule_name,
        c.id AS case_id,c.reference,c.title AS case_title,c.status AS case_status,c.version AS case_version,
        c.assignee,u.name AS assignee_name,
        (SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id=a.id) AS evidence_events,
        (SELECT json_extract(v.payload,'$.verdict') FROM autopsy_alert_reviews v WHERE v.alert_id=a.id) AS verdict
        FROM {source} WHERE {where} AND ({CHANNEL})=?
        ORDER BY {sorts[sort]} {direction},a.id {direction} LIMIT ? OFFSET ?""",
            (*args, channel, size, (page - 1) * size),
        )
        .fetchall()
    )
    return jsonify(
        {
            "items": [dict(row) for row in rows],
            "total": counts[channel],
            "counts": counts,
            "page": page,
            "page_size": size,
            "channel": channel,
            "fetched_at": iso_now(),
        }
    )
