"""Operational insights over authorized, retained case data only."""

import json
import statistics
from collections import Counter, defaultdict
from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request

from .autopsy_pipeline import full_case_scope_sql
from .autopsy_workflow import factual_metrics, sla_status
from .case_counts import consistent_read
from .db import get_db
from .operational import case_scope
from .security import actor_id, current_user, error_response, require_permission, workspace_id
from .task_titles import task_view
from .timeutils import iso_now, parse_timestamp, utc_now
from .validation import public_error_message

soc_insights_api = Blueprint("autopsy_insights", __name__)


@soc_insights_api.get("/api/cases/<int:case_id>/network-insights")
@require_permission("cases.read")
@consistent_read
def network_insights(case_id):
    from .network_insights import network_snapshot

    where, args = authorized_cases()
    if not get_db().execute(f"SELECT 1 FROM incident_cases c WHERE c.id=? AND {where}", (case_id, *args)).fetchone():
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"page", "pair", "q"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ValueError
        page = int(request.args.get("page", "1"))
        query = request.args.get("q", "").strip().casefold()
        pair = request.args.get("pair", "")
        if not 1 <= page <= 1000000 or len(query) > 200 or len(pair) > 24:
            raise ValueError
    except ValueError:
        return error_response("INVALID_NETWORK_FILTER", "تحقق من مرشحات الشبكة", 422)
    try:
        snapshot = network_snapshot(get_db(), case_id, workspace_id())
    except ValueError as exc:
        return error_response("NETWORK_ANALYSIS_LIMIT", public_error_message(exc, "يتجاوز تحليل الشبكة الحد المسموح"), 422)
    items = snapshot.pop("items")
    selected = next((item for item in items if item["key"] == pair), None)
    if pair and selected is None:
        return error_response("CONNECTION_NOT_FOUND", "الاتصال غير متاح", 404)
    filtered = [
        item for item in items if not query or query in " ".join(str(item[key]) for key in ("source", "source_ip", "destination_ip", "names")).casefold()
    ]
    return jsonify({**snapshot, "items": filtered[(page - 1) * 25 : page * 25], "total": len(filtered), "page": page, "page_size": 25, "selected": selected})


@soc_insights_api.get("/api/cases/<int:case_id>/endpoint-queries")
@require_permission("cases.read")
@consistent_read
def endpoint_queries(case_id):
    where, args = authorized_cases()
    if not get_db().execute(f"SELECT 1 FROM incident_cases c WHERE c.id=? AND {where}", (case_id, *args)).fetchone():
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"page", "host", "action"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ValueError
        page = int(request.args.get("page", "1"))
        host, action = request.args.get("host", ""), request.args.get("action", "")
        if not 1 <= page <= 1000000 or len(host) > 512 or action not in {"", "added", "removed", "snapshot", "unchanged"}:
            raise ValueError
    except ValueError:
        return error_response("INVALID_ENDPOINT_FILTER", "تحقق من مرشحات الأجهزة", 422)
    predicate = (
        "owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND source_type='osquery' AND json_extract(normalized_fields,'$.telemetry_schema')='osquery'"
    )
    params: list[object] = [case_id, workspace_id()]
    if host:
        predicate += " AND hostname=?"
        params.append(host)
    if action:
        predicate += " AND action=?"
        params.append(action)
    total = get_db().execute(f"SELECT COUNT(*) FROM security_events WHERE {predicate}", params).fetchone()[0]
    items = []
    for row in get_db().execute(
        f"SELECT id,hostname,event_time,title,action,normalized_fields FROM security_events WHERE {predicate} ORDER BY id DESC LIMIT 25 OFFSET ?",
        (*params, (page - 1) * 25),
    ):
        item = dict(row)
        fields = json.loads(item.pop("normalized_fields"))
        item.update({"query": fields.get("query_name"), "columns": fields.get("query_columns", {}), "event_time_known": fields.get("event_time_known") is True})
        items.append(item)
    return jsonify({"items": items, "total": total, "page": page, "page_size": 25})


@soc_insights_api.get("/api/cases/<int:case_id>/content-inspection")
@require_permission("cases.read")
@consistent_read
def content_inspection(case_id):
    from .content_inspection import ENGINE

    where, args = authorized_cases()
    if not get_db().execute(f"SELECT 1 FROM incident_cases c WHERE c.id=? AND {where}", (case_id, *args)).fetchone():
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"page"} or len(request.args.getlist("page")) > 1:
            raise ValueError
        page = int(request.args.get("page", "1"))
        if not 1 <= page <= 1000000:
            raise ValueError
    except ValueError:
        return error_response("INVALID_INSPECTION_PAGE", "رقم الصفحة غير صالح", 422)
    predicate = "owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND json_extract(normalized_fields,'$.content_inspection.engine')=?"
    params = (case_id, workspace_id(), ENGINE)
    total = get_db().execute(f"SELECT COUNT(*) FROM security_events WHERE {predicate}", params).fetchone()[0]
    rows = get_db().execute(
        f"SELECT id,title,hostname,normalized_fields FROM security_events WHERE {predicate} ORDER BY id DESC LIMIT 25 OFFSET ?", (*params, (page - 1) * 25)
    )
    items = [
        {"event_id": row["id"], "title": row["title"], "hostname": row["hostname"], "inspection": json.loads(row["normalized_fields"])["content_inspection"]}
        for row in rows
    ]
    return jsonify({"items": items, "total": total, "page": page, "page_size": 25})


@soc_insights_api.get("/api/cases/<int:case_id>/observed-hosts")
@require_permission("cases.read")
@consistent_read
def observed_hosts(case_id):
    where, args = authorized_cases()
    if not get_db().execute(f"SELECT 1 FROM incident_cases c WHERE c.id=? AND {where}", (case_id, *args)).fetchone():
        return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
    try:
        if set(request.args) - {"q", "host", "page"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ValueError
        query = request.args.get("q", "").strip()
        host = request.args.get("host", "")
        page = int(request.args.get("page", "1"))
        if len(query) > 200 or len(host) > 512 or not 1 <= page <= 1000000:
            raise ValueError
    except ValueError:
        return error_response("INVALID_HOST_FILTER", "تحقق من اسم الجهاز والصفحة", 422)
    predicate = "owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND hostname IS NOT NULL AND hostname!=''"
    values: list[object] = [case_id, workspace_id()]
    if query:
        predicate += " AND hostname LIKE ? ESCAPE '\\'"
        values.append("%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    total = get_db().execute(f"SELECT COUNT(DISTINCT hostname) FROM security_events WHERE {predicate}", values).fetchone()[0]
    items = [
        dict(row)
        for row in get_db().execute(
            f"SELECT hostname,COUNT(*) AS events,MIN(CASE WHEN json_extract(normalized_fields,'$.event_time_known')=1 THEN event_time END) AS first_seen,MAX(CASE WHEN json_extract(normalized_fields,'$.event_time_known')=1 THEN event_time END) AS last_seen FROM security_events WHERE {predicate} GROUP BY hostname ORDER BY hostname LIMIT 25 OFFSET ?",
            (*values, (page - 1) * 25),
        )
    ]
    events = []
    if host:
        rows = get_db().execute(
            "SELECT id,event_time,hostname,source_ip,destination_ip,username,process_name,parent_process,file_hash,normalized_fields FROM security_events WHERE owner_case_id=? AND workspace_id=? AND hostname=? AND autopsy_active=1 ORDER BY id DESC LIMIT 51",
            (case_id, workspace_id(), host),
        )
        for row in rows:
            item = dict(row)
            fields = json.loads(item.pop("normalized_fields"))
            item["command_line"] = fields.get("command_line")
            item["event_time_known"] = bool(fields.get("event_time_known"))
            events.append(item)
    return jsonify({"items": items, "total": total, "page": page, "page_size": 25, "host": host, "events": events[:50], "events_truncated": len(events) > 50})


def authorized_cases():
    from .autopsy_workspace import selection_scope_sql

    user = current_user() or {}
    where = "c.workspace_id=? AND c.archived_at IS NULL AND c.training_run_id IS NULL"
    args: list[object] = [workspace_id()]
    for clause, values in (case_scope(user), full_case_scope_sql(user), selection_scope_sql()):
        where += clause
        args.extend(values)
    if current_app.config["REQUIRE_CASE_APPROVAL"]:
        where += " AND EXISTS(SELECT 1 FROM case_approvals p WHERE p.case_id=c.id AND p.state='approved')"
    return where, args


def moment(value):
    try:
        return parse_timestamp(value)
    except (ValueError, TypeError, OverflowError):
        return None


def measured_percentage(numerator, denominator):
    if not denominator:
        return None
    ratio = 100 * numerator / denominator
    # At the 2,000-case scope limit, retain the final 0.05% rather than
    # reporting complete success (or no success) for an incomplete result.
    return ratio if 0 < ratio < 1 or 99 < ratio < 100 else round(ratio, 1)


@soc_insights_api.get("/api/soc/performance")
@require_permission("cases.read")
@consistent_read
def performance():
    user = current_user() or {}
    manager = user.get("role") in {"admin", "soc_manager"}
    try:
        if set(request.args) - {"days", "member", "queue", "page"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ValueError
        days = request.args.get("days", "30")
        member = request.args.get("member", "team" if manager else "me")
        queue_kind = request.args.get("queue", "open")
        page = int(request.args.get("page", 1))
        if days not in {"7", "30", "90", "all"} or queue_kind not in {"open", "closed", "awaiting_review"} or not 1 <= page <= 1000000:
            raise ValueError
        member_id = actor_id() if member == "me" else None if member == "team" else int(member)
        if member_id is not None and not 1 <= member_id <= 2**63 - 1:
            raise ValueError
    except ValueError:
        return error_response("INVALID_PERFORMANCE_FILTER", "تحقق من الفترة والعضو", 422)
    if not manager and member_id != actor_id():
        return error_response("PERMISSION_DENIED", "عرض أداء الفريق متاح للمدير", 403)
    if member_id is not None and not get_db().execute("SELECT 1 FROM users WHERE id=? AND workspace_id=?", (member_id, workspace_id())).fetchone():
        return error_response("MEMBER_NOT_FOUND", "العضو غير متاح", 404)
    where, args = authorized_cases()
    if member_id is not None:
        where += " AND (c.assignee=? OR EXISTS(SELECT 1 FROM autopsy_case_members m WHERE m.case_id=c.id AND m.user_id=?))"
        args.extend([member_id, member_id])
    now = utc_now()
    cutoff = None if days == "all" else now - timedelta(days=int(days))
    # Backlog is current; completed work and trend use the selected period.
    cases = [dict(row) for row in get_db().execute(f"SELECT c.* FROM incident_cases c WHERE {where} ORDER BY c.id DESC LIMIT 2001", args)]
    if len(cases) > 2000:
        return error_response("PERFORMANCE_SCOPE_TOO_LARGE", "حدد عضوًا أو نطاق تحقيق أصغر لعرض الأداء", 422)
    ids = [case["id"] for case in cases]
    case_by_id = {case["id"]: case for case in cases}
    marks = ",".join("?" for _ in ids) or "NULL"
    records: dict[int, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for row in get_db().execute(
        f"SELECT case_id,kind,payload FROM autopsy_records WHERE case_id IN ({marks}) AND kind IN ('response','foothold','workflow_sla','workflow_sla_action') AND COALESCE(json_extract(payload,'$.visibility'),'team')!='private' ORDER BY id",
        ids,
    ):
        records[row["case_id"]][row["kind"]].append(json.loads(row["payload"]))
    tasks = [task_view(row) for row in get_db().execute(f"SELECT * FROM case_tasks WHERE case_id IN ({marks})", ids)]
    awaiting_decision = {
        row["case_id"] for row in get_db().execute(f"SELECT case_id FROM case_quick_reports WHERE case_id IN ({marks}) AND status='escalated'", ids)
    }
    alerts = [
        dict(row)
        for row in get_db().execute(
            f"SELECT a.owner_case_id AS case_id,a.severity,r.payload FROM alerts a LEFT JOIN autopsy_alert_reviews r ON r.alert_id=a.id WHERE a.owner_case_id IN ({marks}) AND a.workspace_id=?",
            (*ids, workspace_id()),
        )
    ]
    members = {
        row["id"]: dict(row)
        for row in get_db().execute(
            "SELECT id,socify_user_name(name,name_ar,name_en) AS name,role,is_active FROM users WHERE workspace_id=? ORDER BY name,id", (workspace_id(),)
        )
    }
    workload = {key: {**value, "open": 0, "closed": 0, "tasks_completed": 0} for key, value in members.items() if manager or key == actor_id()}
    trend: dict[str, dict[str, int]] = defaultdict(lambda: {"opened": 0, "closed": 0})
    severity: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    measures = defaultdict(list)
    open_cases, closed_cases, review_cases = [], [], []
    completion = {"total": 0, "completed": 0, "pending": 0, "unmeasured": 0}
    speed = {"on_time": 0, "late": 0, "unmeasured": 0}

    def in_period(value):
        stamp = moment(value)
        return stamp is not None and stamp <= now and (cutoff is None or stamp >= cutoff)

    for case in cases:
        active = case["status"] not in {"closed", "cancelled"}
        created, closed = moment(case["created_at"]), moment(case["closed_at"])
        valid_closure = created is not None and closed is not None and created <= closed <= now
        if case["status"] != "cancelled" and in_period(case["created_at"]):
            completion["total"] += 1
            completion["pending" if active else "completed" if valid_closure else "unmeasured"] += 1
        if active:
            open_cases.append(case)
            severity[case["severity"]] += 1
            if case["assignee"] in workload:
                workload[case["assignee"]]["open"] += 1
        if active and (case["status"] == "awaiting_review" or case["id"] in awaiting_decision):
            review_cases.append(case)
        if in_period(case["created_at"]):
            trend[moment(case["created_at"]).date().isoformat()]["opened"] += 1
        if case["status"] == "closed" and in_period(case["closed_at"]):
            closed_cases.append(case)
            trend[moment(case["closed_at"]).date().isoformat()]["closed"] += 1
            if case["assignee"] in workload:
                workload[case["assignee"]]["closed"] += 1
            metrics = factual_metrics(case, records[case["id"]], now)
            for key, value in metrics.items():
                if key.endswith("_seconds"):
                    measures[key].append(value)
            try:
                sla = sla_status(case, now, retained_records=records[case["id"]]) if valid_closure else {"configured": False}
                speed["unmeasured" if not sla["configured"] else "on_time" if sla["remaining_work_seconds"] >= 0 else "late"] += 1
            except (ValueError, TypeError, KeyError, OverflowError):
                speed["unmeasured"] += 1
    for task in tasks:
        if task["status"] in {"completed", "reviewed"} and in_period(task["completed_at"]) and task["completed_by"] in workload:
            workload[task["completed_by"]]["tasks_completed"] += 1
    active_ids = {case["id"] for case in open_cases}
    for alert in alerts:
        if alert["case_id"] in active_ids:
            outcomes[json.loads(alert["payload"])["verdict"] if alert["payload"] else "undetermined"] += 1
    overdue = [case for case in open_cases if not case["sla_paused_at"] and moment(case["sla_due_at"]) and moment(case["sla_due_at"]) < now]
    pending = [
        task
        for task in tasks
        if task["case_id"] in active_ids and task["status"] not in {"completed", "reviewed"} and (member_id is None or task["assignee"] == member_id)
    ]
    metric_results = {}
    for key in ("detection_delay_seconds", "acknowledgement_delay_seconds", "containment_delay_seconds", "recovery_delay_seconds", "closure_delay_seconds"):
        included = [value for value in measures[key] if value is not None]
        metric_results[key] = {
            "median_seconds": statistics.median(included) if included else None,
            "included": len(included),
            "excluded": len(closed_cases) - len(included),
        }

    def case_view(case):
        return {
            **{key: case[key] for key in ("id", "reference", "title", "severity", "status", "assignee", "created_at", "closed_at", "sla_due_at")},
            "assignee_name": members.get(case["assignee"], {}).get("name"),
        }

    queue = sorted(open_cases, key=lambda c: (c["id"] not in {item["id"] for item in overdue}, c["created_at"], c["id"]))
    if queue_kind == "closed":
        queue = sorted(closed_cases, key=lambda case: (moment(case["closed_at"]), case["id"]), reverse=True)
    elif queue_kind == "awaiting_review":
        queue = sorted(review_cases, key=lambda case: (case["created_at"], case["id"]))
    pages = max(1, (len(queue) + 49) // 50)
    page = min(page, pages)
    return jsonify(
        {
            "days": days,
            "member": member,
            "can_manage": manager,
            "fetched_at": iso_now(),
            "counts": {
                "open": len(open_cases),
                "closed": len(closed_cases),
                "awaiting_review": len(review_cases),
                "overdue": len(overdue),
                "unassigned": sum(case["assignee"] is None for case in open_cases),
                "pending_tasks": len(pending),
                "unreviewed_alerts": outcomes["undetermined"],
            },
            "severity": dict(severity),
            "verdicts": dict(outcomes),
            "metrics": metric_results,
            "completion": {
                **completion,
                "basis": "created_in_period",
                "percentage": measured_percentage(completion["completed"], completion["total"]) if not completion["unmeasured"] else None,
            },
            "speed": {
                **speed,
                "basis": "configured_case_sla",
                "included": speed["on_time"] + speed["late"],
                "compliance_percent": measured_percentage(speed["on_time"], speed["on_time"] + speed["late"]),
            },
            "trend": [{"date": day, **values} for day, values in sorted(trend.items())],
            "members": list(workload.values()) if member_id is None else [workload[member_id]] if member_id in workload else [],
            "queue": [case_view(case) for case in queue[(page - 1) * 50 : page * 50]],
            "queue_total": len(queue),
            "queue_kind": queue_kind,
            "queue_page": page,
            "queue_pages": pages,
            "queue_page_size": 50,
            "tasks": [
                {**task, "case_reference": case_by_id[task["case_id"]]["reference"], "case_title": case_by_id[task["case_id"]]["title"]}
                for task in pending[:50]
            ],
            "task_total": len(pending),
        }
    )


@soc_insights_api.get("/api/cases/<int:case_id>/alerts/<int:alert_id>/dossier")
@require_permission("cases.read")
@consistent_read
def alert_dossier(case_id, alert_id):
    from .quick_reports import _report_view

    where, args = authorized_cases()
    case = get_db().execute(f"SELECT c.* FROM incident_cases c WHERE c.id=? AND {where}", (case_id, *args)).fetchone()
    alert = (
        get_db()
        .execute(
            "SELECT a.*,r.name AS rule_name,v.payload AS review,v.changed_at,v.changed_by FROM alerts a LEFT JOIN rules r ON r.id=a.rule_id LEFT JOIN autopsy_alert_reviews v ON v.alert_id=a.id WHERE a.id=? AND a.owner_case_id=? AND a.workspace_id=?",
            (alert_id, case_id, workspace_id()),
        )
        .fetchone()
    )
    if not case or not alert:
        return error_response("ALERT_NOT_FOUND", "التنبيه غير متاح", 404)
    events = [
        dict(row)
        for row in get_db().execute(
            "SELECT e.id,e.event_time,e.source_ip,e.destination_ip,e.hostname,e.username,e.normalized_fields,e.raw_data,e.autopsy_active FROM alert_events ae JOIN security_events e ON e.id=ae.event_id WHERE ae.alert_id=? AND e.owner_case_id=? ORDER BY e.event_time,e.id LIMIT 51",
            (alert_id, case_id),
        )
    ]
    for event in events:
        event["normalized_fields"] = json.loads(event["normalized_fields"] or "{}")
        event["raw_truncated"] = len(event["raw_data"] or "") > 16000
        event["raw_data"] = (event["raw_data"] or "")[:16000]
    quick = get_db().execute("SELECT * FROM case_quick_reports WHERE case_id=?", (case_id,)).fetchone()
    tasks = [
        task_view(row)
        for row in get_db().execute("SELECT id,title,system_key,status,required,completed_at FROM case_tasks WHERE case_id=? ORDER BY id LIMIT 100", (case_id,))
    ]
    notes = [
        dict(row)
        for row in get_db().execute(
            "SELECT n.body,n.created_at,socify_user_name(u.name,u.name_ar,u.name_en) AS author FROM case_notes n JOIN users u ON u.id=n.author_id WHERE n.case_id=? AND n.visibility='team' ORDER BY n.id DESC LIMIT 10",
            (case_id,),
        )
    ]
    techniques = [
        dict(row)
        for row in get_db().execute(
            "SELECT technique_id,assessment,reason,event_id FROM case_technique_annotations WHERE case_id=? ORDER BY id LIMIT 100", (case_id,)
        )
    ]
    return jsonify(
        {
            "alert": {
                key: alert[key] for key in ("id", "alert_id", "rule_name", "rule_version", "severity", "reason", "detected_at", "changed_at", "changed_by")
            },
            "review": json.loads(alert["review"]) if alert["review"] else None,
            "case": {key: case[key] for key in ("id", "reference", "status", "closed_at", "created_at", "sla_due_at")},
            "events": events[:50],
            "events_truncated": len(events) > 50,
            "tasks": tasks,
            "notes": notes,
            "techniques": techniques,
            "assessment": _report_view(quick),
        }
    )
