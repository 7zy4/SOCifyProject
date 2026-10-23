import json

from flask import Blueprint, jsonify, request

from .attack_snapshot import activate_attack_version
from .audit import record_audit
from .db import get_db
from .security import error_response, require_permission, training_scope_sql, workspace_id

attack_api = Blueprint("attack", __name__)


def _metadata() -> dict[str, object]:
    values = {
        row["key"]: row["value"]
        for row in get_db()
        .execute(
            "SELECT key, value FROM schema_meta WHERE key IN ('attack_version', 'attack_snapshot_count', 'attack_snapshot_source', 'attack_snapshot_sha256')"
        )
        .fetchall()
    }
    count = int(get_db().execute("SELECT COUNT(*) FROM attack_techniques").fetchone()[0])
    return {
        "attack_version": values.get("attack_version", "unknown"),
        "snapshot_count": int(values.get("attack_snapshot_count", count)),
        "snapshot_source": values.get("attack_snapshot_source", "unknown"),
        "snapshot_sha256": values.get("attack_snapshot_sha256", "unknown"),
        "offline_snapshot": True,
    }


@attack_api.get("/api/attack/catalogs")
@require_permission("events.read")
def catalog_versions():
    catalogs = [dict(row) for row in get_db().execute("SELECT * FROM attack_catalog_versions ORDER BY imported_at DESC, version DESC").fetchall()]
    transitions = [dict(row) for row in get_db().execute("SELECT * FROM attack_catalog_transitions ORDER BY id DESC LIMIT 100").fetchall()]
    return jsonify({"items": catalogs, "transitions": transitions})


@attack_api.post("/api/attack/catalogs/<version>/activate")
@require_permission("rules.manage")
def activate_catalog(version: str):
    connection = get_db()
    try:
        changed = activate_attack_version(connection, version)
    except ValueError as exc:
        return error_response("ATTACK_VERSION_NOT_FOUND", str(exc), 404)
    record_audit(
        connection,
        "activate",
        "attack_catalog",
        version,
        details={"changed": changed},
        workspace=workspace_id(),
    )
    connection.commit()
    return jsonify({"version": version, "active": True, "changed": changed, **_metadata()})


def _technique_counts(technique_id: str) -> dict[str, int]:
    pattern = f'%"{technique_id}"%'
    event_scope, event_parameters = training_scope_sql("training_run_id")
    alert_scope, alert_parameters = training_scope_sql("training_run_id")
    case_scope, case_parameters = training_scope_sql("training_run_id")
    run_scope, run_parameters = training_scope_sql("r.id")
    seen = int(
        get_db()
        .execute(
            f"SELECT COUNT(*) FROM security_events WHERE workspace_id = ? AND source != 'rules_engine' AND mitre_ids LIKE ?{event_scope}",
            (workspace_id(), pattern, *event_parameters),
        )
        .fetchone()[0]
    )
    detected = int(
        get_db()
        .execute(
            f"SELECT COUNT(*) FROM alerts WHERE workspace_id = ? AND mitre_technique_ids LIKE ?{alert_scope}", (workspace_id(), pattern, *alert_parameters)
        )
        .fetchone()[0]
    )
    investigated = int(
        get_db()
        .execute(
            f"SELECT COUNT(DISTINCT id) FROM incident_cases WHERE workspace_id = ? AND mitre_ids LIKE ?{case_scope}",
            (workspace_id(), pattern, *case_parameters),
        )
        .fetchone()[0]
    )
    validated = int(
        get_db()
        .execute(
            f"SELECT COUNT(*) FROM assessment_snapshots a JOIN training_runs r ON r.id = a.run_id WHERE a.workspace_id = ? AND a.total_score >= 70 AND EXISTS (SELECT 1 FROM training_run_events tre JOIN security_events e ON e.id = tre.event_id WHERE tre.run_id = r.id AND e.mitre_ids LIKE ?){run_scope}",
            (workspace_id(), pattern, *run_parameters),
        )
        .fetchone()[0]
    )
    return {"seen": seen, "detected_in_run": detected, "investigated": investigated, "validated": validated}


@attack_api.get("/api/attack/techniques")
@require_permission("events.read")
def list_techniques():
    query = request.args.get("q", "").strip()
    if len(query) > 100:
        return error_response("QUERY_TOO_LONG", "نص البحث طويل جدًا", 422)
    if query:
        rows = (
            get_db()
            .execute("SELECT * FROM attack_techniques WHERE technique_id LIKE ? OR name LIKE ? ORDER BY technique_id", (f"%{query}%", f"%{query}%"))
            .fetchall()
        )
    else:
        rows = get_db().execute("SELECT * FROM attack_techniques ORDER BY technique_id").fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["coverage"] = _technique_counts(row["technique_id"])
        items.append(item)
    return jsonify({"items": items, "source": "MITRE ATT&CK Enterprise", **_metadata()})


@attack_api.get("/api/attack/techniques/<path:technique_id>")
@require_permission("events.read")
def technique_detail(technique_id: str):
    row = get_db().execute("SELECT * FROM attack_techniques WHERE technique_id = ?", (technique_id.upper(),)).fetchone()
    if not row:
        return error_response("TECHNIQUE_NOT_FOUND", "تقنية ATT&CK غير موجودة في النسخة المثبتة", 404)
    item = dict(row)
    item["coverage"] = _technique_counts(row["technique_id"])
    item["rules"] = [
        dict(value)
        for value in get_db()
        .execute(
            "SELECT id, name, version, is_active FROM rules WHERE workspace_id = ? AND dsl_json LIKE ? AND archived_at IS NULL",
            (workspace_id(), f'%"{technique_id.upper()}"%'),
        )
        .fetchall()
    ]
    event_scope, event_parameters = training_scope_sql("training_run_id")
    case_scope, case_parameters = training_scope_sql("training_run_id")
    item["events"] = [
        dict(value)
        for value in get_db()
        .execute(
            f"SELECT id, event_id, event_time, title, severity FROM security_events WHERE workspace_id = ? AND source != 'rules_engine' AND mitre_ids LIKE ?{event_scope} ORDER BY event_time DESC LIMIT 100",
            (workspace_id(), f'%"{technique_id.upper()}"%', *event_parameters),
        )
        .fetchall()
    ]
    item["cases"] = [
        dict(value)
        for value in get_db()
        .execute(
            f"SELECT id, reference, title, status FROM incident_cases WHERE workspace_id = ? AND mitre_ids LIKE ?{case_scope} ORDER BY updated_at DESC LIMIT 100",
            (workspace_id(), f'%"{technique_id.upper()}"%', *case_parameters),
        )
        .fetchall()
    ]
    item["interpretation_notice"] = "ATT&CK classifies observed behavior and does not independently prove a real attack."
    return jsonify(item)


def _missed_counts() -> dict[str, int]:
    scope, parameters = training_scope_sql("tr.id")
    rows = (
        get_db()
        .execute(
            f"""SELECT DISTINCT st.mitre_ids, tr.id AS run_id
        FROM training_runs tr JOIN scenario_steps st ON st.scenario_version_id = tr.scenario_version_id
        WHERE tr.workspace_id = ? AND tr.state = 'completed'{scope}""",
            (workspace_id(), *parameters),
        )
        .fetchall()
    )
    missed: dict[str, int] = {}
    for row in rows:
        for technique_id in json.loads(row["mitre_ids"] or "[]"):
            detected = (
                get_db()
                .execute("SELECT 1 FROM alerts WHERE training_run_id = ? AND mitre_technique_ids LIKE ? LIMIT 1", (row["run_id"], f'%"{technique_id}"%'))
                .fetchone()
            )
            if not detected:
                missed[technique_id] = missed.get(technique_id, 0) + 1
    return missed


@attack_api.get("/api/attack/matrix")
@require_permission("events.read")
def matrix():
    rows = get_db().execute("SELECT * FROM attack_techniques WHERE deprecated = 0 AND revoked = 0 ORDER BY tactic, technique_id").fetchall()
    missed = _missed_counts()
    tactics: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        coverage = _technique_counts(row["technique_id"])
        coverage["missed"] = missed.get(row["technique_id"], 0)
        item = {"technique_id": row["technique_id"], "name": row["name"], "coverage": coverage}
        for tactic in str(row["tactic"]).split(","):
            tactics.setdefault(tactic, []).append(item)
    return jsonify(
        {
            "tactics": [{"name": key, "techniques": value} for key, value in tactics.items()],
            "levels": ["configured", "tested", "detected_in_run", "investigated", "validated"],
            **_metadata(),
        }
    )


@attack_api.get("/api/attack/coverage")
@require_permission("events.read")
def coverage():
    rows = get_db().execute("SELECT technique_id, name FROM attack_techniques ORDER BY technique_id").fetchall()
    missed = _missed_counts()
    items = []
    for row in rows:
        counts = _technique_counts(row["technique_id"])
        configured = int(
            get_db()
            .execute(
                "SELECT COUNT(*) FROM rules WHERE workspace_id = ? AND archived_at IS NULL AND dsl_json LIKE ?", (workspace_id(), f'%"{row["technique_id"]}"%')
            )
            .fetchone()[0]
        )
        tested = int(
            get_db()
            .execute(
                "SELECT COUNT(*) FROM rule_versions rv JOIN rules r ON r.id = rv.rule_id WHERE r.workspace_id = ? AND rv.dsl_json LIKE ?",
                (workspace_id(), f'%"{row["technique_id"]}"%'),
            )
            .fetchone()[0]
        )
        items.append(
            {
                "technique_id": row["technique_id"],
                "name": row["name"],
                "configured": configured,
                "tested": tested,
                **counts,
                "missed": missed.get(row["technique_id"], 0),
            }
        )
    return jsonify({"items": items, **_metadata()})


@attack_api.get("/api/attack/navigator-layer")
@require_permission("events.read")
def navigator_layer():
    rows = get_db().execute("SELECT technique_id, name FROM attack_techniques ORDER BY technique_id").fetchall()
    techniques = []
    for row in rows:
        coverage = _technique_counts(row["technique_id"])
        score = min(100, coverage["detected_in_run"] * 20 + coverage["investigated"] * 30 + coverage["validated"] * 50)
        techniques.append(
            {
                "techniqueID": row["technique_id"],
                "score": score,
                "comment": f"seen={coverage['seen']}; detected={coverage['detected_in_run']}; investigated={coverage['investigated']}; validated={coverage['validated']}",
            }
        )
    metadata = _metadata()
    return jsonify(
        {
            "name": "SOCify ATT&CK Coverage",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "Evidence-backed SOCify training coverage",
            "filters": {"platforms": []},
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {"colors": ["#8b1e3f", "#d6a23d", "#1f8f5f"], "minValue": 0, "maxValue": 100},
            "legendItems": [],
            "metadata": [
                {"name": "ATT&CK release", "value": metadata["attack_version"]},
                {"name": "Snapshot techniques", "value": str(metadata["snapshot_count"])},
            ],
            "links": [],
        }
    )
