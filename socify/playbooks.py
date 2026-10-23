import hashlib
import json
import sqlite3
from typing import Any

from flask import Blueprint, jsonify, request

from .audit import record_audit, record_training_action
from .db import get_db, inserted_id, transaction
from .schema import insert_outbox, public_id
from .security import actor_id, can_access_training_run, error_response, require_permission, workspace_id
from .timeutils import iso_now

playbooks_api = Blueprint("playbooks", __name__)

ACTIONS = {
    "isolate_virtual_host",
    "block_simulated_ip",
    "disable_training_account",
    "force_reset_synthetic_credentials",
    "collect_evidence",
    "escalate_to_manager",
    "notify_training_team",
    "tag_ioc",
    "contain_simulated_exfiltration",
    "restore_virtual_service",
}


def _playbook_view(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


@playbooks_api.get("/api/playbooks")
@require_permission("playbooks.request")
def list_playbooks():
    rows = (
        get_db()
        .execute(
            """SELECT p.*, pv.trigger_type, pv.preconditions, pv.expected_outcome,
        (SELECT COUNT(*) FROM playbook_steps ps WHERE ps.playbook_version_id = pv.id) AS step_count
        FROM playbooks p JOIN playbook_versions pv ON pv.playbook_id = p.id AND pv.version = p.active_version
        WHERE p.workspace_id = ? AND p.state = 'published' ORDER BY p.name""",
            (workspace_id(),),
        )
        .fetchall()
    )
    items = []
    for row in rows:
        item = dict(row)
        for field in ("preconditions", "expected_outcome"):
            item[field] = json.loads(item[field])
        items.append(item)
    return jsonify({"items": items})


def _playbook_payload(data: object) -> tuple[dict[str, Any] | None, object | None]:
    if not isinstance(data, dict):
        return None, error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    name = data.get("name")
    description = data.get("description", "")
    steps = data.get("steps")
    if not isinstance(name, str) or not 3 <= len(name.strip()) <= 180 or not isinstance(description, str) or len(description) > 5000:
        return None, error_response("INVALID_PLAYBOOK", "اسم خطة الاستجابة ووصفها غير صالحين", 422)
    if not isinstance(steps, list) or not 1 <= len(steps) <= 30:
        return None, error_response("INVALID_PLAYBOOK_STEPS", "يلزم من خطوة واحدة إلى 30 خطوة", 422)
    normalized = []
    positions: set[int] = set()
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict) or not isinstance(step.get("action"), str) or step.get("action") not in ACTIONS:
            return None, error_response("UNSAFE_PLAYBOOK_ACTION", "تحتوي الخطة على إجراء غير مدعوم أو خارجي", 422)
        position = step.get("position", index)
        parameters = step.get("parameters", {})
        approval_role = step.get("approval_role")
        if (
            type(position) is not int
            or position < 1
            or position in positions
            or not isinstance(parameters, dict)
            or approval_role is not None
            and approval_role != "soc_manager"
        ):
            return None, error_response("INVALID_PLAYBOOK_STEP", "ترتيب الخطوة أو معطياتها أو الموافقة غير صالحة", 422)
        if len(json.dumps(parameters, ensure_ascii=False)) > 5000:
            return None, error_response("INVALID_PLAYBOOK_STEP", "معطيات الخطوة تتجاوز الحجم المسموح", 422)
        timeout = step.get("timeout_seconds", 30)
        retries = step.get("retry_limit", 2)
        compensation = step.get("compensation_action")
        if type(timeout) is not int or not 1 <= timeout <= 300 or type(retries) is not int or not 0 <= retries <= 5:
            return None, error_response("INVALID_PLAYBOOK_STEP", "مدة الخطوة وحد إعادة المحاولة غير صالحين", 422)
        if compensation is not None and (not isinstance(compensation, str) or compensation not in ACTIONS):
            return None, error_response("INVALID_PLAYBOOK_STEP", "إجراء التراجع غير صالح", 422)
        positions.add(position)
        normalized.append(
            {
                "position": position,
                "action": step["action"],
                "parameters": parameters,
                "approval_role": approval_role,
                "timeout_seconds": timeout,
                "retry_limit": retries,
                "compensation_action": compensation,
            }
        )
    trigger = data.get("trigger_type", "manual")
    if (
        not isinstance(trigger, str)
        or trigger not in {"manual", "recommended", "automated_simulation"}
        or not isinstance(data.get("preconditions", {}), dict)
        or not isinstance(data.get("expected_outcome", {}), dict)
    ):
        return None, error_response("INVALID_PLAYBOOK", "نوع التشغيل والشروط والنتيجة المتوقعة غير صالحة", 422)
    return {
        "name": name.strip(),
        "description": description.strip(),
        "trigger_type": trigger,
        "preconditions": data.get("preconditions", {}),
        "expected_outcome": data.get("expected_outcome", {}),
        "steps": normalized,
        "publish": bool(data.get("publish")),
    }, None


def _insert_playbook_version(playbook_id: int, version: int, payload: dict[str, Any]) -> int:
    now = iso_now()
    cursor = get_db().execute(
        "INSERT INTO playbook_versions (playbook_id, version, trigger_type, preconditions, expected_outcome, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            playbook_id,
            version,
            payload["trigger_type"],
            json.dumps(payload["preconditions"], ensure_ascii=False),
            json.dumps(payload["expected_outcome"], ensure_ascii=False),
            actor_id(),
            now,
        ),
    )
    version_id = inserted_id(cursor)
    for step in payload["steps"]:
        get_db().execute(
            "INSERT INTO playbook_steps (playbook_version_id, position, action_type, parameters, approval_role, timeout_seconds, retry_limit, compensation_action) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                version_id,
                step["position"],
                step["action"],
                json.dumps(step["parameters"], ensure_ascii=False),
                step["approval_role"],
                step["timeout_seconds"],
                step["retry_limit"],
                step["compensation_action"],
            ),
        )
    return version_id


@playbooks_api.post("/api/playbooks")
@require_permission("playbooks.manage")
def create_playbook():
    payload, failure = _playbook_payload(request.get_json(silent=True))
    if failure:
        return failure
    if payload is None:
        raise RuntimeError("playbook payload validation did not return data")
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            "INSERT INTO playbooks (playbook_id, workspace_id, name, description, active_version, state, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (public_id("PB"), workspace_id(), payload["name"], payload["description"], "published" if payload["publish"] else "draft", actor_id(), now, now),
        )
        playbook_id = inserted_id(cursor)
        _insert_playbook_version(playbook_id, 1, payload)
        record_audit(get_db(), "create", "playbook", playbook_id, details={"published": payload["publish"]})
    return jsonify({"id": playbook_id, "version": 1, "state": "published" if payload["publish"] else "draft"}), 201


@playbooks_api.post("/api/playbooks/<int:playbook_id>/versions")
@require_permission("playbooks.manage")
def create_playbook_version(playbook_id: int):
    playbook = get_db().execute("SELECT * FROM playbooks WHERE id = ? AND workspace_id = ?", (playbook_id, workspace_id())).fetchone()
    if not playbook:
        return error_response("PLAYBOOK_NOT_FOUND", "خطة الاستجابة غير موجودة", 404)
    payload, failure = _playbook_payload(request.get_json(silent=True))
    if failure:
        return failure
    if payload is None:
        raise RuntimeError("playbook payload validation did not return data")
    version = int(playbook["active_version"]) + 1
    now = iso_now()
    with transaction():
        _insert_playbook_version(playbook_id, version, payload)
        get_db().execute(
            "UPDATE playbooks SET name = ?, description = ?, active_version = ?, state = ?, updated_at = ? WHERE id = ?",
            (payload["name"], payload["description"], version, "published" if payload["publish"] else "draft", now, playbook_id),
        )
        record_audit(get_db(), "version", "playbook", playbook_id, details={"version": version, "published": payload["publish"]})
    return jsonify({"id": playbook_id, "version": version, "state": "published" if payload["publish"] else "draft"}), 201


def _version(playbook_id: int) -> sqlite3.Row | None:
    return (
        get_db()
        .execute(
            "SELECT pv.* FROM playbook_versions pv JOIN playbooks p ON p.id = pv.playbook_id AND p.active_version = pv.version WHERE p.id = ? AND p.workspace_id = ? AND p.state = 'published'",
            (playbook_id, workspace_id()),
        )
        .fetchone()
    )


def _steps(version_id: int) -> list[sqlite3.Row]:
    return get_db().execute("SELECT * FROM playbook_steps WHERE playbook_version_id = ? ORDER BY position", (version_id,)).fetchall()


def _parameters(data: dict[str, Any]) -> dict[str, Any]:
    parameters = data.get("parameters", {})
    if not isinstance(parameters, dict) or len(parameters) > 30:
        raise ValueError("parameters must be an object with at most 30 fields")
    serialized = json.dumps(parameters, ensure_ascii=False)
    if len(serialized) > 10000:
        raise ValueError("parameters exceed the size limit")
    return parameters


def _validate_context(data: dict[str, Any]) -> tuple[int | None, int | None, object | None]:
    case_id = data.get("case_id")
    training_run_id = data.get("training_run_id")
    case = None
    if case_id is not None:
        if not isinstance(case_id, int):
            return None, None, error_response("INVALID_CASE_ID", "معرف التحقيق غير صالح", 422)
        case = get_db().execute("SELECT id, training_run_id FROM incident_cases WHERE id = ? AND workspace_id = ?", (case_id, workspace_id())).fetchone()
        if not case or not can_access_training_run(case["training_run_id"]):
            return None, None, error_response("CASE_NOT_FOUND", "التحقيق غير موجود", 404)
        if training_run_id is None:
            training_run_id = case["training_run_id"]
    if training_run_id is not None and not can_access_training_run(training_run_id):
        return None, None, error_response("RUN_NOT_FOUND", "جلسة التدريب غير موجودة", 404)
    return case_id if isinstance(case_id, int) else None, training_run_id if isinstance(training_run_id, int) else None, None


@playbooks_api.post("/api/playbooks/<int:playbook_id>/preview")
@require_permission("playbooks.request")
def preview_playbook(playbook_id: int):
    version = _version(playbook_id)
    if not version:
        return error_response("PLAYBOOK_NOT_FOUND", "خطة الاستجابة غير موجودة", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("INVALID_JSON", "يلزم إرسال كائن JSON صالح", 400)
    case_id, training_run_id, failure = _validate_context(data)
    if failure:
        return failure
    try:
        parameters = _parameters(data)
    except ValueError as exc:
        return error_response("INVALID_PARAMETERS", str(exc), 422)
    steps = _steps(int(version["id"]))
    return jsonify(
        {
            "playbook_id": playbook_id,
            "version": version["version"],
            "case_id": case_id,
            "training_run_id": training_run_id,
            "parameters": parameters,
            "steps": [
                {
                    "position": step["position"],
                    "action": step["action_type"],
                    "approval_role": step["approval_role"],
                    "expected_change": _expected_change(step["action_type"]),
                    "rollback": step["compensation_action"],
                }
                for step in steps
            ],
            "external_effects": False,
            "confirmation_required": True,
        }
    )


def _expected_change(action: str) -> str:
    return {
        "isolate_virtual_host": "Set the selected simulated host state to isolated",
        "block_simulated_ip": "Set the selected simulated IP state to blocked",
        "disable_training_account": "Disable the selected synthetic training account",
        "force_reset_synthetic_credentials": "Rotate the synthetic credential version",
        "collect_evidence": "Attach a generated training evidence record to the case",
        "escalate_to_manager": "Move the case to the escalated state",
        "notify_training_team": "Create an internal training notification",
        "tag_ioc": "Apply a training tag to the selected indicator",
        "contain_simulated_exfiltration": "Set the simulated exfiltration state to contained",
        "restore_virtual_service": "Set the selected virtual service state to available",
    }.get(action, "Unsupported action")


@playbooks_api.post("/api/playbook-runs")
@require_permission("playbooks.request")
def create_playbook_run():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("playbook_id"), int):
        return error_response("PLAYBOOK_REQUIRED", "حدد خطة الاستجابة", 422)
    version = _version(data["playbook_id"])
    if not version:
        return error_response("PLAYBOOK_NOT_FOUND", "خطة الاستجابة غير موجودة", 404)
    case_id, training_run_id, failure = _validate_context(data)
    if failure:
        return failure
    try:
        parameters = _parameters(data)
    except ValueError as exc:
        return error_response("INVALID_PARAMETERS", str(exc), 422)
    idempotency_key = request.headers.get("Idempotency-Key") or data.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 255:
        return error_response("IDEMPOTENCY_KEY_REQUIRED", "يلزم مفتاح Idempotency بطول 8 محارف على الأقل", 422)
    existing = get_db().execute("SELECT * FROM playbook_runs WHERE workspace_id = ? AND idempotency_key = ?", (workspace_id(), idempotency_key)).fetchone()
    if existing:
        if not _run_access(int(existing["id"])):
            return error_response("PLAYBOOK_RUN_NOT_FOUND", "تشغيل الاستجابة غير موجود", 404)
        return jsonify(_run_view(existing) | {"duplicate": True})
    steps = _steps(int(version["id"]))
    approval_required = any(step["approval_role"] for step in steps)
    now = iso_now()
    with transaction():
        cursor = get_db().execute(
            "INSERT INTO playbook_runs (run_id, workspace_id, playbook_version_id, case_id, training_run_id, state, requested_by, idempotency_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                public_id("PBR"),
                workspace_id(),
                version["id"],
                case_id,
                training_run_id,
                "awaiting_approval" if approval_required else "pending",
                actor_id(),
                idempotency_key,
                now,
                now,
            ),
        )
        run_id = inserted_id(cursor)
        for step in steps:
            step_parameters = {**json.loads(step["parameters"]), **parameters}
            get_db().execute(
                "INSERT INTO playbook_step_runs (run_id, step_id, status, attempt, input) VALUES (?, ?, ?, 0, ?)",
                (
                    run_id,
                    step["id"],
                    "awaiting_approval" if step["approval_role"] else "pending",
                    json.dumps(step_parameters, ensure_ascii=False, separators=(",", ":")),
                ),
            )
        record_audit(
            get_db(),
            "request",
            "playbook_run",
            run_id,
            details={"case_id": case_id, "training_run_id": training_run_id, "approval_required": approval_required},
        )
        record_training_action(
            get_db(),
            training_run_id,
            actor_id(),
            "playbook_requested",
            "playbook_run",
            run_id,
            {"playbook_id": data["playbook_id"]},
            f"playbook-request:{idempotency_key}",
        )
    if not approval_required:
        _execute_run(run_id)
    return jsonify(_run_view(get_db().execute("SELECT * FROM playbook_runs WHERE id = ?", (run_id,)).fetchone())), 201


def _entity_key(action: str, parameters: dict[str, Any]) -> tuple[str, str, str]:
    mapping = {
        "isolate_virtual_host": ("host", "host", "isolated"),
        "block_simulated_ip": ("ip", "ip", "blocked"),
        "disable_training_account": ("account", "username", "disabled"),
        "force_reset_synthetic_credentials": ("account", "username", "credentials_rotated"),
        "contain_simulated_exfiltration": ("exfiltration", "channel", "contained"),
        "restore_virtual_service": ("service", "service", "available"),
    }
    entity_type, parameter_name, state = mapping[action]
    identifier = parameters.get(parameter_name)
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 255:
        raise ValueError(f"parameter {parameter_name} is required")
    return entity_type, identifier.strip(), state


def _apply_action(connection: sqlite3.Connection, run: sqlite3.Row, action: str, parameters: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if action not in ACTIONS:
        raise ValueError("unsupported playbook action")
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    if action in {
        "isolate_virtual_host",
        "block_simulated_ip",
        "disable_training_account",
        "force_reset_synthetic_credentials",
        "contain_simulated_exfiltration",
        "restore_virtual_service",
    }:
        entity_type, entity_id, target_state = _entity_key(action, parameters)
        existing = connection.execute(
            "SELECT state FROM response_simulation_state WHERE workspace_id = ? AND training_run_id IS ? AND entity_type = ? AND entity_id = ?",
            (run["workspace_id"], run["training_run_id"], entity_type, entity_id),
        ).fetchone()
        before = {"entity_type": entity_type, "entity_id": entity_id, "state": existing["state"] if existing else "normal"}
        connection.execute(
            "INSERT INTO response_simulation_state (workspace_id, training_run_id, entity_type, entity_id, state, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(workspace_id, training_run_id, entity_type, entity_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
            (run["workspace_id"], run["training_run_id"], entity_type, entity_id, target_state, iso_now()),
        )
        after = {"entity_type": entity_type, "entity_id": entity_id, "state": target_state}
    elif action == "collect_evidence":
        if not run["case_id"]:
            raise ValueError("collect_evidence requires a case")
        case = connection.execute(
            "SELECT status FROM incident_cases WHERE id = ? AND workspace_id = ? AND training_run_id IS ?",
            (run["case_id"], run["workspace_id"], run["training_run_id"]),
        ).fetchone()
        if not case or case["status"] == "closed":
            raise ValueError("case evidence is locked or inaccessible")
        content = json.dumps(parameters, ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(content.encode()).hexdigest()
        cursor = connection.execute(
            "INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, sha256, provenance, added_by, added_at) VALUES (?, 'training_artifact', ?, ?, ?, ?, ?, ?)",
            (
                run["case_id"],
                f"playbook-run-{run['id']}",
                "Playbook evidence collection",
                digest,
                json.dumps({"playbook_run_id": run["id"]}),
                run["requested_by"],
                iso_now(),
            ),
        )
        after = {"evidence_id": cursor.lastrowid, "sha256": digest}
    elif action == "escalate_to_manager":
        if not run["case_id"]:
            raise ValueError("escalation requires a case")
        case = connection.execute(
            "SELECT status FROM incident_cases WHERE id = ? AND workspace_id = ? AND training_run_id IS ?",
            (run["case_id"], run["workspace_id"], run["training_run_id"]),
        ).fetchone()
        if not case or case["status"] in {"closed", "cancelled"}:
            raise ValueError("case must be reopened before escalation")
        before = {"status": case["status"]}
        connection.execute("UPDATE incident_cases SET status = 'escalated', updated_at = ?, version = version + 1 WHERE id = ?", (iso_now(), run["case_id"]))
        after = {"status": "escalated"}
    elif action == "notify_training_team":
        insert_outbox(
            connection,
            run["workspace_id"],
            "training.notification",
            {"playbook_run_id": run["id"], "case_id": run["case_id"], "message": str(parameters.get("message") or "Playbook notification")[:500]},
        )
        after = {"notification": "queued"}
    elif action == "tag_ioc":
        ioc_id = parameters.get("ioc_id")
        tag = parameters.get("tag")
        if not isinstance(ioc_id, int) or not isinstance(tag, str) or not tag:
            raise ValueError("ioc_id and tag are required")
        from .hunting import _ioc_view

        ioc = connection.execute("SELECT * FROM ioc_indicators WHERE id = ? AND workspace_id = ?", (ioc_id, run["workspace_id"])).fetchone()
        if not ioc or _ioc_view(ioc) is None:
            raise ValueError("indicator not found")
        observations = connection.execute(
            "SELECT o.event_id, o.tags FROM ioc_observations o JOIN security_events e ON e.id = o.event_id WHERE o.ioc_id = ? AND e.workspace_id = ? AND e.training_run_id IS ?",
            (ioc_id, run["workspace_id"], run["training_run_id"]),
        ).fetchall()
        if not observations and (run["training_run_id"] is not None or ioc["source"] != "SOCify synthetic fixtures"):
            raise ValueError("indicator not found in response scope")
        tags = sorted({value for observation in observations for value in json.loads(observation["tags"])}) if observations else json.loads(ioc["tags"])
        before = {"tags": list(tags)}
        tags = sorted(set(tags + [tag[:80]]))
        if observations:
            for observation in observations:
                updated_tags = sorted(set(json.loads(observation["tags"]) + [tag[:80]]))
                connection.execute(
                    "UPDATE ioc_observations SET tags = ? WHERE ioc_id = ? AND event_id = ?", (json.dumps(updated_tags), ioc_id, observation["event_id"])
                )
        else:
            connection.execute("UPDATE ioc_indicators SET tags = ? WHERE id = ?", (json.dumps(tags), ioc_id))
        after = {"tags": tags}
    return before, after


def _execute_run(run_id: int) -> None:
    run = get_db().execute("SELECT * FROM playbook_runs WHERE id = ?", (run_id,)).fetchone()
    if not run or run["state"] not in {"pending", "approved", "failed"}:
        return
    get_db().execute("UPDATE playbook_runs SET state = 'running', updated_at = ? WHERE id = ?", (iso_now(), run_id))
    step_runs = (
        get_db()
        .execute(
            "SELECT psr.*, ps.action_type, ps.retry_limit FROM playbook_step_runs psr JOIN playbook_steps ps ON ps.id = psr.step_id WHERE psr.run_id = ? ORDER BY ps.position",
            (run_id,),
        )
        .fetchall()
    )
    failed = False
    for step in step_runs:
        if step["status"] == "succeeded":
            continue
        parameters = json.loads(step["input"])
        started = iso_now()
        get_db().execute(
            "UPDATE playbook_step_runs SET status = 'running', attempt = attempt + 1, started_at = ?, error = NULL WHERE id = ?", (started, step["id"])
        )
        try:
            before, after = _apply_action(get_db(), run, step["action_type"], parameters)
            output = {"before": before, "after": after, "simulated": True}
            get_db().execute(
                "UPDATE playbook_step_runs SET status = 'succeeded', output = ?, impact = ?, completed_at = ? WHERE id = ?",
                (json.dumps(output, ensure_ascii=False), json.dumps(after, ensure_ascii=False), iso_now(), step["id"]),
            )
        except (ValueError, sqlite3.Error) as exc:
            failed = True
            get_db().execute(
                "UPDATE playbook_step_runs SET status = 'failed', error = ?, completed_at = ? WHERE id = ?", (str(exc)[:500], iso_now(), step["id"])
            )
            break
    state = "failed" if failed else "succeeded"
    get_db().execute("UPDATE playbook_runs SET state = ?, updated_at = ? WHERE id = ?", (state, iso_now(), run_id))
    record_audit(get_db(), "execute", "playbook_run", run_id, result="failed" if failed else "success", details={"state": state})
    record_training_action(
        get_db(),
        run["training_run_id"],
        run["requested_by"],
        "playbook_completed",
        "playbook_run",
        run_id,
        {"state": state},
        f"playbook-complete:{run_id}:{state}",
    )
    insert_outbox(get_db(), run["workspace_id"], "playbook_run.updated", {"id": run_id, "state": state})


@playbooks_api.post("/api/playbook-runs/<int:run_id>/approve")
@require_permission("playbooks.approve")
def approve_run(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("PLAYBOOK_RUN_NOT_FOUND", "تشغيل الاستجابة غير موجود", 404)
    if run["state"] != "awaiting_approval":
        return error_response("APPROVAL_NOT_AVAILABLE", "التشغيل لا ينتظر موافقة", 409)
    get_db().execute("UPDATE playbook_runs SET state = 'approved', approved_by = ?, updated_at = ? WHERE id = ?", (actor_id(), iso_now(), run_id))
    get_db().execute("UPDATE playbook_step_runs SET status = 'pending' WHERE run_id = ? AND status = 'awaiting_approval'", (run_id,))
    record_audit(get_db(), "approve", "playbook_run", run_id)
    _execute_run(run_id)
    return jsonify(_run_view(get_db().execute("SELECT * FROM playbook_runs WHERE id = ?", (run_id,)).fetchone()))


@playbooks_api.post("/api/playbook-runs/<int:run_id>/retry")
@require_permission("playbooks.request")
def retry_run(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("PLAYBOOK_RUN_NOT_FOUND", "تشغيل الاستجابة غير موجود", 404)
    if run["state"] != "failed":
        return error_response("RETRY_NOT_AVAILABLE", "إعادة المحاولة متاحة للتشغيل الفاشل فقط", 409)
    failed_steps = (
        get_db()
        .execute(
            "SELECT psr.id, psr.attempt, ps.retry_limit FROM playbook_step_runs psr JOIN playbook_steps ps ON ps.id = psr.step_id WHERE psr.run_id = ? AND psr.status = 'failed'",
            (run_id,),
        )
        .fetchall()
    )
    if any(step["attempt"] >= step["retry_limit"] for step in failed_steps):
        return error_response("RETRY_LIMIT_REACHED", "بلغت إحدى الخطوات حد إعادة المحاولة", 409)
    get_db().execute("UPDATE playbook_step_runs SET status = 'pending' WHERE run_id = ? AND status = 'failed'", (run_id,))
    _execute_run(run_id)
    return jsonify(_run_view(get_db().execute("SELECT * FROM playbook_runs WHERE id = ?", (run_id,)).fetchone()))


@playbooks_api.post("/api/playbook-runs/<int:run_id>/cancel")
@require_permission("playbooks.request")
def cancel_run(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("PLAYBOOK_RUN_NOT_FOUND", "تشغيل الاستجابة غير موجود", 404)
    if run["state"] not in {"pending", "awaiting_approval", "approved", "failed"}:
        return error_response("CANCEL_NOT_AVAILABLE", "لا يمكن إلغاء التشغيل في حالته الحالية", 409)
    get_db().execute("UPDATE playbook_runs SET state = 'cancelled', updated_at = ? WHERE id = ?", (iso_now(), run_id))
    get_db().execute(
        "UPDATE playbook_step_runs SET status = 'skipped', completed_at = ? WHERE run_id = ? AND status IN ('pending', 'awaiting_approval')",
        (iso_now(), run_id),
    )
    record_audit(get_db(), "cancel", "playbook_run", run_id)
    return jsonify({"id": run_id, "state": "cancelled"})


@playbooks_api.post("/api/playbook-runs/<int:run_id>/rollback")
@require_permission("playbooks.approve")
def rollback_run(run_id: int):
    run = _run_access(run_id)
    if not run:
        return error_response("PLAYBOOK_RUN_NOT_FOUND", "تشغيل الاستجابة غير موجود", 404)
    if run["state"] != "succeeded":
        return error_response("ROLLBACK_NOT_AVAILABLE", "التراجع متاح للتشغيل الناجح فقط", 409)
    steps = (
        get_db()
        .execute(
            "SELECT psr.*, ps.action_type FROM playbook_step_runs psr JOIN playbook_steps ps ON ps.id = psr.step_id WHERE psr.run_id = ? AND psr.status = 'succeeded' ORDER BY ps.position DESC",
            (run_id,),
        )
        .fetchall()
    )
    with transaction():
        for step in steps:
            output = json.loads(step["output"] or "{}")
            before = output.get("before", {})
            if isinstance(before, dict) and {"entity_type", "entity_id", "state"}.issubset(before):
                get_db().execute(
                    "UPDATE response_simulation_state SET state = ?, updated_at = ? WHERE workspace_id = ? AND training_run_id IS ? AND entity_type = ? AND entity_id = ?",
                    (before["state"], iso_now(), run["workspace_id"], run["training_run_id"], before["entity_type"], before["entity_id"]),
                )
            get_db().execute("UPDATE playbook_step_runs SET status = 'rolled_back', completed_at = ? WHERE id = ?", (iso_now(), step["id"]))
        get_db().execute("UPDATE playbook_runs SET state = 'rolled_back', updated_at = ? WHERE id = ?", (iso_now(), run_id))
        record_audit(get_db(), "rollback", "playbook_run", run_id)
    return jsonify({"id": run_id, "state": "rolled_back"})


def _run_view(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    steps = (
        get_db()
        .execute(
            "SELECT psr.id, ps.position, ps.action_type, ps.approval_role, psr.status, psr.attempt, psr.output, psr.impact, psr.error, psr.started_at, psr.completed_at FROM playbook_step_runs psr JOIN playbook_steps ps ON ps.id = psr.step_id WHERE psr.run_id = ? ORDER BY ps.position",
            (row["id"],),
        )
        .fetchall()
    )
    item["steps"] = []
    for step in steps:
        value = dict(step)
        for field in ("output", "impact"):
            value[field] = json.loads(value[field]) if value[field] else None
        item["steps"].append(value)
    return item


@playbooks_api.get("/api/playbook-runs/<int:run_id>")
@require_permission("playbooks.request")
def run_detail(run_id: int):
    row = _run_access(run_id)
    if not row:
        return error_response("PLAYBOOK_RUN_NOT_FOUND", "تشغيل الاستجابة غير موجود", 404)
    return jsonify(_run_view(row))


def _run_access(run_id: int) -> sqlite3.Row | None:
    row = get_db().execute("SELECT * FROM playbook_runs WHERE id = ? AND workspace_id = ?", (run_id, workspace_id())).fetchone()
    if not row or not can_access_training_run(row["training_run_id"]):
        return None
    return row if row["requested_by"] == actor_id() or require_manager_access() else None


def require_manager_access() -> bool:
    from .security import current_user, has_permission

    return has_permission(current_user(), "playbooks.approve")
