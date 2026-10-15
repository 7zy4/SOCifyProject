"""Incident/case management API for the phase-one SOC workflow."""
from functools import wraps
import sqlite3
from flask import Blueprint, current_app, jsonify, request, session

incidents_api = Blueprint("incidents_api", __name__)


def conn():
    db = sqlite3.connect(current_app.config["DATABASE"])
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def authenticated(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        with conn() as db:
            active = db.execute("SELECT 1 FROM users WHERE id = ? AND is_active = 1",
                                (session["user_id"],)).fetchone()
            if not active:
                return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return inner


def valid_assignee(db, user_id):
    return user_id is None or (type(user_id) is int and db.execute(
        "SELECT 1 FROM users WHERE id = ? AND is_active = 1", (user_id,)
    ).fetchone() is not None)


def audit(db, action, incident_id):
    db.execute("""INSERT INTO audit_logs (user_id, action, table_name, record_id,
                   ip_address, user_agent) VALUES (?, ?, 'incidents', ?, ?, ?)""",
               (session["user_id"], action, incident_id, request.remote_addr,
                request.headers.get("User-Agent")))


@incidents_api.route("/api/incidents", methods=["GET"])
@authenticated
def list_cases():
    with conn() as db:
        cases = db.execute("""SELECT i.*, u.name AS assigned_to_name,
                    (SELECT COUNT(*) FROM incident_events ie
                     WHERE ie.incident_id = i.id) AS event_count
                    FROM incidents i LEFT JOIN users u ON u.id = i.assigned_to
                    ORDER BY i.updated_at DESC, i.id DESC LIMIT 200""").fetchall()
        return jsonify([dict(row) for row in cases])


@incidents_api.route("/api/incidents", methods=["POST"])
@authenticated
def new_case():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400
    title = data.get("title")
    if not isinstance(title, str) or not 1 <= len(title.strip()) <= 255:
        return jsonify({"error": "Title required (1-255 characters)"}), 400
    severity = data.get("severity", "medium")
    if severity not in ("critical", "high", "medium", "low"):
        return jsonify({"error": "Invalid severity"}), 400
    event_ids = data.get("event_ids", [])
    if (not isinstance(event_ids, list) or len(event_ids) > 100
            or any(type(x) is not int for x in event_ids)):
        return jsonify({"error": "Invalid event_ids"}), 400
    with conn() as db:
        if not valid_assignee(db, data.get("assigned_to")):
            return jsonify({"error": "Unknown assignee"}), 400
        for eid in set(event_ids):
            if not db.execute("SELECT 1 FROM security_events WHERE id = ?", (eid,)).fetchone():
                return jsonify({"error": f"Event {eid} not found"}), 400
        cursor = db.execute("""INSERT INTO incidents
            (title, description, severity, assigned_to, created_by)
            VALUES (?, ?, ?, ?, ?)""",
            (title.strip(), str(data.get("description") or ""), severity,
             data.get("assigned_to"), session["user_id"]))
        case_id = cursor.lastrowid
        for eid in set(event_ids):
            db.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                       (case_id, eid))
        audit(db, "create", case_id)
        db.commit()
        return jsonify({"id": case_id, "message": "Incident created"}), 201


@incidents_api.route("/api/incidents/<int:case_id>", methods=["GET"])
@authenticated
def case_details(case_id):
    with conn() as db:
        case = db.execute("SELECT * FROM incidents WHERE id = ?", (case_id,)).fetchone()
        if not case:
            return jsonify({"error": "Not found"}), 404
        events = db.execute("""SELECT e.* FROM security_events e
            JOIN incident_events ie ON ie.event_id = e.id WHERE ie.incident_id = ?""",
            (case_id,)).fetchall()
        notes = db.execute("""SELECT n.*, u.name AS author FROM incident_notes n
            JOIN users u ON u.id = n.user_id
            WHERE n.incident_id = ? ORDER BY n.id""", (case_id,)).fetchall()
        return jsonify({"incident": dict(case),
                        "events": [dict(x) for x in events],
                        "notes": [dict(x) for x in notes]})


@incidents_api.route("/api/incidents/<int:case_id>", methods=["PATCH"])
@authenticated
def update_case(case_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400
    fields = {k: v for k, v in data.items() if k in
              ("title", "description", "severity", "status", "assigned_to")}
    if not fields:
        return jsonify({"error": "No valid changes"}), 400
    if ("severity" in fields and fields["severity"] not in
            ("critical", "high", "medium", "low")):
        return jsonify({"error": "Invalid severity"}), 400
    if ("status" in fields and fields["status"] not in
            ("open", "investigating", "resolved", "false_positive")):
        return jsonify({"error": "Invalid status"}), 400
    if "title" in fields and (not isinstance(fields["title"], str)
            or not 1 <= len(fields["title"].strip()) <= 255):
        return jsonify({"error": "Invalid title"}), 400
    if "description" in fields and not isinstance(fields["description"], str):
        return jsonify({"error": "Invalid description"}), 400
    with conn() as db:
        if not db.execute("SELECT 1 FROM incidents WHERE id = ?", (case_id,)).fetchone():
            return jsonify({"error": "Not found"}), 404
        if "assigned_to" in fields and not valid_assignee(db, fields["assigned_to"]):
            return jsonify({"error": "Unknown assignee"}), 400
        fields["updated_at"] = "now"
        updates = {k: v for k, v in fields.items() if k != "updated_at"}
        db.execute("UPDATE incidents SET " + ", ".join(k + " = ?" for k in updates) +
                   ", updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                   (*updates.values(), case_id))
        audit(db, "update", case_id)
        db.commit()
        return jsonify({"message": "Incident updated"})


@incidents_api.route("/api/incidents/<int:case_id>/notes", methods=["POST"])
@authenticated
def add_note(case_id):
    data = request.get_json(silent=True)
    note = data.get("note") if isinstance(data, dict) else None
    if not isinstance(note, str) or not 1 <= len(note.strip()) <= 10000:
        return jsonify({"error": "Note required (1-10000 characters)"}), 400
    with conn() as db:
        if not db.execute("SELECT 1 FROM incidents WHERE id = ?", (case_id,)).fetchone():
            return jsonify({"error": "Not found"}), 404
        db.execute("INSERT INTO incident_notes (incident_id, user_id, note) VALUES (?, ?, ?)",
                   (case_id, session["user_id"], note.strip()))
        db.execute("UPDATE incidents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                   (case_id,))
        audit(db, "note", case_id)
        db.commit()
        return jsonify({"message": "Note added"}), 201


@incidents_api.route("/api/incidents/<int:case_id>/events", methods=["POST"])
@authenticated
def add_event(case_id):
    data = request.get_json(silent=True)
    event_id = data.get("event_id") if isinstance(data, dict) else None
    if type(event_id) is not int:
        return jsonify({"error": "Numeric event_id required"}), 400
    with conn() as db:
        if not db.execute("SELECT 1 FROM incidents WHERE id = ?", (case_id,)).fetchone():
            return jsonify({"error": "Not found"}), 404
        if not db.execute("SELECT 1 FROM security_events WHERE id = ?", (event_id,)).fetchone():
            return jsonify({"error": "Event not found"}), 404
        db.execute("INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                   (case_id, event_id))
        db.execute("UPDATE incidents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                   (case_id,))
        audit(db, "attach_event", case_id)
        db.commit()
        return jsonify({"message": "Event attached"})
