"""Evaluate supported detection rules when a security event is ingested.

Rules operate only on stored, simulated security events. No attack traffic is sent.
Each rule/event pair is recorded once in detection_matches, preventing duplicate alerts.
"""
import datetime as dt
import json
import re
import uuid

VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _json_object(value):
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


def _time_delta(value):
    match = re.fullmatch(r"([1-9][0-9]*)([smh])", str(value or "10m"))
    if not match:
        return dt.timedelta(minutes=10)
    seconds = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    return dt.timedelta(seconds=min(seconds, 86400))


def _identity(event):
    data = _json_object(event["raw_data"])
    return (str(data.get("source_ip") or data.get("src_ip") or data.get("ip")
                or event["source"]), str(data.get("username") or ""))


def _failed_login(event):
    category = (event["category"] or "").lower().replace("_", " ")
    data = _json_object(event["raw_data"])
    return (
        data.get("event_type") == "failed_login"
        or category in ("failed login", "failed logins", "brute force")
        or (category in ("authentication", "auth") and
            ("fail" in (event["title"] or "").lower()
             or data.get("success") is False))
    )


def _match(conn, rule, event):
    kind = rule["condition_type"]
    condition = _json_object(rule["condition_value"])
    data = _json_object(event["raw_data"])
    if kind == "failed_login_count":
        if not _failed_login(event):
            return None
        try:
            threshold = int(condition.get("threshold", 5))
        except (ValueError, TypeError):
            return None
        if not 1 <= threshold <= 10000:
            return None
        cutoff = (dt.datetime.now(dt.timezone.utc) -
                  _time_delta(condition.get("timeframe", "10m"))).strftime("%Y-%m-%d %H:%M:%S")
        candidates = conn.execute("""
            SELECT * FROM security_events
            WHERE timestamp >= ? AND id <= ? AND source != 'rules_engine'
            ORDER BY id DESC
        """, (cutoff, event["id"])).fetchall()
        target = _identity(event)
        count = sum(1 for item in candidates
                    if _failed_login(item) and _identity(item) == target)
        if count >= threshold:
            return f"{count} failed login events from {target[0]} in {condition.get('timeframe', '10m')}"
    elif kind == "network_anomaly":
        try:
            score = float(data.get("anomaly_score"))
            threshold = float(condition.get("threshold", 0.8))
        except (TypeError, ValueError):
            return None
        if 0 <= threshold <= 1 and score >= threshold:
            return f"Network anomaly score {score} >= {threshold}"
    elif kind == "error_level":
        required = str(condition.get("level", "critical")).lower()
        level = str(data.get("level", "")).lower()
        if level and level == required:
            return f"System error level matched: {level}"
    return None


def evaluate_rules(conn, event_id):
    """Create detection alerts in the caller's transaction; returns alert database IDs."""
    event = conn.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
    if not event or event["source"] == "rules_engine":
        return []
    alerts = []
    rules = conn.execute("SELECT * FROM rules WHERE is_active = 1").fetchall()
    for rule in rules:
        if rule["action_type"] != "create_event":
            continue
        if conn.execute("SELECT 1 FROM detection_matches WHERE rule_id = ? AND event_id = ?",
                        (rule["id"], event_id)).fetchone():
            continue
        reason = _match(conn, rule, event)
        if not reason:
            continue
        action = _json_object(rule["action_value"])
        severity = action.get("severity", "medium")
        if severity not in VALID_SEVERITIES:
            severity = "medium"
        metadata = json.dumps({"rule_id": rule["id"], "origin_event_id": event_id,
                               "reason": reason}, ensure_ascii=False)
        cursor = conn.execute("""
            INSERT INTO security_events
                (event_id, source, severity, category, title, description, raw_data, created_by)
            VALUES (?, 'rules_engine', ?, ?, ?, ?, ?, ?)
        """, (f"DET-{uuid.uuid4().hex[:8].upper()}", severity,
              str(action.get("category", "detection"))[:100],
              f"Detection: {rule['name']}"[:255], reason, metadata, event["created_by"]))
        alert_id = cursor.lastrowid
        conn.execute("""
            INSERT INTO detection_matches (rule_id, event_id, alert_event_id)
            VALUES (?, ?, ?)
        """, (rule["id"], event_id, alert_id))
        alerts.append(alert_id)
    return alerts
