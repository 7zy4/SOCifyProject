import json
import sqlite3
from typing import Any

import bcrypt

from .db import inserted_id
from .timeutils import iso_now

DEMO_USERS = [
    ("admin@socify.local", "مدير النظام", "admin", "إدارة المنصة"),
    ("manager@socify.local", "مدير مركز العمليات", "soc_manager", "فريق SOC"),
    ("analyst@socify.local", "محلل التدريب", "analyst", "فريق SOC"),
    ("instructor@socify.local", "مدرب SOCify", "instructor", "التدريب"),
    ("auditor@socify.local", "مراجع القراءة", "auditor", "التدقيق"),
]


def _user(connection: sqlite3.Connection, email: str, name: str, role: str, team: str, password: str) -> int:
    existing = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return int(existing["id"])
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    cursor = connection.execute(
        "INSERT INTO users (email, password_hash, name, role, team, workspace_id, created_at, password_changed_at, is_active) VALUES (?, ?, ?, ?, ?, 1, ?, ?, 1)",
        (email, password_hash, name, role, team, iso_now(), iso_now()),
    )
    user_id = inserted_id(cursor)
    connection.execute("INSERT OR IGNORE INTO workspace_memberships (workspace_id, user_id, role, created_at) VALUES (1, ?, ?, ?)", (user_id, role, iso_now()))
    return user_id


def _rule(connection: sqlite3.Connection, creator: int, name: str, description: str, dsl: dict[str, Any], action: dict[str, Any]) -> int:
    existing = connection.execute("SELECT id FROM rules WHERE workspace_id = 1 AND name = ? AND archived_at IS NULL", (name,)).fetchone()
    if existing:
        return int(existing["id"])
    now = iso_now()
    dsl_json = json.dumps(dsl, separators=(",", ":"))
    action_json = json.dumps(action, separators=(",", ":"))
    cursor = connection.execute(
        "INSERT INTO rules (name, description, condition_type, condition_value, dsl_json, action_type, action_value, is_active, version, deployment_state, workspace_id, created_by, deployed_by, created_at, updated_at) VALUES (?, ?, 'dsl', ?, ?, 'create_alert', ?, 1, 1, 'published', 1, ?, ?, ?, ?)",
        (name, description, dsl_json, dsl_json, action_json, creator, creator, now, now),
    )
    rule_id = inserted_id(cursor)
    connection.execute(
        "INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at) VALUES (?, 1, ?, ?, 'Initial demo publication', ?, ?)",
        (rule_id, dsl_json, action_json, creator, now),
    )
    return rule_id


def _seed_rules(connection: sqlite3.Connection, creator: int) -> None:
    from .builtin_rules import seed_builtin_rules

    seed_builtin_rules(connection)
    _rule(
        connection,
        creator,
        "Five failed logins in ten minutes",
        "Detect five failed logins from the same source IP within event time.",
        {
            "condition": {"field": "event_type", "operator": "equals", "value": "failed_login"},
            "window": {"seconds": 600, "threshold": 5, "group_by": ["source_ip"], "mode": "count", "allowed_lateness_seconds": 86400},
            "mitre_ids": ["T1110"],
        },
        {"severity": "high", "confidence": 0.95},
    )
    _rule(
        connection,
        creator,
        "High anomaly score",
        "Detect normalized anomaly scores at or above 0.8.",
        {"condition": {"field": "anomaly_score", "operator": "gte", "value": 0.8}, "mitre_ids": []},
        {"severity": "high", "confidence": 0.8},
    )
    _rule(
        connection,
        creator,
        "Critical system error",
        "Detect critical system events.",
        {
            "condition": {
                "logic": "and",
                "conditions": [
                    {"field": "category", "operator": "equals", "value": "system"},
                    {"field": "severity", "operator": "equals", "value": "critical"},
                ],
            },
            "mitre_ids": [],
        },
        {"severity": "critical", "confidence": 0.9},
    )
    _rule(
        connection,
        creator,
        "Burst web requests",
        "Detect a burst of twenty web requests from one source in one minute.",
        {
            "condition": {"field": "event_type", "operator": "equals", "value": "web_request"},
            "window": {"seconds": 60, "threshold": 20, "group_by": ["source_ip"], "mode": "count"},
            "mitre_ids": [],
        },
        {"severity": "medium", "confidence": 0.75},
    )
    _rule(
        connection,
        creator,
        "Suspicious office child process",
        "Detect an ordered office-to-script-interpreter process sequence.",
        {
            "condition": {"field": "event_type", "operator": "exists", "value": True},
            "sequence": [
                {"field": "process_name", "operator": "ends_with", "value": "winword.exe"},
                {"field": "process_name", "operator": "ends_with", "value": "powershell.exe"},
            ],
            "window": {"seconds": 300, "threshold": 2, "group_by": ["hostname"], "mode": "count"},
            "mitre_ids": ["T1059"],
        },
        {"severity": "high", "confidence": 0.9},
    )
    _rule(
        connection,
        creator,
        "Phishing followed by credential misuse",
        "Correlate a simulated phishing event with a failed login for the same user.",
        {
            "condition": {"field": "event_type", "operator": "exists", "value": True},
            "sequence": [
                {"field": "event_type", "operator": "equals", "value": "phishing_email"},
                {"field": "event_type", "operator": "equals", "value": "failed_login"},
            ],
            "window": {"seconds": 1800, "threshold": 2, "group_by": ["username"], "mode": "count"},
            "mitre_ids": ["T1566.001", "T1078"],
        },
        {"severity": "critical", "confidence": 0.9},
    )


def _seed_iocs(connection: sqlite3.Connection) -> None:
    now = iso_now()
    rows = [
        ("ip", "198.51.100.20", 0.92, "Synthetic credential attack source"),
        ("ip", "203.0.113.50", 0.88, "Synthetic exfiltration destination"),
        ("domain", "phish-training.test", 1.0, "Reserved synthetic phishing domain"),
    ]
    for ioc_type, value, confidence, context in rows:
        connection.execute(
            "INSERT OR IGNORE INTO ioc_indicators (workspace_id, type, value, first_seen, last_seen, confidence, source, context, tags) VALUES (1, ?, ?, ?, ?, ?, 'SOCify synthetic fixtures', ?, '[\"training\",\"synthetic\"]')",
            (ioc_type, value, now, now, confidence, json.dumps({"reason": context, "synthetic": True})),
        )


def seed_demo_data(connection: sqlite3.Connection, password: str) -> dict[str, str]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        users = {email: _user(connection, email, name, role, team, password) for email, name, role, team in DEMO_USERS}
        creator = users["admin@socify.local"]
        _seed_rules(connection, creator)
        _seed_iocs(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {email: password for email, _, _, _ in DEMO_USERS}
