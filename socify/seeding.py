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
    cursor = connection.execute("INSERT INTO users (email, password_hash, name, role, team, workspace_id, created_at, password_changed_at, is_active) VALUES (?, ?, ?, ?, ?, 1, ?, ?, 1)", (email, password_hash, name, role, team, iso_now(), iso_now()))
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
    cursor = connection.execute("INSERT INTO rules (name, description, condition_type, condition_value, dsl_json, action_type, action_value, is_active, version, deployment_state, workspace_id, created_by, deployed_by, created_at, updated_at) VALUES (?, ?, 'dsl', ?, ?, 'create_alert', ?, 1, 1, 'published', 1, ?, ?, ?, ?)", (name, description, dsl_json, dsl_json, action_json, creator, creator, now, now))
    rule_id = inserted_id(cursor)
    connection.execute("INSERT INTO rule_versions (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at) VALUES (?, 1, ?, ?, 'Initial demo publication', ?, ?)", (rule_id, dsl_json, action_json, creator, now))
    return rule_id


def _seed_rules(connection: sqlite3.Connection, creator: int) -> None:
    _rule(connection, creator, "Five failed logins in ten minutes", "Detect five failed logins from the same source IP within event time.", {"condition": {"field": "event_type", "operator": "equals", "value": "failed_login"}, "window": {"seconds": 600, "threshold": 5, "group_by": ["source_ip"], "mode": "count", "allowed_lateness_seconds": 86400}, "mitre_ids": ["T1110"]}, {"severity": "high", "confidence": 0.95})
    _rule(connection, creator, "High anomaly score", "Detect normalized anomaly scores at or above 0.8.", {"condition": {"field": "anomaly_score", "operator": "gte", "value": 0.8}, "mitre_ids": []}, {"severity": "high", "confidence": 0.8})
    _rule(connection, creator, "Critical system error", "Detect critical system events.", {"condition": {"logic": "and", "conditions": [{"field": "category", "operator": "equals", "value": "system"}, {"field": "severity", "operator": "equals", "value": "critical"}]}, "mitre_ids": []}, {"severity": "critical", "confidence": 0.9})
    _rule(connection, creator, "Burst web requests", "Detect a burst of twenty web requests from one source in one minute.", {"condition": {"field": "event_type", "operator": "equals", "value": "web_request"}, "window": {"seconds": 60, "threshold": 20, "group_by": ["source_ip"], "mode": "count"}, "mitre_ids": []}, {"severity": "medium", "confidence": 0.75})
    _rule(connection, creator, "Suspicious office child process", "Detect an ordered office-to-script-interpreter process sequence.", {"condition": {"field": "event_type", "operator": "exists", "value": True}, "sequence": [{"field": "process_name", "operator": "ends_with", "value": "winword.exe"}, {"field": "process_name", "operator": "ends_with", "value": "powershell.exe"}], "window": {"seconds": 300, "threshold": 2, "group_by": ["hostname"], "mode": "count"}, "mitre_ids": ["T1059"]}, {"severity": "high", "confidence": 0.9})
    _rule(connection, creator, "Phishing followed by credential misuse", "Correlate a simulated phishing event with a failed login for the same user.", {"condition": {"field": "event_type", "operator": "exists", "value": True}, "sequence": [{"field": "event_type", "operator": "equals", "value": "phishing_email"}, {"field": "event_type", "operator": "equals", "value": "failed_login"}], "window": {"seconds": 1800, "threshold": 2, "group_by": ["username"], "mode": "count"}, "mitre_ids": ["T1566.001", "T1078"]}, {"severity": "critical", "confidence": 0.9})


def _seed_scenario(connection: sqlite3.Connection, creator: int) -> None:
    if connection.execute("SELECT 1 FROM attack_scenarios WHERE scenario_id = 'SCN-REFERENCE-CHAIN'").fetchone():
        return
    now = iso_now()
    cursor = connection.execute("INSERT INTO attack_scenarios (scenario_id, workspace_id, name, description, active_version, state, visibility, created_by, created_at, updated_at) VALUES ('SCN-REFERENCE-CHAIN', 1, 'سلسلة التصيد وسوء استخدام الاعتماد', 'سيناريو اصطناعي معزول من ست مراحل يربط التصيد بالوصول والبحث والتجميع والتسريب المحاكى.', 1, 'ready', 'workspace', ?, ?, ?)", (creator, now, now))
    scenario_id = inserted_id(cursor)
    scoring = {"detection": 25, "investigation": 25, "response": 20, "evidence": 15, "time": 10, "false_positive": 5}
    version_cursor = connection.execute("INSERT INTO scenario_versions (scenario_id, version, objectives, roles, difficulty, duration_minutes, environment, scoring_policy, created_by, created_at) VALUES (?, 1, ?, ?, 'beginner', 30, ?, ?, ?, ?)", (scenario_id, json.dumps(["تمييز مؤشرات التصيد", "ربط محاولات الدخول", "جمع الأدلة", "تنفيذ احتواء افتراضي"], ensure_ascii=False), json.dumps(["analyst"]), json.dumps({"mode": "isolated_training", "network": "none"}), json.dumps(scoring), creator, now))
    version_id = inserted_id(version_cursor)
    steps = [
        ("phishing", 1, "رسالة تصيد محاكاة", {"source": "scenario-email", "source_type": "training", "severity": "medium", "category": "email", "event_type": "phishing_email", "title": "Suspicious training attachment", "description": "Synthetic attachment from phish-training.test", "username": "amina", "raw_payload": {"sender": "billing@phish-training.test", "attachment": "invoice-training.docm", "synthetic": True}}, ["T1566.001"], "افحص المرسل والمرفق واربطهما بالمستخدم المستهدف.", ["phishing-correlation"], ["sender", "attachment"], []),
        ("credential-access", 2, "وصول إلى بيانات اعتماد محاكاة", {"source": "scenario-endpoint", "source_type": "training", "severity": "high", "category": "credential_access", "event_type": "credential_store_access", "title": "Synthetic credential store access", "description": "Training process accessed a synthetic credential store", "username": "amina", "hostname": "ws-training-01", "process_name": "winword.exe", "raw_payload": {"synthetic": True}}, ["T1555"], "راجع العملية والأصل الذي سبق نشاط بيانات الاعتماد.", [], ["hostname", "process_name"], []),
        ("unauthorized-login", 3, "محاولات دخول غير مصرح بها", {"repeat": 5, "source": "scenario-auth", "source_type": "training", "severity": "high", "category": "authentication", "event_type": "failed_login", "title": "Failed synthetic login", "description": "Repeated failed login in the isolated exercise", "source_ip": "198.51.100.20", "username": "amina", "hostname": "idp-training-01", "action": "login", "outcome": "failed", "raw_payload": {"action": "login", "outcome": "failed", "synthetic": True}}, ["T1110", "T1078"], "ابحث عن خمس محاولات من المصدر نفسه ضمن نافذة عشر دقائق.", ["Five failed logins in ten minutes"], ["source_ip", "username"], []),
        ("discovery", 4, "نشاط اكتشاف الصلاحيات", {"source": "scenario-endpoint", "source_type": "training", "severity": "high", "category": "discovery", "event_type": "account_discovery", "title": "Synthetic account discovery", "description": "PowerShell queried local training accounts", "username": "amina", "hostname": "ws-training-01", "process_name": "powershell.exe", "parent_process": "winword.exe", "raw_payload": {"command": "Get-LocalUser", "synthetic": True}}, ["T1087", "T1059"], "قارن علاقة العملية الأب بالعملية الابنة.", ["Suspicious office child process"], ["process_name", "parent_process"], []),
        ("data-access", 5, "وصول إلى بيانات تدريبية حساسة", {"source": "scenario-file", "source_type": "training", "severity": "high", "category": "collection", "event_type": "sensitive_data_access", "title": "Synthetic sensitive data access", "description": "Training-only records were collected", "username": "amina", "hostname": "file-training-01", "file_hash": "4f924d4c93f21f54b586a8f9b0c9b79249659b4401e4548d4bf48c4cce1e7a15", "raw_payload": {"path": "/training/finance/records.csv", "synthetic": True}}, ["T1005"], "أضف السجل وهاش الملف إلى حافظة الأدلة.", [], ["file_hash"], []),
        ("exfiltration", 6, "تسريب محاكى داخل المختبر", {"source": "scenario-network", "source_type": "training", "severity": "critical", "category": "exfiltration", "event_type": "simulated_exfiltration", "title": "Contained synthetic exfiltration", "description": "Training data moved to a documentation-range endpoint", "source_ip": "192.0.2.44", "destination_ip": "203.0.113.50", "hostname": "file-training-01", "raw_payload": {"bytes": 5242880, "synthetic": True, "external_connection": False}}, ["T1041"], "نفذ خطة الاحتواء الافتراضية وسجل القرار.", [], ["destination_ip"], ["contain_simulated_exfiltration"]),
    ]
    for step_id, position, name, event, mitre_ids, hint, expected, evidence, responses in steps:
        connection.execute("INSERT INTO scenario_steps (scenario_version_id, step_id, position, name, event_template, artifact, mitre_ids, visible_hint) VALUES (?, ?, ?, ?, ?, '{}', ?, ?)", (version_id, step_id, position, name, json.dumps(event, ensure_ascii=False), json.dumps(mitre_ids), hint))
        connection.execute("INSERT INTO scenario_ground_truth (scenario_version_id, step_id, expected_detections, relevant_evidence, allowed_responses, score_weight) VALUES (?, ?, ?, ?, ?, 1)", (version_id, step_id, json.dumps(expected), json.dumps(evidence), json.dumps(responses)))


def _seed_playbook(connection: sqlite3.Connection, creator: int) -> None:
    if connection.execute("SELECT 1 FROM playbooks WHERE playbook_id = 'PB-CONTAIN-EXFIL'").fetchone():
        return
    now = iso_now()
    cursor = connection.execute("INSERT INTO playbooks (playbook_id, workspace_id, name, description, active_version, state, created_by, created_at, updated_at) VALUES ('PB-CONTAIN-EXFIL', 1, 'احتواء تسريب افتراضي', 'خطة استجابة تدريبية تغيّر حالة المختبر فقط ولا تتصل بأي جهاز أو شبكة خارجية.', 1, 'published', ?, ?, ?)", (creator, now, now))
    playbook_id = inserted_id(cursor)
    version_cursor = connection.execute("INSERT INTO playbook_versions (playbook_id, version, trigger_type, preconditions, expected_outcome, created_by, created_at) VALUES (?, 1, 'manual', ?, ?, ?, ?)", (playbook_id, json.dumps({"case_required": True, "training_run_required": True}), json.dumps({"host": "isolated", "exfiltration": "contained", "evidence": "collected"}), creator, now))
    version_id = inserted_id(version_cursor)
    steps = [
        (1, "isolate_virtual_host", {"host": "file-training-01"}, "soc_manager", "restore_virtual_service"),
        (2, "collect_evidence", {}, None, None),
        (3, "contain_simulated_exfiltration", {"channel": "training-exfil-channel"}, None, "restore_virtual_service"),
        (4, "notify_training_team", {"message": "تم احتواء التسريب المحاكى"}, None, None),
    ]
    for position, action, parameters, approval, compensation in steps:
        connection.execute("INSERT INTO playbook_steps (playbook_version_id, position, action_type, parameters, approval_role, timeout_seconds, retry_limit, compensation_action) VALUES (?, ?, ?, ?, ?, 30, 2, ?)", (version_id, position, action, json.dumps(parameters, ensure_ascii=False), approval, compensation))


def _seed_iocs(connection: sqlite3.Connection) -> None:
    now = iso_now()
    rows = [("ip", "198.51.100.20", 0.92, "Synthetic credential attack source"), ("ip", "203.0.113.50", 0.88, "Synthetic exfiltration destination"), ("domain", "phish-training.test", 1.0, "Reserved synthetic phishing domain")]
    for ioc_type, value, confidence, context in rows:
        connection.execute("INSERT OR IGNORE INTO ioc_indicators (workspace_id, type, value, first_seen, last_seen, confidence, source, context, tags) VALUES (1, ?, ?, ?, ?, ?, 'SOCify synthetic fixtures', ?, '[\"training\",\"synthetic\"]')", (ioc_type, value, now, now, confidence, json.dumps({"reason": context, "synthetic": True})))


def seed_demo_data(connection: sqlite3.Connection, password: str) -> dict[str, str]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        users = {email: _user(connection, email, name, role, team, password) for email, name, role, team in DEMO_USERS}
        creator = users["admin@socify.local"]
        _seed_rules(connection, creator)
        _seed_scenario(connection, creator)
        _seed_playbook(connection, creator)
        _seed_iocs(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {email: password for email, _, _, _ in DEMO_USERS}
