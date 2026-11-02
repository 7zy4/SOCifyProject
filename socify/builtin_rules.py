"""Built-in SOCify tactical detection rule pack auto-seeded into every workspace."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from .db import inserted_id
from .timeutils import iso_now

BUILTIN_RULES: tuple[dict[str, Any], ...] = (
    *(
        {
            "name": f"[SOCify] Snort {severity.title()} Alert",
            "description": "A retained Snort network alert matches the recorded priority.",
            "severity": severity,
            "confidence": 0.80,
            "dsl": {
                "condition": {
                    "logic": "and",
                    "conditions": [
                        {"field": "source_type", "operator": "equals", "value": "snort"},
                        {"field": "event_type", "operator": "equals", "value": "snort_alert"},
                        {"field": "severity", "operator": "equals", "value": severity},
                    ],
                },
                "mitre_ids": [],
            },
        }
        for severity in ("high", "medium", "low")
    ),
    *(
        {
            "name": f"[SOCify] {severity.title()} Runtime Security Alert",
            "description": "A retained runtime sensor alert matches the recorded severity and rule.",
            "severity": severity,
            "confidence": 0.80,
            "dsl": {
                "condition": {
                    "logic": "and",
                    "conditions": [
                        {"field": "source_type", "operator": "equals", "value": "falco"},
                        {"field": "event_type", "operator": "equals", "value": "runtime_alert"},
                        {"field": "severity", "operator": "equals", "value": severity},
                    ],
                },
                "mitre_ids": [],
            },
        }
        for severity in ("critical", "high", "medium", "low")
    ),
    *(
        {
            "name": f"[SOCify] Suricata {severity.title()} Signature",
            "description": "A retained Suricata EVE alert contains a signature and the corresponding IDS severity.",
            "severity": severity,
            "confidence": 0.80,
            "dsl": {
                "condition": {
                    "logic": "and",
                    "conditions": [
                        {"field": "event_type", "operator": "equals", "value": "suricata_alert"},
                        {"field": "ids_severity", "operator": "equals", "value": priority},
                        {"field": "ids_signature", "operator": "exists", "value": True},
                    ],
                },
                "mitre_ids": [],
            },
        }
        for priority, severity in ((1, "high"), (2, "medium"), (3, "low"))
    ),
    {
        "name": "[SOCify] Exposed Credential Material",
        "description": "Credential assignments, bearer tokens or private key markers found in retained event text.",
        "severity": "high",
        "confidence": 0.80,
        "dsl": {"condition": {"field": "exposed_secret_count", "operator": "gt", "value": 0}, "mitre_ids": []},
    },
    {
        "name": "[SOCify] Sensitive Financial Data Exposure",
        "description": "Payment card or IBAN checksum matches found in retained event text; not an exfiltration verdict.",
        "severity": "medium",
        "confidence": 0.80,
        "dsl": {"condition": {"field": "sensitive_data_count", "operator": "gt", "value": 0}, "mitre_ids": []},
    },
    {
        "name": "[SOCify] Suspicious Decoded Content",
        "description": "Decoded text matches a command, credential-dumping, recovery-tampering or sensitive-path detection pattern.",
        "severity": "high",
        "confidence": 0.85,
        "dsl": {"condition": {"field": "decoded_threat_count", "operator": "gt", "value": 0}, "mitre_ids": ["T1027"]},
    },
    {
        "name": "[SOCify] Brute Force Authentication Burst",
        "description": "Detect 5 or more failed authentication attempts from the same source IP within 10 minutes.",
        "severity": "high",
        "confidence": 0.92,
        "dsl": {
            "condition": {"field": "event_type", "operator": "equals", "value": "failed_login"},
            "window": {"seconds": 600, "threshold": 5, "group_by": ["source_ip"], "mode": "count", "allowed_lateness_seconds": 86400},
            "mitre_ids": ["T1110"],
        },
    },
    {
        "name": "[SOCify] Password Spraying Across Accounts",
        "description": "Detect failed logins targeting 4 or more distinct usernames from one source IP within 15 minutes.",
        "severity": "high",
        "confidence": 0.90,
        "dsl": {
            "condition": {"field": "event_type", "operator": "equals", "value": "failed_login"},
            "window": {
                "seconds": 900,
                "threshold": 4,
                "group_by": ["source_ip"],
                "mode": "distinct_count",
                "distinct_field": "username",
                "allowed_lateness_seconds": 86400,
            },
            "mitre_ids": ["T1110.003"],
        },
    },
    {
        "name": "[SOCify] Suspicious Encoded or Download-Cradle PowerShell",
        "description": "Detect PowerShell invocations using encoded commands or remote download cradles.",
        "severity": "high",
        "confidence": 0.91,
        "dsl": {
            "condition": {
                "logic": "and",
                "conditions": [
                    {
                        "logic": "or",
                        "conditions": [
                            {"field": "process_name", "operator": "contains", "value": "powershell"},
                            {"field": "process_name", "operator": "contains", "value": "pwsh"},
                            {"field": "command_line", "operator": "contains", "value": "powershell"},
                        ],
                    },
                    {
                        "logic": "or",
                        "conditions": [
                            {"field": "command_line", "operator": "contains", "value": "-enc"},
                            {"field": "command_line", "operator": "contains", "value": "frombase64string"},
                            {"field": "command_line", "operator": "contains", "value": "downloadstring"},
                            {"field": "command_line", "operator": "contains", "value": "invoke-webrequest"},
                            {"field": "description", "operator": "contains", "value": "-enc "},
                            {"field": "description", "operator": "contains", "value": "downloadstring"},
                            {"field": "description", "operator": "contains", "value": "frombase64string"},
                        ],
                    },
                ],
            },
            "mitre_ids": ["T1059.001"],
        },
    },
    {
        "name": "[SOCify] Office Application Spawning Shell or Script",
        "description": "Detect Microsoft Office processes spawning command shells, PowerShell, or script engines.",
        "severity": "critical",
        "confidence": 0.95,
        "dsl": {
            "condition": {
                "logic": "and",
                "conditions": [
                    {
                        "logic": "or",
                        "conditions": [
                            {"field": "parent_process", "operator": "contains", "value": "winword.exe"},
                            {"field": "parent_process", "operator": "contains", "value": "excel.exe"},
                            {"field": "parent_process", "operator": "contains", "value": "powerpnt.exe"},
                            {"field": "parent_process", "operator": "contains", "value": "outlook.exe"},
                        ],
                    },
                    {
                        "logic": "or",
                        "conditions": [
                            {"field": "process_name", "operator": "contains", "value": "cmd.exe"},
                            {"field": "process_name", "operator": "contains", "value": "powershell"},
                            {"field": "process_name", "operator": "contains", "value": "pwsh"},
                            {"field": "process_name", "operator": "contains", "value": "wscript.exe"},
                            {"field": "process_name", "operator": "contains", "value": "cscript.exe"},
                            {"field": "process_name", "operator": "contains", "value": "mshta.exe"},
                            {"field": "process_name", "operator": "contains", "value": "rundll32.exe"},
                        ],
                    },
                ],
            },
            "mitre_ids": ["T1204.002"],
        },
    },
    {
        "name": "[SOCify] LSASS / Credential Dumping Activity",
        "description": "Detect Mimikatz, comsvcs.dll MiniDump, ProcDump, or direct LSASS credential dumping patterns.",
        "severity": "critical",
        "confidence": 0.96,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "command_line", "operator": "contains", "value": "mimikatz"},
                    {"field": "command_line", "operator": "contains", "value": "sekurlsa"},
                    {"field": "command_line", "operator": "contains", "value": "comsvcs.dll"},
                    {"field": "command_line", "operator": "contains", "value": "procdump"},
                    {"field": "description", "operator": "contains", "value": "mimikatz"},
                    {"field": "description", "operator": "contains", "value": "sekurlsa"},
                    {"field": "description", "operator": "contains", "value": "comsvcs.dll"},
                    {"field": "description", "operator": "contains", "value": "lsass.dmp"},
                ],
            },
            "mitre_ids": ["T1003.001"],
        },
    },
    {
        "name": "[SOCify] Security Audit Log Cleared",
        "description": "Detect Windows Event ID 1102 or explicit audit/event log clearing commands.",
        "severity": "critical",
        "confidence": 0.97,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "event_type", "operator": "in", "value": ["windows_1102", "sysmon_1102", "audit_log_cleared"]},
                    {"field": "command_line", "operator": "contains", "value": "wevtutil cl"},
                    {"field": "command_line", "operator": "contains", "value": "clear-eventlog"},
                    {"field": "description", "operator": "contains", "value": "wevtutil cl"},
                    {"field": "description", "operator": "contains", "value": "clear-eventlog"},
                ],
            },
            "mitre_ids": ["T1070.001"],
        },
    },
    {
        "name": "[SOCify] Local or Domain User Account Created",
        "description": "Detect Windows Event ID 4720 or command-line account creation (net user /add, useradd).",
        "severity": "medium",
        "confidence": 0.84,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "event_type", "operator": "in", "value": ["windows_4720", "user_created"]},
                    {"field": "command_line", "operator": "contains", "value": "useradd "},
                    {"field": "description", "operator": "contains", "value": "useradd "},
                    {
                        "logic": "and",
                        "conditions": [
                            {"field": "command_line", "operator": "contains", "value": "net user "},
                            {"field": "command_line", "operator": "contains", "value": "/add"},
                        ],
                    },
                ],
            },
            "mitre_ids": ["T1136.001"],
        },
    },
    {
        "name": "[SOCify] Privileged Group Membership Modification",
        "description": "Detect additions to privileged Windows/Linux administrative groups (4728/4732/4756/Administrators/sudo).",
        "severity": "high",
        "confidence": 0.90,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "event_type", "operator": "in", "value": ["windows_4728", "windows_4732", "windows_4756", "privileged_group_change"]},
                    {"field": "command_line", "operator": "contains", "value": "localgroup administrators"},
                    {"field": "description", "operator": "contains", "value": "localgroup administrators"},
                    {"field": "description", "operator": "contains", "value": "usermod -ag sudo"},
                ],
            },
            "mitre_ids": ["T1098"],
        },
    },
    {
        "name": "[SOCify] New Service or Scheduled Task Persistence",
        "description": "Detect Windows service installation (7045), scheduled task creation (4698), schtasks /create, or sc create.",
        "severity": "high",
        "confidence": 0.88,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "event_type", "operator": "in", "value": ["windows_7045", "windows_4698", "service_installed", "scheduled_task_created"]},
                    {"field": "command_line", "operator": "contains", "value": "schtasks /create"},
                    {"field": "command_line", "operator": "contains", "value": "sc create "},
                    {"field": "description", "operator": "contains", "value": "schtasks /create"},
                    {"field": "description", "operator": "contains", "value": "sc create "},
                ],
            },
            "mitre_ids": ["T1543.003"],
        },
    },
    {
        "name": "[SOCify] Suspicious LOLBin Proxy Execution",
        "description": "Detect abuse of Windows LOLBins (certutil, bitsadmin, mshta, regsvr32, rundll32 scriptlet execution).",
        "severity": "high",
        "confidence": 0.89,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "command_line", "operator": "contains", "value": "certutil -urlcache"},
                    {"field": "command_line", "operator": "contains", "value": "bitsadmin /transfer"},
                    {"field": "command_line", "operator": "contains", "value": "mshta http"},
                    {"field": "command_line", "operator": "contains", "value": "regsvr32 /s /n"},
                    {"field": "description", "operator": "contains", "value": "certutil -urlcache"},
                    {"field": "description", "operator": "contains", "value": "bitsadmin /transfer"},
                    {"field": "description", "operator": "contains", "value": "mshta http"},
                ],
            },
            "mitre_ids": ["T1218"],
        },
    },
    {
        "name": "[SOCify] Web SQL Injection Probe",
        "description": "Detect SQL injection operators (UNION SELECT, OR 1=1, information_schema) in web/WAF/CEF logs.",
        "severity": "high",
        "confidence": 0.90,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "description", "operator": "contains", "value": "union select"},
                    {"field": "description", "operator": "contains", "value": "' or 1=1"},
                    {"field": "description", "operator": "contains", "value": "information_schema"},
                    {"field": "title", "operator": "contains", "value": "union select"},
                ],
            },
            "mitre_ids": ["T1190"],
        },
    },
    {
        "name": "[SOCify] Web Cross-Site Scripting (XSS) Probe",
        "description": "Detect reflected or stored XSS script payloads in web request paths or WAF logs.",
        "severity": "medium",
        "confidence": 0.85,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "description", "operator": "contains", "value": "<script>"},
                    {"field": "description", "operator": "contains", "value": "%3cscript"},
                    {"field": "description", "operator": "contains", "value": "onerror=alert"},
                    {"field": "title", "operator": "contains", "value": "<script>"},
                ],
            },
            "mitre_ids": ["T1190"],
        },
    },
    {
        "name": "[SOCify] Web Directory / Path Traversal Attempt",
        "description": "Detect ../etc/passwd, ..\\windows\\win.ini, and URL-encoded directory traversal sequences.",
        "severity": "high",
        "confidence": 0.89,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "description", "operator": "contains", "value": "../etc/passwd"},
                    {"field": "description", "operator": "contains", "value": "..\\windows\\win.ini"},
                    {"field": "description", "operator": "contains", "value": "%2e%2e%2f"},
                    {"field": "title", "operator": "contains", "value": "../etc/passwd"},
                ],
            },
            "mitre_ids": ["T1190"],
        },
    },
    {
        "name": "[SOCify] Web Reconnaissance / Scanner Error Burst",
        "description": "Detect 10 or more HTTP 401/403/404 responses to a single source IP within 2 minutes.",
        "severity": "medium",
        "confidence": 0.82,
        "dsl": {
            "condition": {"field": "http_status", "operator": "in", "value": [401, 403, 404]},
            "window": {"seconds": 120, "threshold": 10, "group_by": ["source_ip"], "mode": "count", "allowed_lateness_seconds": 86400},
            "mitre_ids": ["T1595"],
        },
    },
    {
        "name": "[SOCify] Phishing Interaction Followed by Login",
        "description": "Detect phishing email interaction followed by an authentication event for the same username within 30 minutes.",
        "severity": "high",
        "confidence": 0.88,
        "dsl": {
            "condition": {"field": "username", "operator": "exists", "value": True},
            "sequence": [
                {"field": "event_type", "operator": "in", "value": ["phishing_click", "phishing_email", "suspicious_email"]},
                {"field": "category", "operator": "equals", "value": "authentication"},
            ],
            "window": {"seconds": 1800, "threshold": 2, "group_by": ["username"], "mode": "count", "allowed_lateness_seconds": 86400},
            "mitre_ids": ["T1566"],
        },
    },
    {
        "name": "[SOCify] Ransomware Shadow Copy / Recovery Tampering",
        "description": "Detect vssadmin shadow deletion, wmic shadowcopy delete, or bcdedit recovery disabling.",
        "severity": "critical",
        "confidence": 0.97,
        "dsl": {
            "condition": {
                "logic": "or",
                "conditions": [
                    {"field": "command_line", "operator": "contains", "value": "vssadmin delete shadows"},
                    {"field": "command_line", "operator": "contains", "value": "shadowcopy delete"},
                    {"field": "command_line", "operator": "contains", "value": "recoveryenabled no"},
                    {"field": "description", "operator": "contains", "value": "vssadmin delete shadows"},
                    {"field": "description", "operator": "contains", "value": "shadowcopy delete"},
                    {"field": "description", "operator": "contains", "value": "recoveryenabled no"},
                ],
            },
            "mitre_ids": ["T1490"],
        },
    },
    {
        "name": "[SOCify] High Anomaly Score Indicator",
        "description": "Detect events tagged with a normalized anomaly score >= 0.85.",
        "severity": "high",
        "confidence": 0.85,
        "dsl": {
            "condition": {"field": "anomaly_score", "operator": "gte", "value": 0.85},
            "mitre_ids": [],
        },
    },
)


def seed_builtin_rules(connection: sqlite3.Connection) -> int:
    """Idempotently ensure all built-in detection rules exist in every workspace."""
    workspaces = [int(row[0]) for row in connection.execute("SELECT id FROM training_workspaces").fetchall()]
    if not workspaces:
        return 0
    known_mitre = {str(row[0]) for row in connection.execute("SELECT technique_id FROM attack_techniques WHERE revoked = 0").fetchall()}
    now = iso_now()
    inserted_total = 0
    for ws_id in workspaces:
        existing_names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM rules WHERE workspace_id = ? AND archived_at IS NULL",
                (ws_id,),
            ).fetchall()
        }
        creator_row = connection.execute(
            "SELECT id FROM users WHERE workspace_id = ? ORDER BY CASE WHEN role IN ('admin','soc_manager') THEN 0 ELSE 1 END, id LIMIT 1",
            (ws_id,),
        ).fetchone()
        if not creator_row:
            creator_row = connection.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if not creator_row:
            continue
        creator = int(creator_row[0])
        for spec in BUILTIN_RULES:
            legacy_name = next((name for name in sorted(existing_names) if re.sub(r"^\[SOCify [^\]]+\]", "[SOCify]", name) == spec["name"]), None)
            if legacy_name in existing_names and spec["name"] not in existing_names:
                connection.execute(
                    "UPDATE rules SET name = ? WHERE workspace_id = ? AND name = ? AND archived_at IS NULL",
                    (spec["name"], ws_id, legacy_name),
                )
                existing_names.add(spec["name"])
            if spec["name"] in existing_names:
                continue
            dsl = dict(spec["dsl"])
            dsl["condition"] = {
                "logic": "and",
                "conditions": [
                    {"field": "source_type", "operator": "not_equals", "value": "training"},
                    dsl["condition"],
                ],
            }
            if known_mitre and dsl.get("mitre_ids"):
                dsl["mitre_ids"] = [tid for tid in dsl["mitre_ids"] if tid in known_mitre]
            dsl_json = json.dumps(dsl, separators=(",", ":"), ensure_ascii=False)
            action_json = json.dumps({"severity": spec["severity"], "confidence": spec["confidence"]}, separators=(",", ":"))
            cursor = connection.execute(
                """INSERT INTO rules
                   (name, description, condition_type, condition_value, dsl_json, action_type, action_value,
                    is_active, version, deployment_state, workspace_id, created_by, deployed_by, created_at, updated_at)
                   VALUES (?, ?, 'dsl', ?, ?, 'create_alert', ?, 1, 1, 'published', ?, ?, ?, ?, ?)""",
                (spec["name"], spec["description"], dsl_json, dsl_json, action_json, ws_id, creator, creator, now, now),
            )
            rule_id = inserted_id(cursor)
            connection.execute(
                """INSERT INTO rule_versions
                   (rule_id, version, dsl_json, action_json, change_summary, created_by, created_at)
                   VALUES (?, 1, ?, ?, 'SOCify built-in detection pack', ?, ?)""",
                (rule_id, dsl_json, action_json, creator, now),
            )
            inserted_total += 1
    return inserted_total
