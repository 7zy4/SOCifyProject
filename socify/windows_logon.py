"""Retained Windows logon context; no inference of account compromise."""

import ipaddress
import json
from datetime import UTC, datetime, timedelta

from .timeutils import parse_timestamp

RULE_NAME = "[SOCify] Successful Windows Logon After Repeated Failures"

LOGON_TYPES = {
    "2": "interactive",
    "3": "network_logon",
    "4": "batch_logon",
    "5": "service_logon",
    "7": "unlock_logon",
    "8": "network_cleartext",
    "9": "new_credentials",
    "10": "remote_interactive",
    "11": "cached_interactive",
    "12": "cached_remote_interactive",
    "13": "cached_unlock",
}
CONTEXT_FIELDS = (
    "windows_event_id",
    "account_domain",
    "logon_type",
    "logon_type_code",
    "authentication_package",
    "logon_id",
    "source_workstation",
    "source_port",
    "logon_status",
    "logon_substatus",
)


def logon_context(event_id: str, data: dict[str, str], hostname: str | None) -> dict:
    def present(value):
        return value.strip() if isinstance(value, str) and value.strip() not in {"", "-"} else None

    username = present(data.get("TargetUserName"))
    domain = present(data.get("TargetDomainName"))
    host = present(hostname)
    kind = present(data.get("LogonType"))
    source_ip = None
    remote = False
    try:
        address = ipaddress.ip_address(str(data.get("IpAddress", "")))
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if "%" not in str(address):
            source_ip = str(address)
            remote = not (address.is_loopback or address.is_unspecified or address.is_multicast)
    except ValueError:
        pass
    fields = {
        "windows_event_id": int(event_id),
        "account_domain": domain,
        "logon_type": LOGON_TYPES.get(kind or ""),
        "logon_type_code": kind,
        "authentication_package": present(data.get("AuthenticationPackageName")),
        "logon_id": present(data.get("TargetLogonId")),
        "source_workstation": present(data.get("WorkstationName")),
        "logon_status": present(data.get("Status")),
        "logon_substatus": present(data.get("SubStatus")),
    }
    port = data.get("IpPort", "")
    if port.isascii() and port.isdecimal() and len(port) <= 5 and 0 <= int(port) <= 65535:
        fields["source_port"] = int(port)
    if username and domain and host and remote and kind in {"3", "10"}:
        # Preserve displayed names, but match Windows account/host casing consistently.
        fields["auth_target"] = json.dumps([domain.casefold(), username.casefold(), host.casefold(), kind], ensure_ascii=False)
    return {"source_ip": source_ip, "username": username, "normalized_fields": {k: v for k, v in fields.items() if v is not None}}


def reconcile_logons(connection, job):
    """Revisit successes affected by late failures, including a reversed export."""
    from .detection import evaluate_rules
    from .event_identity import job_event_sql

    yield from _reconcile_failed_logons(connection, job)
    rule = connection.execute(
        "SELECT id FROM rules WHERE workspace_id=? AND name=? AND is_active=1 AND archived_at IS NULL", (job["workspace_id"], RULE_NAME)
    ).fetchone()
    if not rule:
        return
    bounds = connection.execute(
        f"SELECT MIN(event_time),MAX(event_time) FROM security_events WHERE {job_event_sql('security_events')} AND autopsy_active=1 AND outcome='failed' AND json_extract(normalized_fields,'$.auth_target') IS NOT NULL AND json_extract(normalized_fields,'$.event_time_known')=1",
        (job["id"], job["id"]),
    ).fetchone()
    if not bounds[0]:
        return
    latest = min(parse_timestamp(bounds[1]), datetime.max.replace(tzinfo=UTC) - timedelta(seconds=600))
    end = (latest + timedelta(seconds=600)).isoformat().replace("+00:00", "Z")
    candidates = connection.execute(
        f"""SELECT e.id FROM security_events e
        WHERE e.workspace_id=? AND e.owner_case_id=? AND e.training_run_id IS ? AND e.autopsy_active=1
        AND e.source_type='windows' AND e.outcome='success' AND e.event_time>=? AND e.event_time<=?
        AND EXISTS (SELECT 1 FROM security_events f WHERE {job_event_sql("f")} AND f.autopsy_active=1
            AND f.outcome='failed' AND f.event_time<=e.event_time AND julianday(f.event_time)>=julianday(e.event_time)-600.0/86400
            AND f.source_ip=e.source_ip AND json_extract(f.normalized_fields,'$.auth_target')=json_extract(e.normalized_fields,'$.auth_target'))
        ORDER BY e.event_time,e.id""",
        (job["workspace_id"], job["case_id"], job["training_run_id"], bounds[0], end, job["id"], job["id"]),
    )
    for row in candidates:
        alerts = evaluate_rules(connection, row["id"], only_rule_id=rule["id"])
        if alerts:
            yield row["id"], alerts


def _reconcile_failed_logons(connection, job):
    """Late failures can complete an earlier imported count or distinct-user window."""
    from .detection import _event_dict, evaluate_dsl, evaluate_rules, legacy_dsl
    from .event_identity import job_event_sql

    bounds = connection.execute(
        f"""SELECT MIN(event_time),MAX(event_time) FROM security_events
        WHERE {job_event_sql("security_events")} AND autopsy_active=1 AND event_type='failed_login'
        AND source_ip IS NOT NULL AND json_extract(normalized_fields,'$.event_time_known')=1""",
        (job["id"], job["id"]),
    ).fetchone()
    if not bounds[0]:
        return
    for name in ("[SOCify] Brute Force Authentication Burst", "[SOCify] Password Spraying Across Accounts"):
        rule = connection.execute(
            "SELECT * FROM rules WHERE workspace_id=? AND name=? AND is_active=1 AND archived_at IS NULL", (job["workspace_id"], name)
        ).fetchone()
        if not rule:
            continue
        dsl = legacy_dsl(rule)
        if not isinstance(dsl.get("window"), dict):
            continue
        seconds = int(dsl["window"]["seconds"])
        latest = min(parse_timestamp(bounds[1]), datetime.max.replace(tzinfo=UTC) - timedelta(seconds=seconds))
        end = (latest + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
        candidates = connection.execute(
            f"""SELECT e.* FROM security_events e
            WHERE e.workspace_id=? AND e.owner_case_id=? AND e.training_run_id IS ? AND e.autopsy_active=1
            AND e.event_type='failed_login' AND e.event_time>=? AND e.event_time<=?
            AND json_extract(e.normalized_fields,'$.event_time_known')=1
            AND EXISTS (SELECT 1 FROM security_events f WHERE {job_event_sql("f")} AND f.autopsy_active=1
                AND f.event_type='failed_login' AND f.id>e.id AND f.source_ip=e.source_ip
                AND json_extract(f.normalized_fields,'$.event_time_known')=1
                AND f.event_time<=e.event_time AND julianday(f.event_time)>=julianday(e.event_time)-?/86400.0)
            ORDER BY e.event_time,e.id""",
            (job["workspace_id"], job["case_id"], job["training_run_id"], bounds[0], end, job["id"], job["id"], seconds),
        )
        for row in candidates:
            evaluation = evaluate_dsl(connection, dsl, _event_dict(row))
            if not evaluation.matched:
                continue
            covered = connection.execute(
                """SELECT a.id FROM alerts a JOIN alert_events ae ON ae.alert_id=a.id
                WHERE a.owner_case_id=? AND a.rule_id=? AND a.rule_version=?
                AND ae.event_id IN (SELECT value FROM json_each(?)) LIMIT 1""",
                (job["case_id"], rule["id"], rule["version"], json.dumps(evaluation.event_ids)),
            ).fetchone()
            if covered:
                # Keep the original proof for an overlapping burst; backfill must not multiply it.
                continue
            alerts = evaluate_rules(connection, row["id"], only_rule_id=rule["id"])
            if alerts:
                yield row["id"], alerts
