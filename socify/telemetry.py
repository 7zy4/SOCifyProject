"""Read-only adapters for retained Zeek, Suricata EVE and osquery results."""

import math
from typing import Any

from .timeutils import iso_timestamp, parse_timestamp


def number(value, maximum=2**53 - 1, integral=False):
    if value in (None, "", "-"):
        return None
    if isinstance(value, bool):
        raise ValueError("boolean telemetry numbers are invalid")
    parsed = float(value)
    if not math.isfinite(parsed) or not 0 <= parsed <= maximum or integral and not parsed.is_integer():
        raise ValueError("telemetry number is outside its permitted range")
    return int(parsed) if integral else parsed


def osquery_rows(record):
    """Expand batch/snapshot rows without copying the entire batch into each event."""
    if not all(key in record for key in ("hostIdentifier", "name")):
        return None
    if "columns" in record:
        rows = [(record.get("action"), record["columns"], "columns")]
    elif "snapshot" in record:
        if not isinstance(record["snapshot"], list):
            raise ValueError("osquery snapshot must be an array")
        rows = [("snapshot", row, f"snapshot/{index}") for index, row in enumerate(record["snapshot"])]
    elif "diffResults" in record:
        diff = record["diffResults"]
        if not isinstance(diff, dict) or set(diff) - {"added", "removed"}:
            raise ValueError("invalid osquery differential results")
        rows = []
        for action, values in diff.items():
            if not isinstance(values, list):
                raise ValueError("osquery changes must be arrays")
            rows.extend((action, row, f"diffResults/{action}/{index}") for index, row in enumerate(values))
    else:
        return None
    if len(rows) > 10000:
        raise ValueError("osquery result exceeds 10000 rows")
    context = {key: value for key, value in record.items() if key not in {"snapshot", "diffResults", "columns", "action"}}
    if not rows:
        # An empty snapshot is evidence too; never invent an endpoint process.
        return [({**context, "action": "snapshot" if "snapshot" in record else "unchanged", "columns": {}}, "")]
    result = []
    for action, columns, pointer in rows:
        if action not in {"added", "removed", "snapshot"} or not isinstance(columns, dict) or len(columns) > 200:
            raise ValueError("invalid osquery result row")
        if any(not isinstance(value, (str, int, float, bool, type(None))) for value in columns.values()):
            raise ValueError("osquery columns must contain scalar values")
        result.append(({**context, "action": action, "columns": columns}, pointer))
    return result


def profile(record: dict[str, Any]) -> dict[str, Any]:
    def section(key) -> dict[str, Any]:
        value = record.get(key)
        return value if isinstance(value, dict) else {}

    fields: dict[str, Any] = {}
    result: dict[str, Any] = {}
    if all(key in record for key in ("uid", "id.orig_h", "id.resp_h")):
        connection = any(key in record for key in ("conn_state", "orig_bytes", "orig_pkts"))
        kind = "conn" if connection else "dns" if "query" in record else "http" if "method" in record else "tls" if "server_name" in record else "event"
        fields = {
            "telemetry_schema": "zeek",
            "flow_id": str(record["uid"]),
            "connection_summary": connection,
            "source_port": number(record.get("id.orig_p"), 65535, True),
            "destination_port": number(record.get("id.resp_p"), 65535, True),
            "protocol": str(record.get("proto") or "").lower(),
            "bytes_sent": number(record.get("orig_bytes"), integral=True),
            "bytes_received": number(record.get("resp_bytes"), integral=True),
            "duration_seconds": number(record.get("duration")),
            "dns_question": record.get("query"),
            "tls_sni": record.get("server_name"),
            "http_host": record.get("host"),
            "http_method": record.get("method"),
            "http_path": record.get("uri"),
            "connection_state": record.get("conn_state"),
        }
        result = {
            "source_type": "zeek",
            "event_type": f"zeek_{kind}",
            "category": "network",
            "severity": "low",
            "source_ip": record["id.orig_h"],
            "destination_ip": record["id.resp_h"],
            "event_time": record.get("ts"),
            "http_status": record.get("status_code"),
            "title": f"Zeek {kind} · {record['id.orig_h']} → {record['id.resp_h']}",
        }
    elif all(key in record for key in ("flow_id", "src_ip", "dest_ip", "event_type")):
        kind = record["event_type"]
        flow = section("flow")
        alert = section("alert")
        http = section("http")
        dns = section("dns")
        tls = section("tls")
        duration = None
        if kind == "flow" and flow.get("start") and flow.get("end"):
            duration = number((parse_timestamp(flow["end"]) - parse_timestamp(flow["start"])).total_seconds())
        fields = {
            "telemetry_schema": "suricata",
            "flow_id": str(record["flow_id"]),
            "connection_summary": kind == "flow",
            "source_port": number(record.get("src_port"), 65535, True),
            "destination_port": number(record.get("dest_port"), 65535, True),
            "protocol": str(record.get("proto") or "").lower(),
            "bytes_sent": number(flow.get("bytes_toserver"), integral=True),
            "bytes_received": number(flow.get("bytes_toclient"), integral=True),
            "duration_seconds": duration,
            "dns_question": dns.get("rrname"),
            "tls_sni": tls.get("sni"),
            "http_host": http.get("hostname"),
            "http_method": http.get("http_method"),
            "http_path": http.get("url"),
            "signature_id": alert.get("signature_id"),
            "ids_severity": number(alert.get("severity"), 255, True),
            "ids_signature": alert.get("signature"),
        }
        result = {
            "source_type": "suricata",
            "event_type": f"suricata_{kind}",
            "category": "network",
            "source_ip": record["src_ip"],
            "destination_ip": record["dest_ip"],
            "event_time": flow.get("start", record.get("timestamp")) if kind == "flow" else record.get("timestamp"),
            "severity": {1: "high", 2: "medium", 3: "low"}.get(fields["ids_severity"], "low"),
            "title": alert.get("signature") or f"Suricata {kind} · {record['src_ip']} → {record['dest_ip']}",
            "action": alert.get("action"),
            "http_status": http.get("status"),
        }
    elif all(key in record for key in ("hostIdentifier", "name", "columns")):
        columns = record["columns"]
        if not isinstance(columns, dict):
            raise ValueError("invalid osquery columns")
        fields = {
            "telemetry_schema": "osquery",
            "query_name": str(record["name"]),
            "query_action": record.get("action"),
            "query_columns": columns,
            "process_id": columns.get("pid"),
            "parent_process_id": columns.get("parent"),
            "command_line": columns.get("cmdline"),
            "process_path": columns.get("path"),
        }
        result = {
            "source_type": "osquery",
            "event_type": "osquery_result",
            "category": "endpoint",
            "severity": "low",
            "hostname": record["hostIdentifier"],
            "event_time": record.get("unixTime"),
            "action": record.get("action"),
            "title": f"{record['name']} · {record.get('action', '')}",
            "process_name": columns.get("name") if "pid" in columns else None,
            "username": columns.get("username"),
            "source_ip": columns.get("local_address"),
            "destination_ip": columns.get("remote_address"),
            "file_hash": columns.get("sha256"),
        }
    if not result:
        return {}
    if result["category"] == "network":
        # An HTTP Host header names a destination, not the endpoint hostname.
        result["hostname"] = ""
    observed = result.pop("event_time", None)
    if observed is not None:
        result["event_time"] = iso_timestamp(observed)
    result["normalized_fields"] = {key: value for key, value in fields.items() if value is not None}
    result["parser_version"] = "socify-telemetry-1"
    return result
