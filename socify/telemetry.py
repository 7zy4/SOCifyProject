"""Read-only adapters for structured sensor and endpoint evidence."""

import math
import re
from typing import Any

from .timeutils import iso_timestamp, parse_timestamp


def falco_profile(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize runtime alerts without treating the collector as an affected host."""
    values = record["output_fields"]
    if not isinstance(values, dict) or len(values) > 200:
        raise ValueError("invalid Falco output fields")

    def text(value, limit=512):
        if value is None or isinstance(value, str) and value in {"", "<NA>", "<nil>"}:
            return None
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError("invalid or oversized Falco text field")
        return value

    def process_id(key):
        value = values.get(key)
        return None if value in ("<NA>", "<nil>") else number(value, integral=True)

    rule = text(record["rule"], 255)
    priority = text(record["priority"], 32)
    timestamp = text(record.get("time"), 80)
    levels = {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "error": "high",
        "warning": "medium",
        "notice": "low",
        "informational": "low",
        "debug": "low",
    }
    if not rule or not priority or priority.casefold() not in levels or not timestamp:
        raise ValueError("Falco rule, priority and event time are required")
    tags = record.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 50 or any(not isinstance(tag, str) or len(tag) > 80 for tag in tags):
        raise ValueError("invalid Falco tags")
    fields = {
        "telemetry_schema": "falco",
        "runtime_rule": rule,
        "runtime_priority": priority.casefold(),
        "runtime_source": text(record.get("source"), 100),
        "sensor_hostname": text(record.get("hostname")),
        "process_id": process_id("proc.pid"),
        "parent_process_id": process_id("proc.ppid"),
        "process_path": text(values.get("proc.exepath"), 2048),
        "container_id": text(values.get("container.id")),
        "container_name": text(values.get("container.name")),
        "container_image": text(values.get("container.image.repository")),
        "container_image_tag": text(values.get("container.image.tag")),
        "kubernetes_namespace": text(values.get("k8s.ns.name")),
        "kubernetes_pod": text(values.get("k8s.pod.name")),
        "kubernetes_node": text(values.get("k8s.node.name")),
        "file_path": text(values.get("fd.name"), 2048),
    }
    if fields["container_id"] == "host":
        for key in ("container_id", "container_name", "container_image", "container_image_tag"):
            fields[key] = None
    return {
        "source": "Falco",
        "source_type": "falco",
        "event_type": "runtime_alert",
        "category": "runtime",
        "severity": levels[priority.casefold()],
        "title": rule,
        "description": text(record.get("output"), 4000) or "",
        "event_time": iso_timestamp(timestamp),
        "hostname": text(values.get("evt.hostname")) or "",
        "username": text(values.get("user.name")) or "",
        "process_name": text(values.get("proc.name")) or "",
        "parent_process": text(values.get("proc.pname")) or "",
        "command_line": text(values.get("proc.cmdline"), 2048) or "",
        "action": text(values.get("evt.type")) or "",
        "tags": tags,
        "mitre_ids": list(dict.fromkeys(tag for tag in tags if re.fullmatch(r"T\d{4}(?:\.\d{3})?", tag)))[:20],
        "normalized_fields": {key: value for key, value in fields.items() if value is not None},
        "parser_version": "socify-falco-1",
    }


def number(value, maximum=2**53 - 1, integral=False):
    if value in (None, "", "-"):
        return None
    if isinstance(value, bool):
        raise ValueError("boolean telemetry numbers are invalid")
    try:
        parsed = float(value)
    except (TypeError, OverflowError) as exc:
        raise ValueError("invalid telemetry number") from exc
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
    if all(key in record for key in ("rule", "priority", "output_fields")):
        return falco_profile(record)

    def section(key) -> dict[str, Any]:
        value = record.get(key)
        return value if isinstance(value, dict) else {}

    fields: dict[str, Any] = {}
    result: dict[str, Any] = {}
    if all(key in record for key in ("uid", "id.orig_h", "id.resp_h")):
        if not isinstance(record["uid"], str) or not record["uid"]:
            raise ValueError("Zeek UID must be a nonempty string")
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
        if (
            isinstance(record["flow_id"], bool)
            or not isinstance(record["flow_id"], (str, int))
            or not str(record["flow_id"]).isascii()
            or not str(record["flow_id"]).isdecimal()
        ):
            raise ValueError("Suricata flow_id must be an unsigned integer identifier")
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
    for key, limit in (("flow_id", 256), ("protocol", 32), ("dns_question", 512), ("tls_sni", 512), ("http_host", 512), ("query_name", 255)):
        value = fields.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > limit):
            raise ValueError(f"invalid or oversized telemetry field: {key}")
    if result["category"] == "network":
        # An HTTP Host header names a destination, not the endpoint hostname.
        result["hostname"] = ""
    observed = result.pop("event_time", None)
    if observed is not None:
        result["event_time"] = iso_timestamp(observed)
    result["normalized_fields"] = {key: value for key, value in fields.items() if value is not None}
    result["parser_version"] = "socify-telemetry-1"
    return result
