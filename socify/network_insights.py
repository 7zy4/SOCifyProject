"""Deterministic connection evidence. Regular timing is not an intrusion verdict."""

import hashlib
import ipaddress
import json
import statistics

from .timeutils import parse_timestamp
from .validation import ValidationError

MAX_NETWORK_EVENTS = 20000


def summarize_connections(events):
    groups = {}
    for event in events:
        fields = event["fields"]
        try:
            source = str(ipaddress.ip_address(event["source_ip"]))
            destination = str(ipaddress.ip_address(event["destination_ip"]))
        except ValueError:
            continue
        port = fields.get("destination_port")
        protocol = fields.get("protocol") or ""
        identity = (event["source"], event["source_type"], source, destination, port, protocol)
        key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:24]
        if key not in groups:
            groups[key] = {
                "key": key,
                "source": event["source"],
                "source_type": event["source_type"],
                "source_ip": source,
                "destination_ip": destination,
                "destination_port": port,
                "protocol": protocol,
                "events": [],
                "flows": {},
                "names": set(),
            }
        group = groups[key]
        group["events"].append(event["id"])
        for name in ("dns_question", "tls_sni", "http_host"):
            if isinstance(fields.get(name), str) and len(group["names"]) < 25:
                group["names"].add(fields[name][:512])
        if fields.get("connection_summary") is True:
            # Duplicate exports of one connection cannot become additional connections.
            stamp = event["event_time"] if fields.get("event_time_known") is True else None
            flow_key = (fields.get("flow_id") or event["id"], parse_timestamp(stamp).timestamp() if stamp else None)
            group["flows"].setdefault(flow_key, (event, stamp))
    output = []
    for group in groups.values():
        flows = list(group.pop("flows").values())
        times = sorted({parse_timestamp(stamp).timestamp() for _, stamp in flows if stamp})
        intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
        median = statistics.median(intervals) if intervals else None
        mad = statistics.median(abs(value - median) for value in intervals) if median is not None else None
        regularity = round(100 * sum(abs(value - median) <= max(1, median * 0.1) for value in intervals) / len(intervals)) if median is not None else None
        periodic = (
            median is not None
            and mad is not None
            and regularity is not None
            and len(times) >= 6
            and times[-1] - times[0] >= 300
            and median >= 1
            and regularity >= 80
            and mad <= max(1, median * 0.1)
        )
        event_ids = group.pop("events")
        sent = [event["fields"].get("bytes_sent") for event, _ in flows]
        received = [event["fields"].get("bytes_received") for event, _ in flows]
        durations = [event["fields"].get("duration_seconds") for event, _ in flows]
        group.update(
            {
                "connection_count": len(flows),
                "event_count": len(event_ids),
                "event_ids": event_ids[:50],
                "events_truncated": len(event_ids) > 50,
                "names": sorted(group["names"]),
                "first_seen": min((stamp for _, stamp in flows if stamp), key=parse_timestamp) if times else None,
                "last_seen": max((stamp for _, stamp in flows if stamp), key=parse_timestamp) if times else None,
                "timed_connections": len(times),
                "median_interval_seconds": median,
                "interval_mad_seconds": mad,
                "regularity_percent": regularity,
                "periodic": bool(periodic),
                "bytes_sent": sum(value for value in sent if value is not None) if any(value is not None for value in sent) else None,
                "bytes_received": sum(value for value in received if value is not None) if any(value is not None for value in received) else None,
                "byte_measurements": sum(value is not None and other is not None for value, other in zip(sent, received, strict=True)),
                "longest_connection_seconds": max((value for value in durations if value is not None), default=None),
            }
        )
        output.append(group)
    return sorted(output, key=lambda item: (-item["periodic"], -item["connection_count"], item["key"]))


def network_snapshot(connection, case_id, workspace):
    rows = connection.execute(
        """SELECT id,source,source_type,source_ip,destination_ip,event_time,
        json_object('flow_id',json_extract(normalized_fields,'$.flow_id'),
          'protocol',json_extract(normalized_fields,'$.protocol'),'destination_port',json_extract(normalized_fields,'$.destination_port'),
          'connection_summary',json_extract(normalized_fields,'$.connection_summary'),'event_time_known',json_extract(normalized_fields,'$.event_time_known'),
          'bytes_sent',json_extract(normalized_fields,'$.bytes_sent'),'bytes_received',json_extract(normalized_fields,'$.bytes_received'),
          'duration_seconds',json_extract(normalized_fields,'$.duration_seconds'),'dns_question',substr(json_extract(normalized_fields,'$.dns_question'),1,512),
          'tls_sni',substr(json_extract(normalized_fields,'$.tls_sni'),1,512),'http_host',substr(json_extract(normalized_fields,'$.http_host'),1,512)) AS fields
        FROM security_events WHERE owner_case_id=? AND workspace_id=? AND autopsy_active=1
          AND source_type IN ('zeek','suricata','snort') AND json_extract(normalized_fields,'$.telemetry_schema') IN ('zeek','suricata','snort')
        ORDER BY id LIMIT ?""",
        (case_id, workspace, MAX_NETWORK_EVENTS + 1),
    ).fetchall()
    if len(rows) > MAX_NETWORK_EVENTS:
        raise ValidationError("تجاوز تحليل الشبكة حد ٢٠٠٠٠ سجل للقضية")
    events = []
    for row in rows:
        item = dict(row)
        item["fields"] = json.loads(item["fields"])
        for field in ("connection_summary", "event_time_known"):
            item["fields"][field] = item["fields"].get(field) == 1
        events.append(item)
    groups = summarize_connections(events)
    return {
        "engine": "socify-connections-1",
        "event_count": len(events),
        "pair_count": len(groups),
        "connection_count": sum(group["connection_count"] for group in groups),
        "periodic_count": sum(group["periodic"] for group in groups),
        "items": groups,
    }


def telemetry_report(connection, case_id, workspace):
    network = network_snapshot(connection, case_id, workspace)
    if len(network["items"]) > 2000:
        raise ValidationError("تجاوز التقرير حد ٢٠٠٠ اتصال")
    endpoints = []
    size = 0
    for row in connection.execute(
        "SELECT id,hostname,event_time,action,normalized_fields FROM security_events WHERE owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND source_type='osquery' ORDER BY id LIMIT 2001",
        (case_id, workspace),
    ):
        fields = json.loads(row["normalized_fields"])
        item = {
            "event_id": row["id"],
            "hostname": row["hostname"],
            "event_time": row["event_time"] if fields.get("event_time_known") else None,
            "action": row["action"],
            "query": fields.get("query_name"),
            "columns": fields.get("query_columns", {}),
        }
        size += len(json.dumps(item).encode())
        endpoints.append(item)
        if len(endpoints) > 2000 or size > 4 * 1024 * 1024:
            raise ValidationError("تجاوز التقرير حد نتائج الأجهزة")
    runtime = []
    for row in connection.execute(
        "SELECT id,hostname,username,title,severity,event_time,raw_hash,normalized_fields FROM security_events WHERE owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND source_type='falco' ORDER BY id LIMIT 2001",
        (case_id, workspace),
    ):
        fields = json.loads(row["normalized_fields"])
        item = {
            "event_id": row["id"],
            "hostname": row["hostname"],
            "username": row["username"],
            "title": row["title"],
            "severity": row["severity"],
            "event_time": row["event_time"] if fields.get("event_time_known") else None,
            "sha256": row["raw_hash"],
            **{
                key: fields[key]
                for key in (
                    "runtime_rule",
                    "runtime_priority",
                    "runtime_source",
                    "sensor_hostname",
                    "process_name",
                    "parent_process",
                    "process_id",
                    "parent_process_id",
                    "process_path",
                    "command_line",
                    "file_path",
                    "container_id",
                    "container_name",
                    "container_image",
                    "container_image_tag",
                    "kubernetes_namespace",
                    "kubernetes_pod",
                    "kubernetes_node",
                )
                if fields.get(key) not in (None, "")
            },
        }
        size += len(json.dumps(item).encode())
        runtime.append(item)
        if len(runtime) > 2000 or size > 4 * 1024 * 1024:
            raise ValidationError("تجاوز التقرير حد أحداث أمن التشغيل")
    alerts = []
    for row in connection.execute(
        "SELECT id,source_ip,destination_ip,title,severity,action,event_time,normalized_fields FROM security_events WHERE owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND source_type='snort' ORDER BY id LIMIT 2001",
        (case_id, workspace),
    ):
        fields = json.loads(row["normalized_fields"])
        item = {"event_id": row["id"], **{key: row[key] for key in ("source_ip", "destination_ip", "title", "severity", "action")}}
        item["event_time"] = row["event_time"] if fields.get("event_time_known") else None
        item.update(
            {
                key: value
                for key, value in fields.items()
                if key
                in {
                    "source_port",
                    "destination_port",
                    "protocol",
                    "ids_rule",
                    "ids_priority",
                    "ids_signature",
                    "ids_classification",
                    "source_timestamp",
                    "packet_number",
                }
            }
        )
        alerts.append(item)
        size += len(json.dumps(item).encode())
        if len(alerts) > 2000 or size > 4 * 1024 * 1024:
            raise ValidationError("تجاوز التقرير حد تنبيهات الشبكة")
    from .windows_logon import CONTEXT_FIELDS

    logons = []
    for row in connection.execute(
        "SELECT id,hostname,username,source_ip,event_time,outcome,normalized_fields FROM security_events WHERE owner_case_id=? AND workspace_id=? AND autopsy_active=1 AND source_type='windows' AND json_extract(normalized_fields,'$.windows_event_id') IN (4624,4625) ORDER BY event_time,id LIMIT 2001",
        (case_id, workspace),
    ):
        fields = json.loads(row["normalized_fields"])
        item = {"event_id": row["id"], **{key: row[key] for key in ("hostname", "username", "source_ip", "outcome")}}
        item["event_time"] = row["event_time"] if fields.get("event_time_known") else None
        item.update({key: fields[key] for key in CONTEXT_FIELDS if fields.get(key) not in (None, "")})
        logons.append(item)
        size += len(json.dumps(item).encode())
        if len(logons) > 2000 or size > 4 * 1024 * 1024:
            raise ValidationError("تجاوز التقرير حد أحداث تسجيل الدخول")
    return {
        "network_analysis": network if network["event_count"] else {},
        "endpoint_results": endpoints,
        "runtime_events": runtime,
        "network_alerts": alerts,
        "logon_events": logons,
    }
