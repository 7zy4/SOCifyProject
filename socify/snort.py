"""Normalize retained Snort JSON alerts without executing sensor actions."""

import ipaddress
import re

from .timeutils import iso_now, iso_timestamp


def snort_profile(record):
    from .telemetry import number

    def text(key, limit=512):
        value = record.get(key, "")
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError("invalid Snort text field")
        return value

    rule = text("rule", 100)
    if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}:[0-9]{1,10}", rule) or any(int(part) > 2**32 - 1 for part in rule.split(":")):
        raise ValueError("invalid Snort rule identifier")

    def endpoint(prefix):
        address = text(prefix + "_addr", 80)
        port = number(record.get(prefix + "_port"), 65535, True)
        if not address:
            combined = text(prefix + "_ap", 100)
            if not combined:
                return "", port
            address, separator, raw_port = combined.rpartition(":")
            if not separator:
                raise ValueError("invalid Snort address and port")
            port = number(raw_port, 65535, True)
            if port is None:
                raise ValueError("Snort address requires a port")
            address = address.removeprefix("[").removesuffix("]")
        if "%" in address:
            raise ValueError("scoped Snort addresses are not supported")
        return str(ipaddress.ip_address(address)), port

    source, source_port = endpoint("src")
    destination, destination_port = endpoint("dst")
    priority = number(record.get("priority"), 2**32 - 1, True)
    stamp = text("timestamp", 80)
    seconds = number(record.get("seconds"), 253402300799)
    known_time = seconds is not None or bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})", stamp))
    moment = iso_timestamp(seconds if seconds is not None else stamp) if known_time else iso_now()
    message = text("msg", 4000)
    fields = {
        "telemetry_schema": "snort",
        "event_time_known": known_time,
        "source_timestamp": stamp or None,
        "protocol": text("proto", 20).lower(),
        "source_port": source_port,
        "destination_port": destination_port,
        "ids_rule": rule,
        "ids_priority": priority,
        "ids_signature": message or None,
        "ids_classification": text("class", 512) or None,
        "packet_number": number(record.get("pkt_num"), integral=True),
    }
    return {
        "source": "Snort",
        "source_type": "snort",
        "event_type": "snort_alert",
        "category": "network",
        "severity": {1: "high", 2: "medium", 3: "low"}.get(priority, "medium" if priority is None or priority == 0 else "low"),
        "title": (message or f"Snort {rule}")[:255],
        "description": message,
        "event_time": moment,
        "source_ip": source,
        "destination_ip": destination,
        "hostname": "",
        "action": text("action", 80),
        "normalized_fields": {key: value for key, value in fields.items() if value is not None},
        "parser_version": "socify-snort-1",
    }
