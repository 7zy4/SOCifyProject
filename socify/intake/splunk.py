"""Splunk webhook alert action (Splunk Enterprise 9.x, "Use a webhook alert action").

The action posts {"sid", "search_name", "app", "owner", "results_link", "result": {...first result row...}}. The
result row holds whatever fields the search returns; common CIM names are read: severity or urgency, src, dest, user,
dest_host, url, file_hash, mitre_technique_id, _time.
"""

from typing import Any

from .common import alert, entities, first, mitre, severity_word


def items(payload: object) -> list[Any]:
    return payload if isinstance(payload, list) else [payload]


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    result = item.get("result") if isinstance(item.get("result"), dict) else {}
    return alert(
        external_id=first(item, "sid"),
        title=first(item, "search_name"),
        severity=severity_word(first(result, "severity", "urgency")),
        time=first(result, "_time"),
        rule_id=first(item, "search_name"),
        rule_name=first(item, "search_name"),
        description=first(result, "description", "signature", "_raw"),
        found=entities(
            hosts=[first(result, "dest_host"), first(result, "host"), first(result, "dest_nt_host")],
            users=[first(result, "user"), first(result, "src_user")],
            ips=[first(result, "src"), first(result, "src_ip"), first(result, "dest"), first(result, "dest_ip")],
            domains=[first(result, "query"), first(result, "dest_domain")],
            urls=[first(result, "url")],
            hashes=[first(result, "file_hash"), first(result, "hash")],
        ),
        techniques=mitre(first(result, "mitre_technique_id", "annotations.mitre_attack")),
    )
