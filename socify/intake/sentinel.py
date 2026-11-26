"""Microsoft Sentinel alerts posted by a Logic App or automation rule HTTP action (SecurityAlert schema, 2024).

The body is a SecurityAlert object (SystemAlertId, AlertName or DisplayName, Severity, TimeGenerated, Description,
Tactics, Techniques, Entities) or an incident object with a "properties" member (title, severity, incidentNumber).
Entities arrive as a list or a JSON string; each has a Type such as host, account, ip, url, dns or filehash.
"""

import json
from typing import Any

from .common import alert, entities, first, mitre, severity_word


def items(payload: object) -> list[Any]:
    if isinstance(payload, dict) and isinstance(payload.get("value"), list):
        return payload["value"]
    return payload if isinstance(payload, list) else [payload]


def _entities(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    return [entry for entry in raw if isinstance(entry, dict)][:200] if isinstance(raw, list) else []


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    source = item.get("properties") if isinstance(item.get("properties"), dict) else item
    found: dict[str, list[object]] = {"hosts": [], "users": [], "ips": [], "domains": [], "urls": [], "hashes": []}
    for entry in _entities(first(source, "Entities", "entities", "relatedEntities")):
        kind = str(entry.get("Type") or entry.get("kind") or "").lower()
        if kind == "host":
            found["hosts"].append(entry.get("HostName") or entry.get("hostName"))
        elif kind == "account":
            found["users"].append(entry.get("Name") or entry.get("accountName"))
        elif kind == "ip":
            found["ips"].append(entry.get("Address") or entry.get("address"))
        elif kind == "url":
            found["urls"].append(entry.get("Url") or entry.get("url"))
        elif kind == "dns":
            found["domains"].append(entry.get("DomainName") or entry.get("domainName"))
        elif kind == "filehash":
            found["hashes"].append(entry.get("Value") or entry.get("hashValue"))
    return alert(
        external_id=first(source, "SystemAlertId", "incidentNumber", "name"),
        title=first(source, "AlertName", "DisplayName", "title"),
        severity=severity_word(first(source, "Severity", "severity")),
        time=first(source, "StartTime", "TimeGenerated", "createdTimeUtc", "firstActivityTimeUtc"),
        rule_id=first(source, "AlertType", "ProductComponentName"),
        rule_name=first(source, "AlertName", "DisplayName", "title"),
        description=first(source, "Description", "description"),
        found=entities(**found),
        techniques=mitre(first(source, "Techniques", "techniques")),
    )
