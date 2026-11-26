"""The SOCify generic intake schema, for any system that can send JSON.

    {"alerts": [{"id": "unique id", "title": "...", "severity": "critical|high|medium|low|info",
                 "time": "2026-11-26T08:00:00Z", "rule": {"id": "...", "name": "..."}, "description": "...",
                 "entities": {"hosts": [], "users": [], "ips": [], "domains": [], "urls": [], "hashes": []},
                 "mitre": ["T1110"]}]}

A single alert object without the "alerts" wrapper is accepted too.
"""

from typing import Any

from .common import alert, entities, first, mitre, severity_word


def items(payload: object) -> list[Any]:
    if isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        return payload["alerts"]
    return payload if isinstance(payload, list) else [payload]


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = item["entities"] if isinstance(item.get("entities"), dict) else {}
    return alert(
        external_id=first(item, "id"),
        title=first(item, "title"),
        severity=severity_word(first(item, "severity")),
        time=first(item, "time"),
        rule_id=first(item, "rule.id"),
        rule_name=first(item, "rule.name"),
        description=first(item, "description"),
        found=entities(**{kind: found.get(kind) for kind in ("hosts", "users", "ips", "domains", "urls", "hashes")}),
        techniques=mitre(item.get("mitre")),
    )
