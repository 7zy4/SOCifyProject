"""Elastic Security detection alerts sent by a Kibana webhook connector (Elastic Security 8.x, alert schema in ECS).

Configure the rule action body as {"alerts": {{context.alerts}}} or send single alert documents. Fields are read either
nested or as flattened dotted keys: kibana.alert.uuid, kibana.alert.rule.name, kibana.alert.rule.uuid,
kibana.alert.severity, kibana.alert.reason, @timestamp, host.name, user.name, source.ip, destination.ip, url.full,
dns.question.name, file.hash.*, threat.technique.id.
"""

from typing import Any

from .common import alert, entities, first, mitre, severity_word


def items(payload: object) -> list[Any]:
    if isinstance(payload, dict):
        for key in ("alerts", "context.alerts"):
            value = first(payload, key)
            if isinstance(value, list):
                return value
    return payload if isinstance(payload, list) else [payload]


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    return alert(
        external_id=first(item, "kibana.alert.uuid", "_id"),
        title=first(item, "kibana.alert.rule.name", "signal.rule.name"),
        severity=severity_word(first(item, "kibana.alert.severity", "signal.rule.severity")),
        time=first(item, "kibana.alert.original_time", "@timestamp"),
        rule_id=first(item, "kibana.alert.rule.uuid", "kibana.alert.rule.rule_id"),
        rule_name=first(item, "kibana.alert.rule.name"),
        description=first(item, "kibana.alert.reason", "kibana.alert.rule.description"),
        found=entities(
            hosts=[first(item, "host.name"), first(item, "host.hostname")],
            users=[first(item, "user.name"), first(item, "user.target.name")],
            ips=[first(item, "source.ip"), first(item, "destination.ip"), first(item, "host.ip")],
            domains=[first(item, "dns.question.name"), first(item, "destination.domain"), first(item, "url.domain")],
            urls=[first(item, "url.full")],
            hashes=[first(item, "file.hash.sha256"), first(item, "file.hash.sha1"), first(item, "file.hash.md5"), first(item, "process.hash.sha256")],
        ),
        techniques=mitre(first(item, "threat.technique.id"), first(item, "kibana.alert.rule.threat.technique.id")),
    )
