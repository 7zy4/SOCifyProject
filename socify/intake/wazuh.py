"""Wazuh alerts, as written to alerts.json and sent by the Wazuh integrator (Wazuh documentation 4.x, "Alerts").

An alert carries rule.level (0-15), rule.id, rule.description, rule.mitre.id, agent.name/ip, data.srcip/dstip,
data.srcuser/dstuser, syscheck hashes and an id unique to the manager. A batch is a list, or {"alerts": [...]}.
"""

from typing import Any

from .common import alert, entities, first, mitre, severity_score

# Wazuh rule levels: 12 and above are high-importance events, 15 the most severe.
LEVELS = ((15, "critical"), (12, "high"), (8, "medium"), (4, "low"), (0, "info"))


def items(payload: object) -> list[Any]:
    if isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        return payload["alerts"]
    return payload if isinstance(payload, list) else [payload]


def normalize(item: dict[str, Any]) -> dict[str, Any]:
    return alert(
        external_id=first(item, "id", "_id"),
        title=first(item, "rule.description"),
        severity=severity_score(first(item, "rule.level"), LEVELS),
        time=first(item, "timestamp", "@timestamp"),
        rule_id=first(item, "rule.id"),
        rule_name=first(item, "rule.description"),
        description=first(item, "full_log"),
        found=entities(
            hosts=[first(item, "agent.name"), first(item, "predecoder.hostname")],
            users=[first(item, "data.srcuser"), first(item, "data.dstuser"), first(item, "data.win.eventdata.targetUserName")],
            ips=[first(item, "agent.ip"), first(item, "data.srcip"), first(item, "data.dstip")],
            urls=[first(item, "data.url")],
            hashes=[first(item, "syscheck.md5_after"), first(item, "syscheck.sha1_after"), first(item, "syscheck.sha256_after")],
        ),
        techniques=mitre(first(item, "rule.mitre.id")),
    )
