"""The normalised alert every intake adapter produces, and the checks that keep untrusted fields bounded.

    {
      "external_id": str | None, "title": str, "severity": "critical|high|medium|low|info", "time": ISO-8601 UTC | None,
      "rule_id": str | None, "rule_name": str | None, "description": str,
      "entities": {"hosts": [], "users": [], "ips": [], "domains": [], "urls": [], "hashes": []},
      "mitre": ["T1110", "T1059.001"]
    }

Nothing from a payload is executed or rendered as markup; text is cut to fixed lengths and lists to fixed sizes.
"""

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

from ..timeutils import parse_timestamp
from ..validation import ValidationError

SEVERITIES = ("critical", "high", "medium", "low", "info")
ENTITY_KINDS = ("hosts", "users", "ips", "domains", "urls", "hashes")
MAX_ENTITIES = 50
MITRE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
HASH = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})")
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_WORDS = {
    "critical": "critical",
    "very-high": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "info",
    "information": "info",
    "info": "info",
}


def text(value: object, limit: int) -> str | None:
    """A single line of printable text cut to `limit` characters, or None."""
    if value is None or isinstance(value, (dict, list)):
        return None
    cleaned = " ".join(str(value).split())
    cleaned = "".join(char for char in cleaned if char.isprintable())
    return cleaned[:limit] or None


def dig(data: object, path: str) -> Any:
    """Read a.b.c from nested objects or from flattened "a.b.c" keys (Elastic sends either)."""
    if isinstance(data, dict) and path in data:
        return data[path]
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def first(data: object, *paths: str) -> Any:
    for path in paths:
        value = dig(data, path)
        if value not in (None, "", [], {}):
            return value
    return None


def severity_word(value: object, default: str = "medium") -> str:
    word = text(value, 30)
    return _WORDS.get(word.lower(), default) if word else default


def severity_score(score: object, bands: Iterable[tuple[float, str]], default: str = "medium") -> str:
    """Map a number onto bands given as (minimum, severity) from highest to lowest."""
    try:
        number = float(str(score))
    except (TypeError, ValueError):
        return default
    for minimum, severity in bands:
        if number >= minimum:
            return severity
    return default


def timestamp(value: object) -> str | None:
    if value in (None, ""):
        return None
    try:
        return parse_timestamp(value).isoformat().replace("+00:00", "Z")
    except (ValidationError, ValueError, TypeError, OverflowError):
        return None


def _values(value: object) -> list[object]:
    """A flat list of candidate values; one nested list (an ECS field that is itself a list) is opened up."""
    if value is None:
        return []
    found: list[object] = []
    for item in value if isinstance(value, (list, tuple, set)) else [value]:
        found.extend(item if isinstance(item, (list, tuple, set)) else [item])
    return found


def entities(**found: object) -> dict[str, list[str]]:
    """Validated, de-duplicated entity lists; values that are not what their kind says are dropped."""
    result: dict[str, list[str]] = {kind: [] for kind in ENTITY_KINDS}
    for kind, values in found.items():
        for raw in _values(values):
            value = text(raw, 2048)
            if value is None:
                continue
            if kind == "ips":
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    continue
            elif kind == "hashes":
                value = value.lower()
                if not HASH.fullmatch(value):
                    continue
            elif kind == "domains":
                value = value.lower().rstrip(".")
                if not DOMAIN.fullmatch(value):
                    continue
            elif kind == "urls" and not value.lower().startswith(("http://", "https://")):
                continue
            elif kind in {"hosts", "users"}:
                value = value[:255]
            if value not in result[kind] and len(result[kind]) < MAX_ENTITIES:
                result[kind].append(value)
    return result


def mitre(*values: object) -> list[str]:
    found: list[str] = []
    for raw in values:
        for item in _values(raw):
            for match in MITRE_ID.findall(str(item).upper()):
                if match not in found and len(found) < 30:
                    found.append(match)
    return found


def alert(
    *,
    external_id: object,
    title: object,
    severity: str,
    time: object,
    rule_id: object,
    rule_name: object,
    description: object,
    found: dict[str, list[str]],
    techniques: list[str],
) -> dict[str, Any]:
    normalized_title = text(title, 255) or text(rule_name, 255) or "Untitled alert"
    return {
        "external_id": text(external_id, 255),
        "title": normalized_title,
        "severity": severity if severity in SEVERITIES else "medium",
        "time": timestamp(time),
        "rule_id": text(rule_id, 255),
        "rule_name": text(rule_name, 255),
        "description": text(description, 4000) or "",
        "entities": found,
        "mitre": techniques,
    }
