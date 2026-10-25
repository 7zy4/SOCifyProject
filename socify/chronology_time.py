from .timeutils import parse_timestamp


def utc_key(value):
    return parse_timestamp(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def record_clock(alias=""):
    if alias not in {"", "r"}:
        raise ValueError("Unknown chronology source")
    prefix = alias + "." if alias else ""
    return f"CASE WHEN {prefix}kind='timeline' THEN json_extract({prefix}payload,'$.event_time') WHEN {prefix}kind='escalation' THEN COALESCE(json_extract({prefix}payload,'$.raised_at'),{prefix}created_at) WHEN {prefix}kind='response' AND json_extract({prefix}payload,'$.status') IN ('succeeded','failed') AND json_extract({prefix}payload,'$.performed_at') IS NOT NULL THEN json_extract({prefix}payload,'$.performed_at') ELSE {prefix}created_at END"


def sql_utc_key(expression):
    if expression not in {"ce.event_time", "event_time", "n.created_at", "created_at", record_clock(), record_clock("r")}:
        raise ValueError("Unknown chronology timestamp expression")
    return f"substr({expression},1,19)||'.'||substr((CASE WHEN substr({expression},20,1)='.' THEN replace(substr({expression},21),'Z','') ELSE '' END)||'000000',1,6)||'Z'"
