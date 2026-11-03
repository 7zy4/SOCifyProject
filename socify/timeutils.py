from datetime import UTC, datetime

from .validation import ValidationError


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(float(value), UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise ValidationError("timestamp is outside the supported range") from exc
    elif isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            raise ValidationError("timestamp is empty")
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValidationError("timestamp must be ISO 8601 with a timezone") from exc
    else:
        raise ValidationError("timestamp must be ISO 8601 or Unix time")
    if parsed.tzinfo is None:
        raise ValidationError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def iso_timestamp(value: object) -> str:
    return parse_timestamp(value).isoformat().replace("+00:00", "Z")
