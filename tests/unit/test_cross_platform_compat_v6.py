import importlib
from zoneinfo import ZoneInfoNotFoundError

import pytest


def test_cross_platform_modules_import_cleanly():
    for module_name in (
        "socify.analysis_sandbox",
        "socify.analysis_transport",
        "socify.autopsy_worker",
        "scripts.start_v4_demo",
        "scripts.run_analysis_service",
        "scripts.start_codespace",
    ):
        imported = importlib.import_module(module_name)
        assert imported is not None


def test_ingestion_utc_fallback_when_system_tzdata_missing(monkeypatch):
    from datetime import UTC

    from socify import ingestion

    def missing_tz(key):
        raise ZoneInfoNotFoundError(key)

    monkeypatch.setattr(ingestion, "ZoneInfo", missing_tz)
    assert ingestion._resolve_timezone("UTC") is UTC
    assert ingestion._resolve_timezone("Etc/UTC") is UTC

    with pytest.raises(ZoneInfoNotFoundError):
        ingestion._resolve_timezone("Mars/Olympus")
