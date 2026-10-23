import json
from pathlib import Path

from scripts.generate_openapi import generate


def test_openapi_matches_registered_service_routes(app) -> None:
    document = generate()
    paths = document["paths"]
    assert isinstance(paths, dict)
    expected = set()
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/") or rule.rule.startswith("/health/"):
            normalized = rule.rule
            for argument in rule.arguments:
                normalized = (
                    normalized.replace(f"<int:{argument}>", "{" + argument + "}")
                    .replace(f"<path:{argument}>", "{" + argument + "}")
                    .replace(f"<{argument}>", "{" + argument + "}")
                )
            expected.add(normalized)
    assert set(paths) == expected
    assert json.loads(Path("docs/api/openapi.yaml").read_text(encoding="utf-8"))["openapi"] == "3.1.0"
