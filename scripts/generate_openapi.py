import json
from pathlib import Path

from socify import create_app


def generate() -> dict[str, object]:
    app = create_app({"TESTING": True, "DATABASE": ":memory:", "SECRET_KEY": "openapi-generation-only", "CREDENTIAL_KEY": "openapi-generation-only"})
    paths: dict[str, dict[str, object]] = {}
    for rule in sorted(app.url_map.iter_rules(), key=lambda item: item.rule):
        if not rule.rule.startswith("/api/") and not rule.rule.startswith("/health/"):
            continue
        path = rule.rule
        for argument in rule.arguments:
            path = (
                path.replace(f"<int:{argument}>", "{" + argument + "}")
                .replace(f"<path:{argument}>", "{" + argument + "}")
                .replace(f"<{argument}>", "{" + argument + "}")
            )
        parameters = [
            {"name": argument, "in": "path", "required": True, "schema": {"type": "integer" if f"<int:{argument}>" in rule.rule else "string"}}
            for argument in sorted(rule.arguments)
        ]
        for method in sorted(set(rule.methods or ()) - {"HEAD", "OPTIONS"}):
            operation: dict[str, object] = {
                "operationId": rule.endpoint.replace(".", "_") + "_" + method.lower() + "_" + path.replace("/", "_").replace("{", "").replace("}", ""),
                "responses": {
                    "200": {"description": "Successful response"},
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                },
            }
            if parameters:
                operation["parameters"] = parameters
            if method in {"POST", "PUT", "PATCH"}:
                operation["requestBody"] = {"required": False, "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}}
            paths.setdefault(path, {})[method.lower()] = operation
    return {
        "openapi": "3.1.0",
        "info": {"title": "SOCify Training Platform API", "version": "2.0.0"},
        "servers": [{"url": "/"}],
        "paths": paths,
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error", "correlation_id"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {"code": {"type": "string"}, "message": {"type": "string"}, "details": {"type": "object"}},
                        },
                        "correlation_id": {"type": "string"},
                    },
                }
            },
            "responses": {
                "BadRequest": {"description": "Invalid request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "Unauthorized": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                "Forbidden": {"description": "Permission denied", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
            },
        },
    }


if __name__ == "__main__":
    destination = Path("docs/api/openapi.yaml")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(generate(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
