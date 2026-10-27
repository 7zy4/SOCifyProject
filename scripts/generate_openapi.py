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
            if path == "/api/soc/monitoring":
                operation["summary"] = "Authorized SOC monitoring queue"
                operation["description"] = (
                    "Counts and rows share case/workspace membership and full batch-scope authorization. Channels derive from linked case status; no alerts are invented. Search matches rule, alert ID or case reference/title."
                )
                query_fields = {
                    "channel": {"type": "string", "enum": ["main", "investigation", "closed"], "default": "main"},
                    "page": {"type": "integer", "minimum": 1, "maximum": 1000000, "default": 1},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 25},
                    "q": {"type": "string", "maxLength": 200},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "mine": {"type": "string", "enum": ["0", "1"], "default": "0"},
                    "sort": {"type": "string", "enum": ["detected_at", "severity", "rule_name"]},
                    "direction": {"type": "string", "enum": ["asc", "desc"]},
                }
                operation["parameters"] = [{"name": key, "in": "query", "required": False, "schema": value} for key, value in query_fields.items()]
                operation["responses"]["422"] = {"description": "Unknown, duplicate or invalid filters"}
            elif path.endswith("/email-review"):
                operation["summary"] = "Inspect a quarantined EML and retain its analysis"
                operation["description"] = (
                    "Requires cases.update, evidence.download and full case scope. The original must be a retained .eml sample of at most 2 MiB with a valid digest. MIME inspection is static and does not verify authentication headers, visit URLs or execute attachments. An existing analysis is returned without duplication."
                )
                operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"type": "object", "maxProperties": 0}}}}
                operation["responses"].update(
                    {
                        "201": {"description": "New retained email analysis"},
                        "404": {"description": "Case or sample unavailable"},
                        "409": {"description": "Closed case or invalid sample integrity"},
                        "422": {"description": "Invalid MIME, body, file type or resource bound"},
                    }
                )
            elif path.endswith("/email-reviews"):
                operation["summary"] = "List retained email analyses in an authorized case"
                operation["parameters"] = parameters + [
                    {"name": "before", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": 9223372036854775807}}
                ]
                operation["description"] = (
                    "Returns at most 10 analyses and a next_before cursor. Full batch scope is required. No raw sample bytes are returned."
                )
            paths.setdefault(path, {})[method.lower()] = operation
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "SOCify Digital Autopsy API",
            "version": "3.0.0",
            "description": "Internal case-centered investigation. General training and unscoped legacy data endpoints return 410 in operational mode. V3 case creation requires title, reason and objective; structured record contracts are published by /api/autopsy/catalog. All writes require an authenticated session, permission and CSRF token.",
        },
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
