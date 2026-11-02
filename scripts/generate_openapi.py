import json
from pathlib import Path
from typing import Any

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
            operation: dict[str, Any] = {
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
            if path == "/api/profile/display-name":
                operation["summary"] = "Save the authenticated user's display names"
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name_ar", "name_en"],
                                "additionalProperties": False,
                                "properties": {key: {"type": "string", "maxLength": 100} for key in ("name_ar", "name_en")},
                            }
                        }
                    },
                }
                operation["description"] = (
                    "User-authored names are selected by interface language. Empty values fall back to the registered name. Account identity, email and role do not change."
                )
                operation["responses"]["422"] = {"description": "Invalid name or unknown field"}
            elif path == "/api/audit":
                operation["summary"] = "Search retained workspace activity"
                operation["description"] = (
                    "Requires audit.read. Searches literal text in actor names, operations, resource identifiers, trace IDs and retained redacted details. Case titles and references are searchable and returned only when that case is visible to the caller. Filter choices are workspace-scoped. Results are newest first; filters and pagination never change the underlying audit history."
                )
                operation["parameters"] = [
                    {"name": "q", "in": "query", "schema": {"type": "string", "maxLength": 200}},
                    *[{"name": key, "in": "query", "schema": {"type": "string", "maxLength": 100}} for key in ("action", "resource", "result")],
                    {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 1000000, "default": 1}},
                    {"name": "page_size", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100}},
                ]
                operation["responses"]["422"] = {"description": "Search or filter exceeds its length limit"}
            elif path == "/api/soc/performance":
                operation["summary"] = "Team and personal operational performance"
                operation["description"] = (
                    "Current authorized backlog and period completions. Team/member selection is manager-only; analysts can select themselves. Missing evidenced times remain null. Excludes training, archived, unapproved and restricted-batch cases. Returns 422 above 2000 scoped cases; never silently samples."
                )
                operation["parameters"] = [
                    {"name": "days", "in": "query", "schema": {"type": "string", "enum": ["7", "30", "90", "all"], "default": "30"}},
                    {"name": "member", "in": "query", "schema": {"type": "string"}, "description": "me, team, or an authorized workspace member ID"},
                ]
                operation["responses"]["422"] = {"description": "Invalid filters or scope exceeds the bounded dashboard size"}
            elif path.endswith("/dossier"):
                operation["summary"] = "Retained alert investigation dossier"
                operation["description"] = (
                    "Full case scope required. Includes alert review, up to 50 linked events, case decisions, tasks and shared notes. Private notes are excluded. Case decisions are distinct from the alert verdict."
                )
            elif path.endswith("/content-inspection"):
                operation["summary"] = "Retained content inspection findings and decoded text"
                operation["description"] = (
                    "Full case scope required. Latest active case events with deterministic inspection results, 25 per page. Findings redact detected secret/financial values. Offsets are zero-based characters within the named source field or decoded layer. Original evidence is preserved separately. No execution or network lookups."
                )
                operation["parameters"] = parameters + [{"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 1000000}}]
                operation["responses"].update({"404": {"description": "Case unavailable"}, "422": {"description": "Invalid pagination"}})
            elif path.endswith("/observed-hosts"):
                operation["summary"] = "Hosts and process observations from active uploaded logs"
                operation["parameters"] = parameters + [
                    {"name": "q", "in": "query", "schema": {"type": "string", "maxLength": 200}},
                    {"name": "host", "in": "query", "schema": {"type": "string", "maxLength": 512}},
                    {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 1000000}},
                ]
                operation["description"] = (
                    "25 grouped hostnames per page; latest 50 events for an exact selected hostname. Event evidence is retained log data, not a live endpoint inventory."
                )
            elif path == "/api/soc/monitoring":
                operation["summary"] = "Authorized SOC monitoring queue"
                operation["description"] = (
                    "Counts and rows are restricted to the server-session investigation selection, approved cases, workspace membership and full batch-scope authorization. No selection yields zero rows. Channels derive from linked case status. Search matches rule, alert ID or case reference/title."
                )
                query_fields = {
                    "channel": {"type": "string", "enum": ["main", "investigation", "closed"], "default": "main"},
                    "page": {"type": "integer", "minimum": 1, "maximum": 1000000, "default": 1},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 25},
                    "q": {"type": "string", "maxLength": 200},
                    "case_id": {"type": "integer", "minimum": 1, "maximum": 9223372036854775807},
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
            contracts: dict[str, dict[str, Any]] = {
                "/api/investigation-selection": {
                    "case_ids": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 2,
                        "uniqueItems": True,
                        "items": {"type": "integer", "minimum": 1, "maximum": 9223372036854775807},
                    }
                },
                "/api/cases/{case_id}/approval": {
                    "decision": {"type": "string", "enum": ["approved", "rejected"]},
                    "version": {"type": "integer", "minimum": 1},
                    "reason": {"type": "string", "minLength": 3, "maxLength": 1000},
                },
                "/api/cases/{case_id}/relationships": {
                    "related_case_id": {"type": "integer", "minimum": 1, "maximum": 9223372036854775807},
                    "reason": {"type": "string", "minLength": 3, "maxLength": 1000},
                },
                "/api/demo/switch": {"user_id": {"type": "integer", "minimum": 1, "maximum": 9223372036854775807}},
            }
            if path in contracts and method == "POST":
                fields = contracts[path]
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"type": "object", "additionalProperties": False, "required": list(fields), "properties": fields}}
                    },
                }
                operation["responses"].update(
                    {
                        "404": {"description": "Resource unavailable within workspace scope"},
                        "409": {"description": "Manager approval required, already decided, or stale version"},
                        "422": {"description": "Invalid fields, bounds or unrelated pair"},
                    }
                )
            if path == "/api/investigation-selection":
                operation["description"] = (
                    "Requires cases.read. Select one approved visible case or two approved visible cases with an explicit manager-created relationship. Selection is revalidated on every request; revoked membership or an invalid relationship clears the entire selection."
                )
            elif path.endswith("/approval"):
                operation["description"] = (
                    "Manager/admin with cases.override only. When case approval is required, each new case starts pending. A versioned decision is atomic, final, audited and recorded in custody. With this policy enabled, case work is blocked until approval. Existing cases retain their recorded access after migration."
                )
            elif path.startswith("/api/demo/"):
                operation["description"] = (
                    "Available only with explicit DEMO_MODE in development and a signed-in account in the isolated demo registry. Switching is restricted to registered active accounts in the same workspace without MFA. The previous session is revoked, a new session is created and case selection is cleared. Production refuses demo mode."
                )
            paths.setdefault(path, {})[method.lower()] = operation
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "SOCify Tactical Workbench API",
            "version": "current",
            "description": "Fast-triage SOC workbench API for SIEM log ingestion, built-in detection rules, safe static file and email inspection, suspicious IP and email watchlists, direct case ownership, and guided printable reporting with manager escalation. All writes require an authenticated session, permission and CSRF token.",
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
