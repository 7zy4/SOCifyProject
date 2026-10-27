from flask import current_app

from .db import get_db


def operational_mode() -> bool:
    return not (current_app.config.get("TESTING") and current_app.config.get("LEGACY_TRAINING_TESTS"))


def case_scope(user: dict, alias: str = "c") -> tuple[str, list[object]]:
    if not operational_mode() or user.get("role") in {"soc_manager", "admin"}:
        return "", []
    return (
        f" AND ((NOT EXISTS (SELECT 1 FROM autopsy_case_context x WHERE x.case_id = {alias}.id) AND ({alias}.creator = ? OR {alias}.assignee = ?)) OR EXISTS (SELECT 1 FROM autopsy_case_members m WHERE m.case_id = {alias}.id AND m.user_id = ?))",
        [user["id"], user["id"], user["id"]],
    )


def case_visible(case_id: int, user: dict) -> bool:
    scope, args = case_scope(user)
    return (
        get_db()
        .execute(
            f"SELECT 1 FROM incident_cases c WHERE c.id = ? AND c.workspace_id = ? AND c.archived_at IS NULL{scope}", (case_id, user["workspace_id"], *args)
        )
        .fetchone()
        is not None
    )
