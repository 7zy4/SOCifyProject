from .db import get_db


def case_scope(user: dict, alias: str = "c") -> tuple[str, list[object]]:
    """SQL condition and arguments limiting cases to those the user is a member of; managers and administrators see the whole team."""
    if user.get("role") in {"soc_manager", "admin"}:
        return "", []
    return (
        f" AND ((NOT EXISTS (SELECT 1 FROM autopsy_case_context x WHERE x.case_id = {alias}.id) AND ({alias}.creator = ? OR {alias}.assignee = ?)) OR EXISTS (SELECT 1 FROM autopsy_case_members m WHERE m.case_id = {alias}.id AND m.user_id = ?))",
        [user["id"], user["id"], user["id"]],
    )


def case_visible(case_id: int, user: dict) -> bool:
    """True when the case exists in the user's team, is not archived and the user is a member (or a manager)."""
    scope, args = case_scope(user)
    return (
        get_db()
        .execute(
            f"SELECT 1 FROM incident_cases c WHERE c.id = ? AND c.workspace_id = ? AND c.archived_at IS NULL{scope}", (case_id, user["workspace_id"], *args)
        )
        .fetchone()
        is not None
    )
