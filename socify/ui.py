from flask import Blueprint, redirect, render_template, request
from flask_wtf.csrf import generate_csrf

from .case_policy import ANY_METHOD, case_policy
from .security import current_user, login_required

ui = Blueprint("ui", __name__)


@ui.get("/")
def index():
    return redirect("/cases" if current_user() else "/login")


@ui.get("/playbooks")
@ui.get("/audit")
@ui.get("/admin")
@ui.get("/profile")
@ui.get("/team")
@ui.get("/monitoring")
@ui.get("/performance")
@ui.get("/log-management")
@ui.get("/endpoint-security")
@ui.get("/threat-intel")
@ui.get("/email-security")
@ui.get("/sandbox")
@ui.get("/reports")
@ui.get("/cases")
@ui.get("/my-tasks")
@ui.get("/analysis-library")
@ui.get("/cases/<int:case_id>")
@case_policy(before_approval=ANY_METHOD, batch_member={"GET"})
@login_required
def dashboard(case_id: int | None = None):
    from .cases import _case_row
    from .security import has_permission

    if request.path in {
        "/monitoring",
        "/performance",
        "/log-management",
        "/endpoint-security",
        "/threat-intel",
        "/email-security",
        "/sandbox",
        "/reports",
    } and not has_permission(current_user(), "cases.read"):
        return render_template("unavailable.html"), 403
    if case_id is not None and not _case_row(case_id):
        return render_template("unavailable.html"), 404
    if (
        request.path
        not in {
            "/cases",
            "/my-tasks",
            "/team",
            "/profile",
            "/playbooks",
            "/analysis-library",
            "/audit",
            "/admin",
            "/monitoring",
            "/performance",
            "/log-management",
            "/endpoint-security",
            "/threat-intel",
            "/email-security",
            "/sandbox",
            "/reports",
        }
        and case_id is None
    ):
        return redirect("/cases")
    return render_template(
        "app.html",
        user=current_user(),
        section="case" if case_id else request.path.strip("/"),
        csrf_token=generate_csrf(),
        case_id=case_id,
    )
