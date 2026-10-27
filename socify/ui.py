from flask import Blueprint, redirect, render_template, request, url_for
from flask_wtf.csrf import generate_csrf

from .operational import operational_mode
from .security import current_user, login_required

ui = Blueprint("ui", __name__)


@ui.get("/")
def index():
    if operational_mode():
        return redirect("/cases" if current_user() else "/login")
    return render_template("index.html", user=current_user())


@ui.get("/test")
def test_redirect():
    return redirect(url_for("ui.dashboard"))


@ui.get("/dashboard")
@ui.get("/events")
@ui.get("/alerts")
@ui.get("/rules")
@ui.get("/sources")
@ui.get("/imports")
@ui.get("/incidents")
@ui.get("/lab")
@ui.get("/attack")
@ui.get("/hunt")
@ui.get("/graph")
@ui.get("/playbooks")
@ui.get("/scores")
@ui.get("/audit")
@ui.get("/admin")
@ui.get("/profile")
@ui.get("/team")
@ui.get("/monitoring")
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
@login_required
def dashboard(case_id: int | None = None):
    if operational_mode():
        from .cases import _case_row
        from .security import error_response, has_permission

        if request.path in {
            "/monitoring",
            "/log-management",
            "/endpoint-security",
            "/threat-intel",
            "/email-security",
            "/sandbox",
            "/reports",
        } and not has_permission(current_user(), "cases.read"):
            return error_response("PERMISSION_DENIED", "هذا القسم غير متاح لدورك", 403)
        if case_id is not None and not _case_row(case_id):
            return error_response("CASE_NOT_FOUND", "القضية غير متاحة", 404)
        if request.path in {"/lab", "/scores"}:
            return error_response("FEATURE_RETIRED", "وظائف التدريب متقاعدة في النسخة التشغيلية", 410)
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
            operational=True,
            case_id=case_id,
        )
    section = request.path.strip("/") or "dashboard"
    return render_template("app.html", user=current_user(), section=section, csrf_token=generate_csrf(), operational=False)
