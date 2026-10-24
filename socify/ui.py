from flask import Blueprint, redirect, render_template, request, url_for
from flask_wtf.csrf import generate_csrf

from .security import current_user, login_required

ui = Blueprint("ui", __name__)


@ui.get("/")
def index():
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
@login_required
def dashboard():
    section = request.path.strip("/") or "dashboard"
    return render_template("app.html", user=current_user(), section=section, csrf_token=generate_csrf())
