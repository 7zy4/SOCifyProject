import logging
import time
from pathlib import Path
from typing import Any

from flask import Flask, g, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix

from .auth import auth_api
from .autopsy_api import autopsy_api
from .autopsy_capsules import autopsy_capsules_api
from .autopsy_chronology import autopsy_chronology_api
from .autopsy_detection import autopsy_detection_api
from .autopsy_email import autopsy_email_api
from .autopsy_ingestion import autopsy_ingestion_api
from .autopsy_intel import autopsy_intel_api
from .autopsy_investigation import autopsy_investigation_api
from .autopsy_procedures import autopsy_procedures_api
from .autopsy_reports import autopsy_reports_api
from .autopsy_samples import autopsy_samples_api
from .autopsy_soc import autopsy_soc_api
from .autopsy_workflow import autopsy_workflow_api
from .autopsy_workspace import autopsy_workspace_api
from .autopsy_yara import autopsy_yara_api
from .cases import cases_api
from .codespaces_proxy import CodespacesProxy
from .config import build_config
from .db import close_db, connect_path
from .operational import operational_mode
from .platform import platform_api
from .request_limits import BoundedRequest, NumericInputError, StructureLimitError
from .schema import ensure_schema
from .security import correlation_id, error_response
from .soc_insights import soc_insights_api
from .sources import sources_api
from .teams import teams_api
from .ui import ui

csrf = CSRFProtect()

# Operational-mode routing policy; tests/security/test_route_policy_sweep.py checks every name against the URL map.
RETIRED_API_PREFIXES = frozenset(
    {
        "training",
        "scores",
        "scenarios",
        "assessments",
        "leaderboards",
        "lab",
        "playbooks",
        "playbook-runs",
        "hunt",
        "iocs",
        "attack",
        "visualizations",
        "stream",
        "events",
        "rules",
        "imports",
        "dashboard",
        "stats",
        "settings",
    }
)
OPERATIONAL_BLUEPRINTS = frozenset({"auth", "cases", "teams", "sources", "watchlist", "quick_reports"})
OPERATIONAL_LEGACY_ENDPOINTS = frozenset({"platform.audit_logs", "platform.role_matrix", "platform.health_api"})
OPERATIONAL_BLUEPRINT_PREFIX = "autopsy"


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    root = Path(__file__).parent.parent
    app = Flask(__name__, template_folder=str(root / "templates"), static_folder=str(root / "static"))
    app.request_class = BoundedRequest
    app.config.update(build_config())
    if test_config:
        app.config.update(test_config)
    if app.config.get("DEMO_MODE") and app.config["ENV_NAME"] != "development":
        raise RuntimeError("Demo account switching is restricted to development")
    proxy_hops = int(app.config.get("TRUSTED_PROXY_HOPS") or 0)
    if proxy_hops > 0:
        # Only the client address is taken from the proxy chain; scheme and host stay governed by SOCIFY_HTTPS and TRUSTED_HOSTS.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxy_hops, x_proto=0, x_host=0, x_port=0, x_prefix=0)  # type: ignore[method-assign]
    if app.config["ENV_NAME"] == "development" and app.config.get("CODESPACE_PUBLIC_HOST"):
        app.wsgi_app = CodespacesProxy(app.wsgi_app, app.config["CODESPACE_PUBLIC_HOST"])  # type: ignore[method-assign]

    @app.context_processor
    def product_context():
        return {"product_name": app.config["PRODUCT_NAME"] if operational_mode() else "SOCify", "operational": operational_mode()}

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    @app.before_request
    def start_request_timer():
        # Registered before CSRFProtect, so a request it rejects still gets the usual request log line.
        g.request_started = time.perf_counter()

    csrf.init_app(app)
    app.teardown_appcontext(close_db)
    for blueprint in (
        ui,
        autopsy_workspace_api,
        autopsy_api,
        autopsy_ingestion_api,
        autopsy_procedures_api,
        autopsy_reports_api,
        autopsy_samples_api,
        autopsy_soc_api,
        soc_insights_api,
        autopsy_email_api,
        autopsy_intel_api,
        autopsy_capsules_api,
        autopsy_chronology_api,
        autopsy_detection_api,
        autopsy_workflow_api,
        autopsy_yara_api,
        autopsy_investigation_api,
        auth_api,
        cases_api,
        sources_api,
        platform_api,
        teams_api,
    ):
        app.register_blueprint(blueprint)
    from .quick_reports import quick_reports_api
    from .sources import source_webhook_ingest
    from .watchlist import watchlist_api

    app.register_blueprint(watchlist_api)
    app.register_blueprint(quick_reports_api)
    csrf.exempt(source_webhook_ingest)

    @app.before_request
    def prepare_request():
        request.environ["socify.correlation_id"] = correlation_id()
        if any(type(value) is int and not 1 <= value <= 9223372036854775807 for value in (request.view_args or {}).values()):
            return error_response("INVALID_IDENTIFIER", "معرف المورد خارج النطاق المسموح", 404)
        if (
            operational_mode()
            and request.path.startswith("/api/")
            and (request.blueprint is not None or request.path.split("/", 3)[2] in RETIRED_API_PREFIXES)
            and request.blueprint not in OPERATIONAL_BLUEPRINTS
            and request.endpoint not in OPERATIONAL_LEGACY_ENDPOINTS
            and not str(request.blueprint or "").startswith(OPERATIONAL_BLUEPRINT_PREFIX)
        ):
            return error_response("CASE_CONTEXT_REQUIRED", "استخدم الأداة من داخل قضية مصرح بها؛ مسارات التدريب العامة متقاعدة", 410)
        if operational_mode():
            from .autopsy_pipeline import guard_batch_scope
            from .autopsy_workspace import guard_workspace

            return guard_workspace() or guard_batch_scope()

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Correlation-ID"] = correlation_id()
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/") or request.path.startswith("/health/") or response.mimetype == "text/html":
            response.headers.setdefault("Cache-Control", "no-store")
        started = g.pop("request_started", None)
        if started is not None and request.endpoint != "static" and not request.path.startswith("/health/"):
            # The path excludes the query string; bodies, headers and credentials are never logged.
            user = g.get("current_user")
            app.logger.info(
                "request method=%s path=%s status=%s duration_ms=%.1f correlation_id=%s user_id=%s",
                request.method,
                request.path,
                response.status_code,
                (time.perf_counter() - started) * 1000,
                correlation_id(),
                user["id"] if isinstance(user, dict) else "-",
            )
        return response

    @app.errorhandler(CSRFError)
    def csrf_failure(error: CSRFError):
        reasons = {
            "The CSRF token is missing.": ("TOKEN_MISSING", "لم يصل رمز حماية النموذج. افتح صفحة تسجيل الدخول من جديد وأعد المحاولة."),
            "The CSRF session token is missing.": (
                "SESSION_MISSING",
                "تعذّر استعادة جلسة النموذج. افتح الموقع من Ports في نافذة متصفح مستقلة واسمح بملفات الارتباط.",
            ),
            "The CSRF token has expired.": ("TOKEN_EXPIRED", "انتهت صلاحية النموذج. أعد إدخال بياناتك في النموذج الجديد."),
            "The CSRF token is invalid.": ("TOKEN_INVALID", "تعذّر التحقق من رمز النموذج. افتح صفحة تسجيل الدخول من جديد وأعد المحاولة."),
            "The CSRF tokens do not match.": ("TOKEN_MISMATCH", "تغيرت جلسة النموذج. أعد إدخال بياناتك في النموذج الجديد."),
            "The referrer header is missing.": ("REFERRER_MISSING", "لم يرسل المتصفح عنوان صفحة النموذج. افتح الموقع من Ports في نافذة متصفح مستقلة."),
            "The referrer does not match the host.": (
                "REFERRER_MISMATCH",
                "عنوان صفحة النموذج يختلف عن عنوان الخادم. افتح صفحة تسجيل الدخول من عنوان Ports نفسه.",
            ),
        }
        reason, message = reasons.get(error.description, ("VALIDATION_FAILED", "تعذّر التحقق من حماية النموذج. افتح صفحة تسجيل الدخول من جديد."))
        identifier = correlation_id()
        app.logger.warning("csrf_rejected reason=%s correlation_id=%s", reason, identifier)
        if not request.is_json and request.path in {"/login", "/register"}:
            template = "login.html" if request.path == "/login" else "register.html"
            return render_template(
                template,
                csrf_token=generate_csrf(),
                csrf_error=f"{message} الرمز يُنشأ تلقائيًا ولا تحتاج إلى إدخاله.",
                csrf_reason=reason,
                csrf_correlation_id=identifier,
            ), 400
        return error_response("CSRF_VALIDATION_FAILED", "رمز الحماية مفقود أو منتهي. حدّث الصفحة وأعد المحاولة", 400, {"reason": reason})

    @app.errorhandler(404)
    def not_found(_: Exception):
        if request.path.startswith("/api/"):
            return error_response("NOT_FOUND", "المورد المطلوب غير موجود", 404)
        return render_template("unavailable.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(_: Exception):
        return error_response("METHOD_NOT_ALLOWED", "طريقة الطلب غير مسموحة لهذا المورد", 405)

    @app.errorhandler(413)
    def too_large(_: Exception):
        return error_response("UPLOAD_TOO_LARGE", "حجم الطلب يتجاوز الحد المسموح", 413)

    @app.errorhandler(OverflowError)
    def number_out_of_range(_: OverflowError):
        return error_response("NUMBER_OUT_OF_RANGE", "قيمة رقمية تتجاوز النطاق المسموح", 422)

    @app.errorhandler(RecursionError)
    @app.errorhandler(StructureLimitError)
    def structure_too_deep(_: Exception):
        return error_response("STRUCTURE_LIMIT_EXCEEDED", "عمق البيانات أو عدد عناصرها يتجاوز الحد المسموح", 422)

    @app.errorhandler(NumericInputError)
    def numeric_input_invalid(_: Exception):
        return error_response("NUMERIC_INPUT_OUT_OF_RANGE", "استخدم أعدادًا منتهية ومعرفات ضمن نطاق الأعداد الصحيحة المسموح", 422)

    @app.errorhandler(500)
    def internal_error(error: Exception):
        app.logger.error("request_failed correlation_id=%s error_type=%s", correlation_id(), type(error).__name__)
        return error_response("INTERNAL_ERROR", "تعذر إكمال الطلب. استخدم معرف الارتباط عند التواصل مع المسؤول", 500)

    with app.app_context():
        connection = connect_path(str(app.config["DATABASE"]), bool(app.config.get("TESTING")))
        try:
            ensure_schema(connection)
        finally:
            connection.close()
    return app
