import logging
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf

from .attack import attack_api
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
from .detection import detection_api
from .events import events_api
from .hunting import hunting_api
from .ingestion import ingestion_api
from .operational import operational_mode
from .platform import platform_api
from .playbooks import playbooks_api
from .request_limits import BoundedRequest, NumericInputError, StructureLimitError
from .schema import ensure_schema
from .scoring import scoring_api
from .security import correlation_id, error_response
from .sources import sources_api
from .teams import teams_api
from .training import training_api
from .ui import ui
from .visualization import visualization_api


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    root = Path(__file__).parent.parent
    app = Flask(__name__, template_folder=str(root / "templates"), static_folder=str(root / "static"))
    app.request_class = BoundedRequest
    app.config.update(build_config())
    if test_config:
        app.config.update(test_config)
    if app.config.get("DEMO_MODE") and app.config["ENV_NAME"] != "development":
        raise RuntimeError("Demo account switching is restricted to development")
    if app.config["ENV_NAME"] == "development" and app.config.get("CODESPACE_PUBLIC_HOST"):
        app.wsgi_app = CodespacesProxy(app.wsgi_app, app.config["CODESPACE_PUBLIC_HOST"])  # type: ignore[method-assign]

    @app.context_processor
    def product_context():
        return {"product_name": app.config["PRODUCT_NAME"] if operational_mode() else "SOCify", "operational": operational_mode()}

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    CSRFProtect(app)
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
        autopsy_email_api,
        autopsy_intel_api,
        autopsy_capsules_api,
        autopsy_chronology_api,
        autopsy_detection_api,
        autopsy_workflow_api,
        autopsy_yara_api,
        autopsy_investigation_api,
        auth_api,
        events_api,
        detection_api,
        cases_api,
        sources_api,
        ingestion_api,
        training_api,
        attack_api,
        hunting_api,
        visualization_api,
        playbooks_api,
        scoring_api,
        platform_api,
        teams_api,
    ):
        app.register_blueprint(blueprint)

    @app.before_request
    def prepare_request():
        request.environ["socify.correlation_id"] = correlation_id()
        if any(type(value) is int and not 1 <= value <= 9223372036854775807 for value in (request.view_args or {}).values()):
            return error_response("INVALID_IDENTIFIER", "معرف المورد خارج النطاق المسموح", 404)
        if (
            operational_mode()
            and request.path.startswith("/api/")
            and (request.blueprint is not None or request.path.split("/", 3)[2] in {"training", "scores", "scenarios", "lab"})
            and request.blueprint not in {"auth", "cases", "teams"}
            and request.endpoint not in {"platform.audit_logs", "platform.role_matrix"}
            and not str(request.blueprint or "").startswith("autopsy")
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
        return jsonify({"error": "Not Found"}), 404

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
