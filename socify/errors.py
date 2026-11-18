"""How the application answers requests that fail: CSRF rejections, unknown paths and refused input."""

from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFError, generate_csrf

from .request_limits import NumericInputError, StructureLimitError
from .security import correlation_id, error_response


def register_error_handlers(app: Flask) -> None:
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
