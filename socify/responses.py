"""Headers every response carries and the one log line written per request."""

import time

from flask import Flask, g, request

from .security import correlation_id


def register_response_policy(app: Flask) -> None:
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
