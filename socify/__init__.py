"""SOCify: create_app builds the Flask application; importing the package itself stays light.

Modules are imported inside create_app, so a small tool (such as a container health check) that imports one module
does not load Flask and every blueprint first.
"""

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flask import Flask


def create_app(test_config: dict[str, Any] | None = None) -> "Flask":
    from flask import Flask, g, request
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
    from .errors import register_error_handlers
    from .extensions import csrf
    from .platform import platform_api
    from .request_limits import BoundedRequest
    from .responses import register_response_policy
    from .schema import ensure_schema
    from .security import correlation_id, error_response
    from .soc_insights import soc_insights_api
    from .sources import sources_api
    from .static_assets import register_static_fingerprints
    from .teams import teams_api
    from .ui import ui

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
        return {"product_name": app.config["PRODUCT_NAME"]}

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
    from .api_tokens import api_tokens_api
    from .api_tokens import register as register_api_tokens
    from .intake import intake_api
    from .notifications import notifications_api
    from .onboarding import onboarding_api
    from .outbox import outbox_api
    from .quick_reports import quick_reports_api
    from .sources import source_webhook_ingest
    from .team_sla import team_sla_api
    from .watchlist import watchlist_api

    app.register_blueprint(watchlist_api)
    app.register_blueprint(quick_reports_api)
    app.register_blueprint(onboarding_api)
    app.register_blueprint(api_tokens_api)
    app.register_blueprint(outbox_api)
    app.register_blueprint(intake_api)
    app.register_blueprint(team_sla_api)
    app.register_blueprint(notifications_api)
    csrf.exempt(source_webhook_ingest)
    # Before prepare_request, so the workspace and batch guards see the token's account.
    register_api_tokens(app)

    @app.before_request
    def prepare_request():
        request.environ["socify.correlation_id"] = correlation_id()
        if any(type(value) is int and not 1 <= value <= 9223372036854775807 for value in (request.view_args or {}).values()):
            return error_response("INVALID_IDENTIFIER", "معرف المورد خارج النطاق المسموح", 404)
        from .autopsy_pipeline import guard_batch_scope
        from .autopsy_workspace import guard_workspace

        return guard_workspace() or guard_batch_scope()

    register_response_policy(app)
    register_static_fingerprints(app)
    register_error_handlers(app)

    with app.app_context():
        connection = connect_path(str(app.config["DATABASE"]), bool(app.config.get("TESTING")))
        try:
            ensure_schema(connection)
        finally:
            connection.close()
    return app
