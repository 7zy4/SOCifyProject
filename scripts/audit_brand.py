"""Validate shared V4 tokens and render real bilingual operational pages."""

import argparse
import json
import logging
import secrets
import shutil
import tempfile
import threading
from pathlib import Path

from scripts.generate_brand_guide import generate
from scripts.generate_interface_tokens import generate as generate_tokens
from socify.report_brand import design_tokens

ROOT = Path(__file__).resolve().parents[1]


def contrast(first: str, second: str) -> float:
    def luminance(value):
        values = [int(value[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        values = [channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4 for channel in values]
        return sum(channel * weight for channel, weight in zip(values, (0.2126, 0.7152, 0.0722), strict=True))

    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def validate_tokens() -> list[dict]:
    tokens = design_tokens()
    if (ROOT / "static/tokens.css").read_text() != generate_tokens():
        raise RuntimeError("Generated tokens differ from their source")
    for font in tokens["fonts"]:
        if not (ROOT / "static/fonts" / font["file"]).is_file():
            raise RuntimeError("Missing bundled font: " + font["file"])
    checks = []
    for index, mode in enumerate(("light", "dark")):
        for foreground, background in [
            ("text", "panel"),
            ("text", "panel-2"),
            ("muted", "panel"),
            ("muted", "panel-2"),
            ("blue", "panel"),
            ("blue", "panel-2"),
            ("red", "red-bg"),
            ("high", "high-bg"),
            ("amber", "amber-bg"),
            ("success", "success-bg"),
            ("on-primary", "primary-fill"),
            ("on-primary", "primary-hover"),
            ("terminal-text", "terminal-bg"),
        ]:
            ratio = contrast(tokens["colors"][foreground][index], tokens["colors"][background][index])
            checks.append({"mode": mode, "foreground": foreground, "background": background, "contrast": round(ratio, 3)})
            if ratio < 4.5:
                raise RuntimeError(f"{mode}: {foreground}/{background} contrast is {ratio:.2f}, below 4.5")
    return checks


def audit_pages(output: Path) -> list[dict]:
    from playwright.sync_api import sync_playwright
    from werkzeug.serving import make_server

    from scripts.prepare_v4_demo import provision
    from socify import create_app
    from socify.db import get_db
    from socify.seeding import _user

    with tempfile.TemporaryDirectory(prefix="socify-v4-brand-") as temporary:
        directory = Path(temporary) / "demo"
        manifest = provision(directory)
        keys = dict(line.split("=", 1) for line in (directory / "runtime.env").read_text().splitlines())
        app = create_app(
            {
                "DATABASE": str(directory / "socify.db"),
                "ENV_NAME": "development",
                "DEMO_MODE": True,
                "SECRET_KEY": keys["SOCIFY_SECRET_KEY"],
                "CREDENTIAL_KEY": keys["SOCIFY_CREDENTIAL_KEY"],
            }
        )
        # An ephemeral, authenticated administrator exercises restricted pages.
        # Do not change demo roles or bypass production authorization checks.
        audit_password = secrets.token_urlsafe(32) + "!7aA"
        with app.app_context():
            _user(get_db(), "audit@synthetic.socify.test", "Visual audit", "admin", "Synthetic audit", audit_password)
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        results = []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=shutil.which("chromium") or shutil.which("google-chrome"))
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                base = f"http://127.0.0.1:{server.server_port}"
                page.goto(base + "/login")
                page.locator("input[name=email]").fill("audit@synthetic.socify.test")
                page.locator("input[name=password]").fill(audit_password)
                page.locator("button[type=submit]").click()
                page.wait_for_url("**/cases")
                case_id = manifest["primary_case"]
                page.locator(f'.case-selection-card input[value="{case_id}"]').check()
                page.get_by_role("button", name="بدء التحقيق بالنطاق المحدد", exact=True).click()
                page.wait_for_url(f"**/cases/{case_id}")
                sections = [
                    "dashboard",
                    "monitoring",
                    "log-management",
                    "cases",
                    "endpoint-security",
                    "threat-intel",
                    "email-security",
                    "sandbox",
                    "reports",
                    "my-tasks",
                    "playbooks",
                    "analysis-library",
                    "team",
                    "profile",
                    "audit",
                    "admin",
                    f"cases/{case_id}",
                ]
                for language in ("ar", "en"):
                    for mode in ("dark", "light"):
                        page.evaluate(
                            '([lang,theme])=>{localStorage.setItem("socify-interface-language",lang);localStorage.setItem("socify-interface-theme",theme)}',
                            [language, mode],
                        )
                        for width in (1440, 390):
                            page.set_viewport_size({"width": width, "height": 1000})
                            for section in sections:
                                response = page.goto(base + "/" + section + (f"?case_id={case_id}" if section != "monitoring" else ""))
                                page.locator('#workspace[aria-busy="false"]').wait_for()
                                page.evaluate("document.fonts.ready")
                                measurement = page.evaluate(
                                    "({width:innerWidth,scroll:document.documentElement.scrollWidth,language:document.documentElement.lang,theme:document.documentElement.dataset.theme,font:getComputedStyle(document.body).fontFamily})"
                                )
                                if not response or not response.ok or errors or measurement["scroll"] > width:
                                    raise RuntimeError(f"Visual audit failed at {section}: {measurement}; errors={errors}")
                                if measurement["language"] != language or measurement["theme"] != mode:
                                    raise RuntimeError("Language or theme selection was lost")
                                slug = section.replace("/", "-")
                                page.screenshot(path=str(output / f"{slug}-{language}-{mode}-{width}.png"), full_page=True)
                                results.append({"route": section, "resolved_url": page.url, **measurement})
                browser.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)
        return results


def run() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokens-only", action="store_true", help="Validate tokens only; does not claim browser acceptance")
    arguments = parser.parse_args()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    output = ROOT / "artifacts/brand"
    output.mkdir(parents=True, exist_ok=True)
    contrasts = validate_tokens()
    generate(output)
    pages = [] if arguments.tokens_only else audit_pages(output)
    report = {"token_checks": contrasts, "pages": pages, "browser_verified": not arguments.tokens_only}
    (output / "visual-audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({"contrast_pairs": len(contrasts), "pages": len(pages), "browser_verified": not arguments.tokens_only}))


if __name__ == "__main__":
    run()
