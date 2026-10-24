import json
import logging
import secrets
import shutil
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from scripts.generate_brand_guide import generate
from socify import create_app
from socify.db import connect_path
from socify.seeding import seed_demo_data


def run() -> None:
    output = Path("artifacts/brand").resolve()
    output.mkdir(parents=True, exist_ok=True)
    guide = generate(output)
    with tempfile.TemporaryDirectory(prefix="socify-brand-") as temporary:
        database = str(Path(temporary) / "review.db")
        app = create_app(
            {
                "DATABASE": database,
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
                "SECRET_KEY": secrets.token_urlsafe(32),
                "CREDENTIAL_KEY": secrets.token_urlsafe(32),
                "ALLOW_REGISTRATION": True,
            }
        )
        connection = connect_path(database, True)
        seed_demo_data(connection, "Visual-Review-Local-2026!")
        admin = connection.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()[0]
        connection.close()
        with app.test_client() as client:
            with client.session_transaction() as session:
                session["user_id"] = admin
                session["workspace_id"] = 1
            events = [
                client.post(
                    "/api/events",
                    json={
                        "source": "Visual review",
                        "title": f"سجل مصادقة Authentication {index}",
                        "severity": "high",
                        "event_type": "failed_login",
                        "source_ip": "198.51.100.20",
                    },
                ).get_json()["id"]
                for index in range(1, 6)
            ]
            case = client.post("/api/incidents", json={"title": "تحقيق الهوية البصرية · Incident review", "event_ids": events}).get_json()
            case_url = f"/api/incidents/{case['id']}"
            for task in client.get(case_url).get_json()["tasks"]:
                client.patch(f"{case_url}/tasks/{task['id']}", json={"status": "completed"})
            for status in ("investigating", "contained", "recovered"):
                client.post(case_url + "/transitions", json={"status": status, "reason": "التحقق من بيانات الاختبار"})
            closure = {"status": "closed", "reason": "اكتمال التحقق التجريبي"}
            closure.update(
                {
                    key: "تمت مراجعة الأدلة والنتائج ضمن بيئة اختبار معزولة."
                    for key in ("disposition", "root_cause", "impact", "response_summary", "evidence_summary", "lessons_learned", "validation")
                }
            )
            if client.post(case_url + "/transitions", json=closure).status_code != 200:
                raise RuntimeError("Visual review fixture could not close the case")
            incident_report = output / "SOCify-Incident-Report-Sample.html"
            incident_report.write_bytes(client.get(case_url + "/report?format=html").data)
            scenario = client.get("/api/scenarios").get_json()["items"][0]["id"]
            run_id = client.post("/api/training/runs", json={"scenario_id": scenario}).get_json()["id"]
            client.post(f"/api/training/runs/{run_id}/play", json={"steps": 50})
            score = client.post(f"/api/training/runs/{run_id}/submit", json={}).get_json()["assessment"]
            score_report = output / "SOCify-Assessment-Report-Sample.html"
            score_report.write_bytes(client.get(f"/api/assessments/{score['id']}/report").data)
            active = client.post("/api/training/runs", json={"scenario_id": scenario}).get_json()["id"]
            client.post(f"/api/training/runs/{active}/play", json={"steps": 1})
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        results = []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=shutil.which("chromium") or shutil.which("google-chrome"))
                page = browser.new_page(viewport={"width": 1440, "height": 1100})
                base = f"http://127.0.0.1:{server.server_port}"
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 1100})
                    for route in ("/", "/login", "/register"):
                        page.goto(base + route)
                        page.evaluate("document.fonts.ready")
                        measurements = page.evaluate(
                            "({width:innerWidth,scroll:document.documentElement.scrollWidth,font:getComputedStyle(document.body).fontFamily})"
                        )
                        results.append({"route": route, "viewport": width, **measurements})
                        page.screenshot(path=str(output / f"public-{route.strip('/') or 'home'}-{width}.png"), full_page=True)
                page.set_viewport_size({"width": 1440, "height": 1100})
                page.goto(base + "/login")
                page.locator("input[name=email]").fill("admin@socify.local")
                page.locator("input[name=password]").fill("Visual-Review-Local-2026!")
                page.locator("button[type=submit]").click()
                page.wait_for_url("**/dashboard")
                routes = [
                    "dashboard",
                    "events",
                    "alerts",
                    "rules",
                    "sources",
                    "imports",
                    f"incidents?selected={case['id']}",
                    "lab",
                    "attack",
                    "hunt",
                    "graph",
                    "playbooks",
                    "scores",
                    "audit",
                    "admin",
                    "profile",
                    "team",
                ]
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 1100})
                    for route in routes:
                        page.goto(base + "/" + route)
                        page.locator('#workspace[aria-busy="false"]').wait_for()
                        page.evaluate("document.fonts.ready")
                        slug = route.split("?")[0]
                        measurements = page.evaluate(
                            "({width:innerWidth,scroll:document.documentElement.scrollWidth,font:getComputedStyle(document.body).fontFamily,errors:document.getElementById('global-message').hidden?[]:[document.getElementById('global-message').textContent]})"
                        )
                        results.append({"route": route, "viewport": width, **measurements})
                        page.screenshot(path=str(output / f"{slug}-{width}.png"), full_page=True)
                page.set_viewport_size({"width": 1440, "height": 1100})
                page.goto(base + "/dashboard")
                page.locator('#workspace[aria-busy="false"]').wait_for()
                page.evaluate("document.documentElement.dir='ltr'")
                page.screenshot(path=str(output / "dashboard-ltr.png"), full_page=True)
                for source in (guide, incident_report, score_report):
                    page = browser.new_page(viewport={"width": 900, "height": 1200})
                    page.set_content(source.read_text())
                    page.evaluate("document.fonts.ready")
                    page.screenshot(path=str(source.with_suffix(".png")), full_page=True)
                    if source == guide:
                        bounds = page.locator(".guide-page").evaluate_all(
                            "pages=>pages.map(p=>({height:p.clientHeight,scroll:p.scrollHeight,contentBottom:p.querySelector('main').getBoundingClientRect().bottom-p.getBoundingClientRect().top}))"
                        )
                        results.append({"guide_pages": bounds})
                        if any(item["scroll"] > item["height"] or item["contentBottom"] > item["height"] - 40 * 4 / 3 for item in bounds):
                            raise RuntimeError("The identity guide exceeds its printable content bounds")
                    page.pdf(path=str(source.with_suffix(".pdf")), prefer_css_page_size=True, print_background=True)
                browser.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)
        (output / "visual-audit.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
        if any(item.get("scroll", 0) > item.get("width", float("inf")) or item.get("errors") for item in results):
            raise RuntimeError("Visual review found page overflow or an application error")
        print(output)


if __name__ == "__main__":
    run()
