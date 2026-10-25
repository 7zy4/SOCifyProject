import argparse
import json
import os
import platform
import resource
import secrets
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scripts.benchmark_reference import distribution, git_revision, memory_total_bytes
from socify import create_app
from socify.autopsy_worker import run_autopsy_worker_once
from socify.db import connect_path, get_db
from socify.import_worker import run_import_worker_once
from socify.seeding import seed_demo_data


def ensure(condition, stage):
    if not condition:
        raise RuntimeError(f"Synthetic V3 capacity verification failed: {stage}")


def seed_capacity(connection, case_id, actor, count):
    start = connection.execute("SELECT COALESCE(MAX(id),0) FROM security_events").fetchone()[0]
    for offset in range(0, count, 10000):
        batch = min(10000, count - offset)
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """WITH RECURSIVE sequence(n) AS (VALUES(?) UNION ALL SELECT n+1 FROM sequence WHERE n<?)
            INSERT INTO security_events(event_id,external_id,idempotency_key,workspace_id,source,source_type,severity,category,event_type,title,description,event_time,ingested_at,timestamp,source_ip,hostname,raw_data,normalized_fields,tags,mitre_ids,status,created_by,parser_version,raw_hash,provenance,owner_case_id)
            SELECT printf('V3-CAP-%09d',n),printf('V3-CAP-%09d',n),printf('v3-capacity:%09d',n),1,'capacity-synthetic','synthetic','medium','capacity','capacity_event','Capacity synthetic event','Storage-query seed, not parser throughput','2026-10-20T10:00:00Z','2026-10-20T10:00:00Z','2026-10-20T10:00:00Z',printf('192.0.2.%d',n%64+1),'capacity.example.test','{}','{"event_time_known":true}','[]','[]','open',?,'capacity-fixture/1','','{"synthetic":true}',? FROM sequence""",
            (offset + 1, offset + batch, actor, case_id),
        )
        connection.execute(
            "INSERT INTO case_events(case_id,event_id,attached_by,attached_at) SELECT ?,id,?,'2026-10-20T10:00:00Z' FROM security_events WHERE id>? AND owner_case_id=?",
            (case_id, actor, start, case_id),
        )
        start = connection.execute("SELECT MAX(id) FROM security_events").fetchone()[0]
        connection.commit()
        if (offset + batch) % 100000 == 0:
            print(f"Seeded {offset + batch} synthetic storage events", flush=True)
    connection.execute("ANALYZE")
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def main():
    parser = argparse.ArgumentParser(description="Synthetic V3 case capacity and 20-user API benchmark; never use company data")
    parser.add_argument("--events", type=int, default=1000000)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    if not 1000 <= options.events <= 1000000 or not 1 <= options.concurrency <= 20 or not 20 <= options.requests <= 1000:
        parser.error("events:1000..1000000 concurrency:1..20 requests:20..1000")
    started, cpu = time.monotonic(), resource.getrusage(resource.RUSAGE_SELF)
    with tempfile.TemporaryDirectory(prefix="socify-v3-capacity-") as folder:
        path = Path(folder) / "synthetic.db"
        app = create_app(
            {
                "DATABASE": str(path),
                "TESTING": True,
                "LEGACY_TRAINING_TESTS": False,
                "SECRET_KEY": secrets.token_urlsafe(40),
                "CREDENTIAL_KEY": secrets.token_urlsafe(40),
                "WTF_CSRF_ENABLED": False,
                "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
                "MAX_IMPORT_ROWS": 10000,
            }
        )
        connection = connect_path(str(path))
        seed_demo_data(connection, secrets.token_urlsafe(28) + "Aa9!")
        actor = connection.execute("SELECT id FROM users WHERE role='soc_manager'").fetchone()[0]

        def client_for_actor():
            client = app.test_client()
            with client.session_transaction() as session:
                session.update(user_id=actor, workspace_id=1, user_role="soc_manager")
            return client

        client = client_for_actor()
        case = client.post(
            "/api/cases",
            json={"title": "Synthetic capacity investigation", "reason": "forensic_review", "objective": "Measure bounded V3 APIs against synthetic case data"},
        )
        ensure(case.status_code == 201, "case creation")
        case_id, base = case.json["id"], f"/api/cases/{case.json['id']}"
        original = "\n".join(
            json.dumps(
                {
                    "title": "Parsed capacity fixture",
                    "source_ip": f"198.51.100.{index % 64 + 1}",
                    "hostname": "parser.example.test",
                    "event_time": "2026-10-20T10:00:00Z",
                }
            )
            for index in range(10000)
        )
        import_start = time.monotonic()
        imported = client.post(base + "/imports", json={"filename": "capacity.jsonl", "content": original})
        ensure(imported.status_code == 201, "case import")
        with app.app_context():
            while run_import_worker_once(get_db(), "capacity-import", 120) is not None:
                pass
        job = client.get(base + f"/imports/{imported.json['id']}").json
        ensure(job["accepted"] == 10000 and job["rejected"] == 0, "10,000-row parser result")
        imported_seconds = time.monotonic() - import_start
        seed_start = time.monotonic()
        seed_capacity(connection, case_id, actor, max(0, options.events - 10000))
        seed_seconds = time.monotonic() - seed_start
        expected = max(options.events, 10000)
        ensure(client.get(base + "/logs").json["total"] == expected, "case event count")
        paths = {
            "case_open": base,
            "log_page": base + "/logs?limit=50",
            "fts_search": base + "/logs?q=capacity&limit=50",
            "timeline": base + "/timeline?limit=50",
        }
        observations: dict[str, list[float]] = {name: [] for name in paths}

        def read(index):
            name = list(paths)[index % len(paths)]
            begin = time.monotonic()
            response = client_for_actor().get(paths[name])
            ensure(response.status_code == 200, name)
            ensure(response.json is not None, "JSON response")
            return name, time.monotonic() - begin

        for index in range(4):
            read(index)
        with ThreadPoolExecutor(max_workers=options.concurrency) as pool:
            for name, elapsed in pool.map(read, range(options.requests)):
                observations[name].append(elapsed)
        report_begin = time.monotonic()
        report = client.post(base + "/reports", json={"version": client.get(base).json["version"], "profile": "full"})
        ensure(report.status_code == 202, "report request")
        with app.app_context():
            run_autopsy_worker_once("capacity-report")
        ready = client.get(base + f"/reports/{report.json['id']}").json
        ensure(ready["job"]["state"] == "completed", "isolated report job")
        pdf = client.get(base + f"/reports/{report.json['id']}/files/pdf")
        ensure(pdf.status_code == 200 and pdf.data.startswith(b"%PDF-"), "PDF artifact")
        report_seconds = time.monotonic() - report_begin
        connection.close()
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result = {
            "schema": "socify-v3-capacity/1",
            "revision": git_revision(),
            "environment": {
                "python": platform.python_version(),
                "kernel": platform.release(),
                "cpu_count": os.cpu_count(),
                "host_memory_bytes": memory_total_bytes(),
                "database_bytes": path.stat().st_size,
            },
            "scope": {
                "case_events": expected,
                "actual_parsed_events": 10000,
                "storage_seed_events": max(0, options.events - 10000),
                "concurrent_clients": options.concurrency,
                "requests": options.requests,
                "authentication": "synthetic test sessions; CSRF measured separately by real browser tests",
                "transport": "Flask test client including application validation, SQL and JSON serialization; excludes ingress/TLS latency",
                "fts_hit_count": "Exact below 10000; declared lower bound above 10000 with exact has_next for each returned page",
            },
            "import": {"seconds": imported_seconds, "rows_per_second": 10000 / imported_seconds},
            "storage_seed_seconds": seed_seconds,
            "reads": {name: distribution(values) for name, values in observations.items()},
            "report": {"seconds": report_seconds, "pdf_bytes": len(pdf.data), "formats": ready["formats"]},
            "resources": {
                "coordinator_peak_rss_kib": usage.ru_maxrss,
                "coordinator_user_cpu_seconds": usage.ru_utime - cpu.ru_utime,
                "coordinator_system_cpu_seconds": usage.ru_stime - cpu.ru_stime,
                "elapsed_seconds": time.monotonic() - started,
            },
            "limitations": [
                "Synthetic storage expansion does not measure million-row parsing or enrichment throughput",
                "Memory/CPU values cover coordinator only, not Docker analysis service",
                "Single bounded report timing is not a report latency distribution",
                "No company SLO agreed; measurements are evidence for sizing, not a production capacity promise",
            ],
        }
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
