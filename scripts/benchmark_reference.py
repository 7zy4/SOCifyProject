import argparse
import json
import math
import os
import platform
import resource
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

from socify import create_app
from socify.db import connect_path
from socify.schema import ensure_schema
from socify.seeding import seed_demo_data


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    return ordered[min(math.ceil(len(ordered) * percent) - 1, len(ordered) - 1)]


def git_revision() -> str:
    git_path = Path(".git")
    if git_path.is_file():
        git_path = Path(git_path.read_text().strip().removeprefix("gitdir: "))
    head = (git_path / "HEAD").read_text().strip()
    if not head.startswith("ref: "):
        return head
    reference = head.removeprefix("ref: ")
    loose = git_path / reference
    if loose.exists():
        return loose.read_text().strip()
    packed = (git_path / "packed-refs").read_text().splitlines()
    return next(line.split()[0] for line in packed if line.endswith(f" {reference}"))


def memory_total_bytes() -> int | None:
    try:
        line = next(item for item in Path("/proc/meminfo").read_text().splitlines() if item.startswith("MemTotal:"))
        return int(line.split()[1]) * 1024
    except (OSError, StopIteration, ValueError):
        return None


def bulk_events(connection: sqlite3.Connection, count: int, actor: int) -> None:
    connection.execute(
        """WITH RECURSIVE sequence(value) AS (
        VALUES(1) UNION ALL SELECT value + 1 FROM sequence WHERE value < ?
        )
        INSERT INTO security_events
        (event_id, external_id, idempotency_key, workspace_id, source, source_type, severity, category, event_type,
        title, description, event_time, ingested_at, timestamp, source_ip, hostname, raw_data, normalized_fields,
        tags, mitre_ids, status, created_by, parser_version, raw_hash, provenance)
        SELECT printf('BENCH-%09d', value), printf('bulk-%09d', value), printf('bulk:%09d', value), 1,
        'benchmark-bulk', 'synthetic', CASE value % 4 WHEN 0 THEN 'critical' WHEN 1 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END,
        'benchmark', 'benchmark_event', 'Reference benchmark event', 'Deterministic synthetic performance fixture',
        '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
        printf('198.51.100.%d', value % 250 + 1), printf('bench-%06d', value % 1000), '{}', '{}', '[]', '[]',
        'open', ?, 'socify-benchmark-1', '', '{"synthetic":true}' FROM sequence""",
        (count, actor),
    )


def distribution(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.50) * 1000, 3),
        "p95_ms": round(percentile(values, 0.95) * 1000, 3),
        "p99_ms": round(percentile(values, 0.99) * 1000, 3),
    }


def run(output: Path, bulk_count: int, import_count: int, samples: int) -> dict[str, Any]:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="socify-benchmark-") as directory:
        database_path = Path(directory) / "benchmark.db"
        connection = connect_path(str(database_path), True)
        ensure_schema(connection)
        seed_demo_data(connection, "Benchmark-Only-Password-2026!")
        actor = int(connection.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()[0])
        bulk_started = time.perf_counter()
        bulk_events(connection, bulk_count, actor)
        bulk_seconds = time.perf_counter() - bulk_started
        connection.close()

        application = create_app(
            {
                "DATABASE": str(database_path),
                "TESTING": True,
                "LEGACY_TRAINING_TESTS": True,
                "WTF_CSRF_ENABLED": False,
                "SECRET_KEY": "benchmark-session-key",  # pragma: allowlist secret
                "CREDENTIAL_KEY": "benchmark-credential-key",  # pragma: allowlist secret
                "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
                "MAX_IMPORT_ROWS": import_count,
            }
        )
        client = application.test_client()
        with client.session_transaction() as session:
            session["user_id"] = actor
            session["workspace_id"] = 1
            session["user_role"] = "admin"

        import_payload = "\n".join(
            json.dumps(
                {
                    "external_id": f"import-{index:09d}",
                    "source": "benchmark-import",
                    "event_type": "benchmark_import",
                    "category": "benchmark",
                    "severity": "low",
                    "title": "Reference import event",
                    "event_time": "2026-01-01T00:00:00Z",
                },
                separators=(",", ":"),
            )
            for index in range(import_count)
        )
        import_started = time.perf_counter()
        imported = client.post("/api/imports", json={"filename": "benchmark.jsonl", "format": "jsonl", "content": import_payload})
        import_seconds = time.perf_counter() - import_started

        hunt_latencies: list[float] = []
        errors = 0 if imported.status_code == 201 else 1
        hunt_total = None
        for _ in range(samples):
            sample_started = time.perf_counter()
            response = client.post("/api/hunt/query", json={"query": 'source = "benchmark-bulk"', "page_size": 100})
            hunt_latencies.append(time.perf_counter() - sample_started)
            if response.status_code != 200:
                errors += 1
            else:
                hunt_total = response.get_json()["total"]

        detection_latencies: list[float] = []
        for index in range(samples):
            sample_started = time.perf_counter()
            response = client.post(
                "/api/events",
                json={
                    "external_id": f"detection-{index:09d}",
                    "source": "benchmark-detection",
                    "event_type": "benchmark_detection",
                    "category": "benchmark",
                    "severity": "low",
                    "title": "Detection latency benchmark",
                    "event_time": "2026-01-01T00:00:00Z",
                },
            )
            detection_latencies.append(time.perf_counter() - sample_started)
            if response.status_code != 201:
                errors += 1

        result: dict[str, Any] = {
            "schema_version": 1,
            "benchmark_scope": "archived V2 training workflow; does not establish V3 capacity",
            "commit": git_revision(),
            "command": f"python -m scripts.benchmark_reference --bulk-events {bulk_count} --import-events {import_count} --samples {samples}",
            "fixture_seed": 20261023,
            "platform": {
                "python": platform.python_version(),
                "operating_system": platform.platform(),
                "cpu_count": os.cpu_count(),
                "memory_bytes": memory_total_bytes(),
            },
            "workload": {"bulk_events": bulk_count, "import_events": import_count, "samples": samples},
            "bulk_load": {"seconds": round(bulk_seconds, 3), "events_per_second": round(bulk_count / bulk_seconds, 2)},
            "import": {
                "seconds": round(import_seconds, 3),
                "events_per_second": round(import_count / import_seconds, 2),
                "status_code": imported.status_code,
                "accepted": imported.get_json().get("accepted") if imported.is_json else None,
            },
            "hunt": {**distribution(hunt_latencies), "total": hunt_total},
            "detection": distribution(detection_latencies),
            "errors": errors,
            "error_rate": round(errors / (samples * 2 + 1), 6),
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/performance-reference.json"))
    parser.add_argument("--bulk-events", type=int, default=100000)
    parser.add_argument("--import-events", type=int, default=10000)
    parser.add_argument("--samples", type=int, default=20)
    arguments = parser.parse_args()
    if arguments.bulk_events < 1 or arguments.import_events < 1 or arguments.samples < 1:
        parser.error("workload counts must be positive")
    result = run(arguments.output, arguments.bulk_events, arguments.import_events, arguments.samples)
    print(json.dumps(result, indent=2, sort_keys=True))
    failed = result["errors"] != 0 or result["import"]["seconds"] > 60 or result["hunt"]["p95_ms"] > 1500 or result["detection"]["p95_ms"] > 150
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
