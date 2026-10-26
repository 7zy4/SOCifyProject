import argparse
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import resource
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from scripts.benchmark_reference import distribution, git_revision
from socify.timeutils import parse_timestamp

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "socify-v3-performance"
SERVICES = ("socify", "import-worker", "autopsy-worker", "analysis", "ingress")


class DockerProject:
    def __init__(self, env_file):
        self.executable = shutil.which("docker")
        if not self.executable or not Path(self.executable).is_absolute():
            raise RuntimeError("An absolute trusted Docker executable is required")
        self.prefix = [
            "compose",
            "--project-directory",
            str(ROOT),
            "--file",
            str(ROOT / "docker-compose.yml"),
            "--file",
            str(ROOT / "tests/container/compose.performance.yml"),
            "--env-file",
            str(env_file),
            "--project-name",
            PROJECT,
        ]

    def run(self, arguments, content=None):
        if not arguments or arguments[0] not in {"compose", "inspect"}:
            raise ValueError("Unknown synthetic performance command")
        return subprocess.run([self.executable, *arguments], input=content, capture_output=True, check=True, shell=False).stdout  # noqa: S603

    def python(self, service, program, payload=None):
        return self.run(
            self.prefix + ["exec", "-T", "-e", "SOCIFY_CONTAINER_ACCEPTANCE=synthetic", service, "python", "-c", program],
            None if payload is None else json.dumps(payload).encode(),
        )

    def identities(self):
        result = {}
        for service in SERVICES:
            identifier = self.run(self.prefix + ["ps", "-q", service]).decode().strip()
            if not identifier:
                raise RuntimeError("All five isolated synthetic services must be running")
            item = json.loads(self.run(["inspect", identifier]))[0]
            if not item["Name"].startswith("/" + PROJECT + "-"):
                raise RuntimeError("Unexpected container project")
            if item["Config"]["Labels"].get("io.socify.synthetic-capacity") != "true":
                raise RuntimeError("Synthetic capacity marker is required before creating any accounts or fixtures")
            result[service] = {
                "container_id": identifier,
                "image": item["Image"],
                "memory_limit_bytes": item["HostConfig"]["Memory"],
                "cpu_limit": item["HostConfig"]["NanoCpus"] / 1e9,
                "restart_count": item["RestartCount"],
                "oom_killed": item["State"]["OOMKilled"],
            }
        return result

    def resources(self):
        result = {}
        for service in SERVICES:
            program = "import json;from pathlib import Path;p=Path('/sys/fs/cgroup');cpu=dict(line.split() for line in (p/'cpu.stat').read_text().splitlines());print(json.dumps({'cpu_usage_usec':int(cpu['usage_usec']),'memory_peak_bytes':int((p/'memory.peak').read_text()),'memory_limit_bytes':int((p/'memory.max').read_text()),'pids_peak':int((p/'pids.peak').read_text())}))"
            result[service] = json.loads(self.python(service, program))
        return result


def load_state(path):
    if not path.exists():
        return None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor) as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > 1024 * 1024
        ):
            raise RuntimeError("Synthetic state must be a private bounded regular file owned by the operator")
        return json.load(source)


def save_state(path, state):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix="capacity-state-", delete=False) as target:
        json.dump(state, target, allow_nan=False)
        name = target.name
    os.replace(name, path)


@contextmanager
def state_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise RuntimeError("Unsafe synthetic state lease")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


@contextmanager
def tls_proxy(upstream_port):
    with tempfile.TemporaryDirectory(prefix="socify-capacity-tls-") as directory:
        key = ed25519.Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, algorithm=None)
        )
        private_path, cert_path = Path(directory) / "local.key", Path(directory) / "local.crt"
        for path, content in (
            (private_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
            (cert_path, certificate.public_bytes(serialization.Encoding.PEM)),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(content)

        class Proxy(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def relay(self):
                size = int(self.headers.get("Content-Length", 0))
                if not 0 <= size <= 10 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(size) if size else None
                headers = {key: value for key, value in self.headers.items() if key.lower() not in {"host", "connection", "transfer-encoding"}}
                headers["Host"] = "localhost"
                connection = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=120)
                try:
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    content = response.read()
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in {"connection", "content-length", "transfer-encoding", "server", "date"}:
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                finally:
                    connection.close()

            do_GET = do_POST = relay

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(cert_path, private_path)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        context = ssl.create_default_context(cafile=str(cert_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, context
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class Session:
    def __init__(self, port, context):
        self.port, self.context, self.cookie = port, context, ""
        self.tls_versions = set()

    def call(self, path, body=None, raw=False):
        headers = {"Host": "localhost", "Content-Type": "application/json"}
        if body is not None:
            headers["X-CSRFToken"] = self.call("/api/auth/csrf")["csrf_token"]
        if self.cookie:
            headers["Cookie"] = self.cookie
        connection = http.client.HTTPSConnection("localhost", self.port, context=self.context, timeout=120)
        try:
            connection.connect()
            self.tls_versions.add(connection.sock.version())
            connection.request("GET" if body is None else "POST", path, body=None if body is None else json.dumps(body), headers=headers)
            response = connection.getresponse()
            content = response.read()
            if response.getheader("Set-Cookie"):
                parsed = SimpleCookie(response.getheader("Set-Cookie"))
                if "session" in parsed:
                    self.cookie = "session=" + parsed["session"].value
            if response.status >= 400:
                raise RuntimeError(f"Synthetic capacity HTTP failure {response.status} at {path}")
            return (content, dict(response.getheaders())) if raw else json.loads(content)
        finally:
            connection.close()


def bootstrap(docker, accounts):
    program = """import json,sys,os,bcrypt
from scripts.bootstrap_team import create_manager
from socify import create_app
from socify.db import get_db,transaction,inserted_id
from socify.timeutils import iso_now
if os.environ.get('SOCIFY_CONTAINER_ACCEPTANCE')!='synthetic':raise RuntimeError('Synthetic fixture only')
accounts=json.load(sys.stdin);app=create_app()
owner=create_manager(app,accounts[0]['email'],'Synthetic capacity owner','Synthetic capacity team',accounts[0]['login_value'])
with app.app_context(),transaction():
    workspace=get_db().execute('SELECT workspace_id FROM users WHERE id=?',(owner,)).fetchone()[0]
    identifiers=[owner]
    for index,item in enumerate(accounts[1:],1):
        encoded=bcrypt.hashpw(item['login_value'].encode(),bcrypt.gensalt(rounds=12)).decode()
        identifier=inserted_id(get_db().execute("INSERT INTO users(email,password_hash,name,role,workspace_id,is_active,created_at) VALUES (?,?,?,'l1_analyst',?,1,?)",(item['email'],encoded,'Capacity analyst '+str(index),workspace,iso_now())))
        get_db().execute("INSERT INTO workspace_memberships(workspace_id,user_id,role,created_at) VALUES (?,?,'l1_analyst',?)",(workspace,identifier,iso_now()))
        identifiers.append(identifier)
print(json.dumps({'user_ids':identifiers,'workspace_id':workspace}))
"""
    return json.loads(docker.python("socify", program, accounts))


def fixture_content(offset, count):
    return "\n".join(
        json.dumps(
            {
                "title": f"Production capacity event {index}",
                "source_ip": f"198.51.100.{index % 64 + 1}",
                "hostname": "capacity.example.test",
                "event_time": "2026-10-20T10:00:00Z",
                "severity": "medium",
            },
            separators=(",", ":"),
        )
        for index in range(offset, offset + count)
    )


def wait_job(session, path, field, pending, deadline_seconds=180):
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        result = session.call(path)
        if result[field] not in pending:
            return result
        time.sleep(0.4)
    raise TimeoutError("Synthetic capacity worker deadline exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15006)
    parser.add_argument("--events", type=int, default=1000000)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--report-samples", type=int, default=10)
    parser.add_argument("--measure-only", action="store_true")
    options = parser.parse_args()
    if (
        not 10000 <= options.events <= 1000000
        or options.events % 10000
        or not 100 <= options.requests <= 1000
        or options.requests % 20
        or not 5 <= options.report_samples <= 20
        or not 1 <= options.port <= 65535
    ):
        parser.error("Use 10000..1000000 events in 10000-row batches and 100..1000 requests in multiples of 20")
    state_path = options.state.resolve()
    if state_path.is_relative_to(ROOT) or state_path == options.output.resolve():
        parser.error("Private synthetic credential state must stay outside the repository and public output")
    docker = DockerProject(options.env_file.resolve())
    started = time.monotonic()
    initial_cpu = resource.getrusage(resource.RUSAGE_SELF)
    with state_lock(state_path), tls_proxy(options.port) as (port, context):
        images_before = docker.identities()
        state = load_state(state_path)
        if state is None:
            accounts = [{"email": "capacity-" + secrets.token_hex(8) + "@example.test", "login_value": secrets.token_urlsafe(28) + "Aa9!"} for _ in range(20)]
            identities = bootstrap(docker, accounts)
            state = {
                "schema": "socify-private-capacity-state/1",
                "project": PROJECT,
                "events": options.events,
                "accounts": accounts,
                **identities,
                "batches": {},
                "ingestion_revision": git_revision(),
                "ingestion_images": images_before,
                "cpu_before": docker.resources(),
            }
            save_state(state_path, state)
        if state["project"] != PROJECT or state["events"] != options.events:
            raise RuntimeError("Synthetic state does not match this isolated workload")
        state.setdefault("driver_runs", []).append(
            {
                "started_at": datetime.now(UTC).isoformat(),
                "revision": git_revision(),
                "prior_completed_batches": sum(bool(batch.get("completed")) for batch in state["batches"].values()),
                "measure_only": options.measure_only,
                "images": images_before,
            }
        )
        save_state(state_path, state)
        sessions = [Session(port, context) for _ in state["accounts"]]
        for session, account in zip(sessions, state["accounts"], strict=True):
            session.call("/api/auth/login", {"email": account["email"], "password": account["login_value"]})
        owner = sessions[0]
        if "case_id" not in state:
            case = owner.call(
                "/api/cases",
                {
                    "title": f"Production synthetic {options.events}-event capacity",
                    "reason": "forensic_review",
                    "objective": "Measure real ingestion TLS authenticated team reads and isolated report resources",
                },
            )
            state["case_id"] = case["id"]
            base = "/api/cases/" + str(case["id"])
            for user_id in state["user_ids"][1:]:
                owner.call(base + "/members", {"user_id": user_id, "responsibility": "l1"})
            owner.call(
                base + "/records/timeline",
                {
                    "title": "Production capacity investigator observation",
                    "event_time": "2026-10-20T09:59:00Z",
                    "category": "observed",
                    "source": "Synthetic capacity fixture, not a real attack",
                },
            )
            save_state(state_path, state)
        base = "/api/cases/" + str(state["case_id"])
        if not options.measure_only:
            state.setdefault("ingestion_started_epoch", time.time())
            for offset in range(0, options.events, 10000):
                batch = str(offset // 10000)
                prior = state["batches"].get(batch)
                if prior and prior.get("completed"):
                    continue
                content = fixture_content(offset, 10000)
                digest = hashlib.sha256(content.encode()).hexdigest()
                if prior is None:
                    job = owner.call(base + "/imports", {"filename": f"capacity-{batch}.jsonl", "content": content})
                    prior = {"id": job["id"], "sha256": digest}
                    state["batches"][batch] = prior
                    save_state(state_path, state)
                status = wait_job(owner, base + "/imports/" + str(prior["id"]), "status", {"queued", "processing", "interrupted"})
                if status["status"] != "completed" or status["accepted"] != 10000 or status["rejected"] or status["content_hash"] != digest:
                    raise RuntimeError("Real ingestion count, parser status or original digest failed")
                prior.update(
                    completed=True,
                    accepted=status["accepted"],
                    parser_version=status["parser_version"],
                    created_at=status["created_at"],
                    started_at=status["started_at"],
                    completed_at=status["completed_at"],
                )
                save_state(state_path, state)
                print(
                    json.dumps(
                        {
                            "phase": "real_ingestion",
                            "completed_events": offset + 10000,
                            "target": options.events,
                            "elapsed_seconds": round(time.time() - state["ingestion_started_epoch"], 3),
                        }
                    ),
                    flush=True,
                )
            state.setdefault("ingestion_completed_epoch", time.time())
            state.setdefault("ingestion_resources", docker.resources())
            save_state(state_path, state)
        if len(state["batches"]) != options.events // 10000 or not all(batch.get("completed") for batch in state["batches"].values()):
            raise RuntimeError("All real ingestion batches must finish before capacity measurement")
        if owner.call(base + "/logs?limit=1")["total"] != options.events:
            raise RuntimeError("Actual case population differs from the requested real workload")
        for batch in state["batches"].values():
            if not batch.get("completed_at"):
                status = owner.call(base + "/imports/" + str(batch["id"]))
                for key in ("created_at", "started_at", "completed_at"):
                    batch[key] = status[key]
        save_state(state_path, state)
        ingestion_times = [
            (parse_timestamp(batch["completed_at"]) - parse_timestamp(batch["started_at"])).total_seconds() for batch in state["batches"].values()
        ]
        queue_times = [(parse_timestamp(batch["started_at"]) - parse_timestamp(batch["created_at"])).total_seconds() for batch in state["batches"].values()]
        paths = {
            "case_open": base,
            "log_page": base + "/logs?limit=50",
            "fts_search": base + "/logs?q=capacity&limit=50",
            "timeline": base + "/timeline?limit=50",
            "chronology": base + "/chronology?limit=50",
        }
        measurement_cpu = docker.resources()
        cold = {}
        for name, path in paths.items():
            begin = time.monotonic()
            owner.call(path)
            cold[name] = round((time.monotonic() - begin) * 1000, 3)

        def read_as_user(index):
            values = []
            for iteration in range(options.requests // 20):
                name = list(paths)[(index + iteration) % len(paths)]
                begin = time.monotonic()
                sessions[index].call(paths[name])
                values.append((name, time.monotonic() - begin))
            return values

        observations = {name: [] for name in paths}
        with ThreadPoolExecutor(max_workers=20) as pool:
            for results in pool.map(read_as_user, range(20)):
                for name, elapsed in results:
                    observations[name].append(elapsed)
        sample = owner.call(base + "/logs?limit=1")["items"][0]
        owner.call(base + "/logs/" + str(sample["id"]) + "/exhibit", {})
        for batch_key in ("0", str(options.events // 10000 - 1)):
            batch = state["batches"][batch_key]
            original, headers = owner.call(base + "/imports/" + str(batch["id"]) + "/original", raw=True)
            if hashlib.sha256(original).hexdigest() != batch["sha256"] or headers["X-Evidence-SHA256"] != batch["sha256"]:
                raise RuntimeError("Stored original export digest failed")
        report_times, report_bytes = [], []
        for _ in range(options.report_samples):
            report_start = time.monotonic()
            report = owner.call(base + "/reports", {"version": owner.call(base)["version"]})
            ready = wait_job(owner, base + "/jobs/" + str(report["job_id"]), "state", {"queued", "processing"})
            if ready["state"] != "completed":
                raise RuntimeError("Isolated capacity report failed")
            metadata = owner.call(base + "/reports/" + str(report["id"]))
            if set(metadata["formats"]) != {"json", "html", "md", "docx", "pdf"}:
                raise RuntimeError("All five native report formats must be present")
            pdf, headers = owner.call(base + "/reports/" + str(report["id"]) + "/files/pdf", raw=True)
            if not pdf.startswith(b"%PDF-") or hashlib.sha256(pdf).hexdigest() != headers["X-Content-SHA256"]:
                raise RuntimeError("Capacity PDF digest failed")
            report_times.append(time.monotonic() - report_start)
            report_bytes.append(len(pdf))
        resources = docker.resources()
        for service, value in resources.items():
            value["measurement_cpu_used_usec"] = value["cpu_usage_usec"] - measurement_cpu[service]["cpu_usage_usec"]
        images = docker.identities()
        if any(value["memory_limit_bytes"] != images[service]["memory_limit_bytes"] for service, value in resources.items()):
            raise RuntimeError("Kernel resource counters do not match the isolated container limits")
        if any(value["oom_killed"] for value in images.values()):
            raise RuntimeError("A synthetic service was OOM killed")
        result = {
            "schema": "socify-production-capacity/1",
            "synthetic_only": True,
            "revision": git_revision(),
            "ingestion_revision": state["ingestion_revision"],
            "actual_parsed_events": options.events,
            "storage_seed_events": 0,
            "hash_checked_batches": len(state["batches"]),
            "parser_versions": sorted({batch["parser_version"] for batch in state["batches"].values()}),
            "authenticated_identities": len(sessions),
            "concurrent_clients": 20,
            "requests": options.requests,
            "tls_versions": sorted(set().union(*(session.tls_versions for session in sessions))),
            "transport": "Verified localhost TLS fixture -> actual Nginx ingress -> production Gunicorn -> SQLite; independent authenticated cookie sessions with real CSRF and RBAC",
            "ingestion": {
                "wall_seconds_including_pauses": round(state["ingestion_completed_epoch"] - state["ingestion_started_epoch"], 3),
                "rows_per_processing_second": options.events / sum(ingestion_times),
                "batches": len(ingestion_times),
                "rows_per_batch": 10000,
                "processing": distribution(ingestion_times),
                "queue_wait": distribution(queue_times),
                "processing_seconds_total": sum(ingestion_times),
                "images": state["ingestion_images"],
                "resources": state.get("ingestion_resources", {}),
                "driver_runs": state["driver_runs"],
                "limits": "Worker timestamps measure each real batch. Wall time includes operator interruptions and fixes; lifetime cgroup peaks include the earlier synthetic smoke workload. Historical driver invocations before this manifest format are recorded separately in the QA log.",
            },
            "first_reads_ms": cold,
            "reads": {name: distribution(values) for name, values in observations.items()},
            "report": {
                "samples": len(report_times),
                "latencies": distribution(report_times),
                "pdf_bytes_min": min(report_bytes),
                "pdf_bytes_max": max(report_bytes),
                "sha256_verified": True,
                "formats_per_report": 5,
            },
            "resources": resources,
            "tls_fixture_and_driver": {
                "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "user_cpu_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_utime - initial_cpu.ru_utime,
                "system_cpu_seconds": resource.getrusage(resource.RUSAGE_SELF).ru_stime - initial_cpu.ru_stime,
            },
            "environment": {"python": platform.python_version(), "kernel": platform.release(), "host_cpu_count": os.cpu_count()},
            "measured_images": images,
            "harness_elapsed_seconds": round(time.monotonic() - started, 3),
            "limitations": [
                "Synthetic structured JSONL with 64 repeated reserved IPs, one host and one timestamp; different formats/cardinality need separate sizing",
                "TLS termination is a locally trusted test fixture, not a company certificate/deployment",
                "Kernel memory.peak covers each service lifetime including startup/cache; measured CPU deltas cover reads/report and separate ingestion counters are retained",
                "No company production SLO has been agreed; this is a measured workload, not unlimited capacity or a zero-defect guarantee",
            ],
        }
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
