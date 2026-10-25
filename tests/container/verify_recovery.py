import argparse
import hashlib
import http.client
import json
import secrets
import shutil
import subprocess
import time
from http.cookies import SimpleCookie
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--project", default="socify-v3-verification")
    parser.add_argument("--port", type=int, default=15005)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    if options.project != "socify-v3-verification":
        raise SystemExit("This test is limited to the isolated synthetic verification project")
    compose = ["compose", "--env-file", options.env_file, "--project-name", options.project]
    docker = shutil.which("docker")
    if not docker or not Path(docker).is_absolute():
        raise SystemExit("A trusted absolute Docker executable is required")

    def run(arguments, content=None):
        if not arguments or arguments[0] not in {"compose", "inspect"}:
            raise ValueError("Unknown synthetic deployment test command")
        result = subprocess.run([docker, *arguments], input=content, capture_output=True, check=True, shell=False)  # noqa: S603
        return result.stdout

    email, password = "recovery-" + secrets.token_hex(6) + "@example.test", secrets.token_urlsafe(28) + "Aa9!"
    bootstrap = "import json,sys; from scripts.bootstrap_team import create_manager; from socify import create_app; p=json.load(sys.stdin); create_manager(create_app(),p['email'],'Synthetic recovery owner','Synthetic recovery team',p['password'])"
    run(compose + ["exec", "-T", "socify", "python", "-c", bootstrap], json.dumps({"email": email, "password": password}).encode())
    cookie = ""

    def call(path, body=None, raw=False):
        nonlocal cookie
        headers = {"Host": "localhost", "Content-Type": "application/json"}
        if body is not None:
            headers["X-CSRFToken"] = call("/api/auth/csrf")["csrf_token"]
        if cookie:
            headers["Cookie"] = cookie
        connection = http.client.HTTPConnection("127.0.0.1", options.port, timeout=55)
        try:
            connection.request("GET" if body is None else "POST", path, body=None if body is None else json.dumps(body), headers=headers)
            response = connection.getresponse()
            data = response.read()
            if response.getheader("Set-Cookie"):
                parsed = SimpleCookie(response.getheader("Set-Cookie"))
                if "session" in parsed:
                    cookie = "session=" + parsed["session"].value
            assert response.status < 400, (path, response.status)
            return (data, dict(response.getheaders())) if raw else json.loads(data)
        finally:
            connection.close()

    def wait(path, field, pending):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = call(path)
            if result[field] not in pending:
                return result
            time.sleep(0.2)
        raise TimeoutError("Synthetic recovery acceptance deadline exceeded")

    call("/api/auth/login", {"email": email, "password": password})
    identity = call("/api/auth/me")
    created = call(
        "/api/cases",
        {"title": "Synthetic restart recovery", "reason": "forensic_review", "objective": "Prove session jobs evidence and custody survive service restart"},
    )
    base = "/api/cases/" + str(created["id"])
    original = call(base + "/imports", {"filename": "before.json", "content": '[{"title":"Evidence retained before restart"}]'})
    assert wait(base + "/imports/" + str(original["id"]), "status", {"queued", "processing", "interrupted"})["status"] == "completed"
    original_hashes = {row["id"]: row["sha256"] for row in call(base)["evidence"]}
    run(compose + ["stop", "--timeout", "60", "import-worker", "autopsy-worker"])
    restarted = time.monotonic()
    try:
        pending_import = call(base + "/imports", {"filename": "pending.json", "content": '[{"title":"Queued work survives all services restart"}]'})
        pending_report = call(base + "/reports", {"version": call(base)["version"]})
        assert call(base + "/imports/" + str(pending_import["id"]))["status"] == "queued"
        assert call(base + "/jobs/" + str(pending_report["job_id"]))["state"] == "queued"
        run(compose + ["restart", "--timeout", "60"])
    finally:
        run(compose + ["start", "import-worker", "autopsy-worker"])
    deadline = time.monotonic() + 60
    while True:
        try:
            assert call("/api/auth/me") == identity
            break
        except (OSError, http.client.HTTPException, AssertionError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
    assert wait(base + "/imports/" + str(pending_import["id"]), "status", {"queued", "processing", "interrupted"})["status"] == "completed"
    assert wait(base + "/jobs/" + str(pending_report["job_id"]), "state", {"queued", "processing"})["state"] == "completed"
    assert call(base + "/logs")["total"] == 2
    after = {row["id"]: row["sha256"] for row in call(base)["evidence"]}
    assert all(after[key] == value for key, value in original_hashes.items())
    assert call(base + "/custody")["integrity_valid"]
    pdf, headers = call(base + "/reports/" + str(pending_report["id"]) + "/files/pdf", raw=True)
    assert pdf.startswith(b"%PDF-") and hashlib.sha256(pdf).hexdigest() == headers["X-Content-SHA256"]
    isolation = {}
    probe = 'import socket,json; s=socket.socket(); s.settimeout(1);\ntry: s.connect(("192.0.2.1",443)); result={"blocked":False}\nexcept OSError as e: result={"blocked":e.errno in (1,13,101,113),"errno":e.errno}\nprint(json.dumps(result))'
    for service in ("socify", "import-worker", "autopsy-worker", "analysis"):
        identifier = run(compose + ["ps", "-q", service]).decode().strip()
        inspected = json.loads(run(["inspect", identifier]))[0]
        host = inspected["HostConfig"]
        assert inspected["Config"]["User"] not in {"", "root", "0"}
        assert host["ReadonlyRootfs"] and "ALL" in host["CapDrop"]
        assert any("no-new-privileges" in value for value in host["SecurityOpt"])
        network = json.loads(run(compose + ["exec", "-T", service, "python", "-c", probe]))
        assert network["blocked"], service
        if service == "analysis":
            assert not any(row["Destination"] == "/data" for row in inspected["Mounts"])
            assert not any(value.startswith(("SOCIFY_SECRET_KEY=", "SOCIFY_CREDENTIAL_KEY=")) for value in inspected["Config"]["Env"])
        isolation[service] = {
            "image": inspected["Image"],
            "network_mode": host["NetworkMode"],
            "nonroot": True,
            "read_only_root": True,
            "capabilities_dropped": True,
            "egress": network,
        }
    result = {
        "schema": "socify-v3-production-recovery/1",
        "synthetic_only": True,
        "existing_authenticated_session_retained": True,
        "all_five_services_restarted": True,
        "queued_import_and_report_completed": True,
        "original_evidence_hashes_retained": True,
        "custody_chain_valid": True,
        "pdf_sha256_verified": True,
        "seconds": round(time.monotonic() - restarted, 3),
        "isolation": isolation,
        "limitations": [
            "Queued work and authenticated continuity tested; in-flight lease expiration has separate integration tests",
            "Ingress proxies fixed internal upstream and intentionally receives browser traffic; network probes here cover data-processing services",
            "Host administrators remain trusted",
        ],
    }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
