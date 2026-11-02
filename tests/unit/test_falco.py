import pytest

from socify.detection import _condition_matches, validate_dsl
from socify.events import normalize_event
from socify.ingestion import _record_from_mapping
from socify.telemetry import profile


def falco(**changes):
    return {
        "rule": "Interactive shell in application container",
        "priority": "Critical",
        "time": "2026-11-02T10:20:30.123456789Z",
        "source": "syscall",
        "hostname": "collector-pod-7",
        "output": "Interactive shell observed in checkout container",
        "tags": ["container", "T1059", "T1059"],
        "output_fields": {
            "evt.hostname": "worker-04",
            "evt.type": "execve",
            "proc.name": "sh",
            "proc.pname": "containerd",
            "proc.pid": 321,
            "proc.ppid": 42,
            "proc.cmdline": "sh",
            "proc.exepath": "/bin/sh",
            "user.name": "root",
            "container.id": "a12bc45",
            "container.name": "checkout",
            "container.image.repository": "registry.example.test/checkout",
            "container.image.tag": "stable",
            "k8s.ns.name": "payments",
            "k8s.pod.name": "checkout-7",
            "k8s.node.name": "worker-04",
        },
        **changes,
    }


def test_native_event_preserves_original_and_extracts_runtime_context():
    original = falco()
    parsed = _record_from_mapping(original, 1, "runtime.json", "fingerprint")
    event = normalize_event(parsed)
    assert parsed["raw_payload"] == original
    assert parsed["mitre_ids"] == ["T1059"]
    assert event["source_type"] == "falco" and event["event_type"] == "runtime_alert"
    assert event["severity"] == "critical" and event["hostname"] == "worker-04"
    assert event["process_name"] == "sh" and event["parent_process"] == "containerd"
    assert event["event_time"].startswith("2026-11-02T10:20:30")
    fields = parsed["normalized_fields"]
    assert fields["sensor_hostname"] == "collector-pod-7" and fields["process_id"] == 321
    assert fields["container_name"] == "checkout" and fields["kubernetes_namespace"] == "payments"


@pytest.mark.parametrize(
    "priority,severity",
    [
        ("Emergency", "critical"),
        ("Alert", "critical"),
        ("Critical", "critical"),
        ("Error", "high"),
        ("Warning", "medium"),
        ("Notice", "low"),
        ("Informational", "low"),
        ("Debug", "low"),
    ],
)
def test_priority_mapping(priority, severity):
    assert profile(falco(priority=priority))["severity"] == severity


def test_collector_and_host_placeholder_do_not_invent_affected_assets():
    parsed = profile(falco(output_fields={"container.id": "host", "container.name": "host", "proc.pid": "<NA>", "proc.name": "<NA>"}))
    assert parsed["hostname"] == "" and parsed["process_name"] == ""
    assert "container_id" not in parsed["normalized_fields"] and "process_id" not in parsed["normalized_fields"]
    assert normalize_event(parsed)["hostname"] is None
    # Missing source and formatted output remain missing, including plugin events.
    raw = falco(output_fields={})
    raw.pop("source")
    raw.pop("output")
    assert profile(raw)["description"] == ""
    assert "runtime_source" not in profile(raw)["normalized_fields"]


def test_container_context_can_be_used_in_detection_rules():
    dsl = validate_dsl(
        {
            "condition": {
                "logic": "and",
                "conditions": [
                    {"field": "kubernetes_namespace", "operator": "equals", "value": "payments"},
                    {"field": "container_name", "operator": "equals", "value": "checkout"},
                ],
            }
        }
    )
    event = profile(falco())
    assert _condition_matches(dsl["condition"], event)[0]
    event["normalized_fields"]["kubernetes_namespace"] = "unrelated"
    assert not _condition_matches(dsl["condition"], event)[0]


@pytest.mark.parametrize(
    "changes",
    [
        {"output_fields": []},
        {"output_fields": {str(i): "x" for i in range(201)}},
        {"rule": ""},
        {"rule": "r" * 256},
        {"priority": "unknown"},
        {"priority": None},
        {"time": ""},
        {"time": "not-a-time"},
        {"hostname": {}},
        {"tags": "container"},
        {"tags": ["x"] * 51},
        {"tags": ["x" * 81]},
        {"tags": [42]},
        {"output": []},
        {"output_fields": {"proc.pid": True}},
        {"output_fields": {"proc.pid": -1}},
        {"output_fields": {"proc.pid": 1.5}},
        {"output_fields": {"proc.cmdline": "x" * 2049}},
        {"output_fields": {"container.name": {"name": "bad"}}},
    ],
)
def test_malformed_native_fields_fail_explicitly(changes):
    with pytest.raises(ValueError):
        profile(falco(**changes))
