import json

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st

from socify.event_identity import identity_key
from socify.events import normalize_event


def normalized(raw):
    return normalize_event(
        {
            "source": "registered-gateway",
            "source_type": "http",
            "raw_payload": raw,
            "event_time": "2026-11-02T08:00:00Z",
            "normalized_fields": {"event_time_known": True},
            "provenance": {"format": "structured"},
        }
    )


def context(**changes):
    return {"workspace_id": 1, "case_id": 2, "training_run_id": None, "source_id": 3, "autopsy_options": "{}", **changes}


@seed(20261104)
@settings(max_examples=100, deadline=None)
@given(
    st.dictionaries(
        st.text(alphabet="abcعربي_", min_size=1, max_size=8),
        st.one_of(st.none(), st.booleans(), st.integers(-10000, 10000), st.text(max_size=20), st.lists(st.integers(), max_size=5)),
        max_size=8,
    )
)
def test_json_order_and_whitespace_only_preserve_identity_but_unknown_facts_do_not(payload):
    raw = {"external_id": "explicit-1", "timestamp": "2026-11-02T08:00:00Z", "payload": payload}
    equivalent = json.loads(json.dumps(dict(reversed(list(raw.items()))), indent=4, sort_keys=True, ensure_ascii=False))
    baseline = identity_key(normalized(raw), context())
    assert baseline is not None and identity_key(normalized(equivalent), context()) == baseline
    changed = {**raw, "payload": {**payload, "preserved_unknown_fact": [False, 0, "0"]}}
    assert identity_key(normalized(changed), context()) != baseline


@pytest.mark.parametrize(
    "different", [{"workspace_id": 4}, {"case_id": 4}, {"training_run_id": 4}, {"source_id": 4}, {"autopsy_options": '{"mapping":{"unknown":"hostname"}}'}]
)
def test_context_and_effective_policy_cannot_share_identity(different):
    event = normalized({"external_id": "explicit-1"})
    assert identity_key(event, context()) != identity_key(event, context(**different))


@pytest.mark.parametrize("identifier", [True, False, None, "", [], {}])
def test_non_identity_values_never_collapse(identifier):
    assert identity_key(normalized({"external_id": identifier}), context()) is None


def test_scalar_types_array_order_unicode_and_unknown_time_remain_distinct():
    keys = {identity_key(normalized({"external_id": value}), context()) for value in (1, "1", "١", "01")}
    assert len(keys) == 4
    first, second = (normalized({"external_id": "1", "value": items}) for items in ([1, 2], [2, 1]))
    assert identity_key(first, context()) != identity_key(second, context())
    first["normalized_fields"] = '{"event_time_known":false}'
    assert identity_key(first, context()) is None
