import base64

import pytest

from socify.autopsy_static_analysis import validate_yara


def payload():
    return {
        "rules": 'rule Fixture { strings: $a = "Synthetic_YARA_fixture" condition: $a }',
        "fixtures": {"positive": [base64.b64encode(b"Synthetic_YARA_fixture").decode()], "negative": [base64.b64encode(b"Routine fixture bytes").decode()]},
    }


def test_yara_trusted_synthetic_fixtures_validate_both_classes_with_reproducible_provenance():
    first, second = validate_yara(payload()), validate_yara(payload())
    assert first == second
    assert first["valid"] and first["rules"] == ["Fixture"]
    assert first["fixtures_passed"] == {"positive": 1, "negative": 1}
    assert len(first["fixtures_sha256"]) == 64
    assert "no malware-free verdict" in first["limitations"]


@pytest.mark.parametrize(
    "rules",
    [
        'include "/etc/passwd"\nrule Invalid { condition: true }',
        "rule Invalid { broken syntax }",
        "\n".join(f"rule Many_{index} {{ condition: true }}" for index in range(101)),
    ],
)
def test_yara_includes_syntax_and_excessive_rule_counts_fail_closed(rules):
    assert validate_yara({**payload(), "rules": rules})["valid"] is False


@pytest.mark.parametrize(
    "fixtures",
    [
        {"positive": [], "negative": ["eA=="]},
        {"positive": ["eA=="] * 11, "negative": ["eA=="]},
        {"positive": ["eA=="], "negative": ["eA=="]},
        {"positive": ["%%%%"], "negative": ["eA=="]},
    ],
)
def test_yara_fixture_mismatch_and_invalid_or_unbounded_input_cannot_publish(fixtures):
    assert validate_yara({**payload(), "fixtures": fixtures})["valid"] is False


def test_yara_oversized_source_is_rejected_before_compilation():
    with pytest.raises(ValueError, match="limit"):
        validate_yara({**payload(), "rules": "x" * 65537})
