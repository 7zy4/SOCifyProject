import pytest
import yaml

from socify.sigma_subset import compile_sigma, validate_fixtures


def source(selection, condition="selected"):
    return yaml.safe_dump(
        {"title": "Synthetic bounded Sigma", "logsource": {"category": "socify_normalized"}, "detection": {"selected": selection, "condition": condition}}
    )


@pytest.mark.parametrize(
    "field,value,positive,negative",
    [
        ("title", "*needle*", "Needle text", "Routine"),
        ("title", "needle*", "Needle text", "Other needle"),
        ("title", "*needle", "Ends in needle", "Needle text"),
        ("title", "*", "exists", None),
        ("title", None, None, "exists"),
        ("title|exists", False, None, "exists"),
        ("title|startswith", "needle", "Needle text", "Other needle"),
        ("title|endswith", "needle", "Ends in needle", "Needle text"),
        ("title|contains", ["one", "two"], "TWO tokens", "three"),
        ("title|contains|all", ["one", "two"], "ONE TWO", "one only"),
    ],
)
def test_sigma_supported_string_list_wildcard_and_existence_semantics(field, value, positive, negative):
    compiled = compile_sigma(source({field: value}))
    validate_fixtures(compiled, {"positive": [{} if positive is None else {"title": positive}], "negative": [{} if negative is None else {"title": negative}]})


def test_sigma_cidr_parenthesized_boolean_and_not_semantics():
    rule = source({"source_ip|cidr": "192.0.2.0/24"}, "not (selected)")
    validate_fixtures(compile_sigma(rule), {"positive": [{"source_ip": "198.51.100.8"}], "negative": [{"source_ip": "192.0.2.8"}]})
    rule = yaml.safe_dump(
        {
            "title": "Boolean fixture",
            "logsource": {"category": "socify_normalized"},
            "detection": {"selected": {"title": "one"}, "other": {"title": "two"}, "condition": "selected or other"},
        }
    )
    validate_fixtures(compile_sigma(rule), {"positive": [{"title": "two"}], "negative": [{"title": "three"}]})


@pytest.mark.parametrize(
    "selection",
    [
        {"EventID": 1},
        {"title|contains|startswith": "text"},
        {"title|contains|contains": "text"},
        {"title|contains": True},
        {"title|exists": "yes"},
        {"title|contains": "*text*"},
        {"title": "bad?wildcard"},
        {"title": []},
        {"title": {"nested": "object"}},
        {"title": float("inf")},
        {"title": ["value"] * 21},
        {},
        [],
    ],
)
def test_sigma_unmapped_or_ambiguous_selections_are_rejected(selection):
    with pytest.raises(ValueError):
        compile_sigma(source(selection))


@pytest.mark.parametrize(
    "fixture",
    [
        None,
        {},
        {"positive": [], "negative": [{}]},
        {"positive": [{}], "negative": []},
        {"positive": [{"password_hash": 1}], "negative": [{}]},
        {"positive": [{"title": "x" * 11000}], "negative": [{}]},
    ],
)
def test_sigma_fixture_requirements_are_enforced_before_publication(fixture):
    with pytest.raises(ValueError):
        validate_fixtures(compile_sigma(source({"title": "expected"})), fixture)


def test_sigma_parser_limits_and_numeric_fixture_type():
    for text in (
        "x" * 65537,
        source({"title": "expected"}, "not " * 10 + "selected"),
        "title: [",
        "---\ntitle: one\n---\ntitle: two",
        "title: test\nlogsource: {category: socify_normalized}\ndetection: {selected: {title: text}, condition: selected}\ntags: invalid",
    ):
        with pytest.raises(ValueError):
            compile_sigma(text)
    validate_fixtures(compile_sigma(source({"http_status": 403})), {"positive": [{"http_status": 403}], "negative": [{"http_status": 200}]})
