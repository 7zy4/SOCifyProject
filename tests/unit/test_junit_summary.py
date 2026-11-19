import io

from tools.junit_summary import coverage_check, publish


def _report(tmp_path, failing):
    cases = "".join(
        f'<testcase classname="tests.unit.test_example" name="test_{index:02d}"><failure message="value 50% off&#10;second line">trace</failure></testcase>'
        for index in range(failing)
    )
    cases += '<testcase classname="tests.unit.test_example" name="test_error"><error message="fixture crashed">trace</error></testcase>'
    cases += '<testcase classname="tests.unit.test_example" name="test_ok"/>'
    path = tmp_path / "junit.xml"
    path.write_text(
        f'<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="{failing + 2}" failures="{failing}" errors="1" skipped="0">{cases}</testsuite></testsuites>',
        encoding="utf-8",
    )
    return path


def test_first_annotation_lists_every_failure_and_escapes_messages(tmp_path):
    out, summary = io.StringIO(), tmp_path / "summary.md"
    assert publish(_report(tmp_path, 12), "Unit tests", str(summary), out) == 13
    lines = out.getvalue().splitlines()
    assert lines[0].startswith("::error title=Unit tests failures (13 tests)::tests.unit.test_example.test_00%0A")
    assert lines[0].split("::", 2)[2].split("%0A") == [f"tests.unit.test_example.test_{index:02d}" for index in range(12)] + [
        "tests.unit.test_example.test_error"
    ]
    assert lines[1] == "::error title=Unit tests failure::tests.unit.test_example.test_00: value 50%25 off%0Asecond line"
    assert len(lines) == 14
    text = summary.read_text(encoding="utf-8")
    assert "Tests: 14; failures: 12; errors: 1; skipped: 0" in text and "<h3>tests.unit.test_example.test_error</h3><pre>fixture crashed</pre>" in text


def _passing(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(
        '<?xml version="1.0"?><testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="a" name="b"/></testsuite></testsuites>'
    )
    return path


def test_passing_report_prints_nothing(tmp_path):
    out = io.StringIO()
    assert publish(_passing(tmp_path), "Unit tests", None, out) == 0
    assert out.getvalue() == ""


def test_missing_report_is_reported(tmp_path):
    out = io.StringIO()
    assert publish(tmp_path / "absent.xml", "Unit tests", None, out) == 0
    assert out.getvalue().startswith("::error title=Unit tests::No JUnit report at")


def _coverage(tmp_path, lines_covered, branches_covered):
    path = tmp_path / "coverage.xml"
    path.write_text(
        f'<?xml version="1.0"?><coverage lines-valid="1000" lines-covered="{lines_covered}" branches-valid="1000" branches-covered="{branches_covered}"/>'
    )
    return path


def test_coverage_below_the_configured_minimum_is_reported_when_every_test_passed(tmp_path):
    out, summary = io.StringIO(), tmp_path / "summary.md"
    assert publish(_passing(tmp_path), "Unit tests", str(summary), out, _coverage(tmp_path, 900, 790)) == 0
    assert out.getvalue() == "::error title=Unit tests coverage::Total coverage 84.50% is below the required 90%\n"
    assert "Coverage: 84.50% (required: 90%)" in summary.read_text(encoding="utf-8")
    # With failing tests too, the complete list stays first and the coverage shortfall second, inside the 10 kept annotations.
    out = io.StringIO()
    assert publish(_report(tmp_path, 12), "Unit tests", None, out, _coverage(tmp_path, 900, 790)) == 13
    lines = out.getvalue().splitlines()
    assert lines[0].startswith("::error title=Unit tests failures (13 tests)::")
    assert lines[1] == "::error title=Unit tests coverage::Total coverage 84.50% is below the required 90%"
    assert len(lines) == 15


def test_coverage_uses_the_rounding_of_the_test_step(tmp_path):
    # pyproject.toml sets no precision, so like --cov-fail-under the total is rounded to a whole percent before comparing.
    assert coverage_check(_coverage(tmp_path, 900, 892)) == (89.6, 90.0, False)
    assert coverage_check(_coverage(tmp_path, 900, 888)) == (89.4, 90.0, True)
    out = io.StringIO()
    assert publish(_passing(tmp_path), "Unit tests", None, out, _coverage(tmp_path, 950, 900)) == 0
    assert out.getvalue() == ""
    assert publish(_passing(tmp_path), "Unit tests", None, out, tmp_path / "absent-coverage.xml") == 0
    assert out.getvalue() == ""
