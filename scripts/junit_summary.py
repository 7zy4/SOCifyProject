"""Publish failed tests from a JUnit report as GitHub annotations and a job summary, readable without signing in.

GitHub keeps only the first 10 error annotations of a step, so the first annotation lists every failing test.
With --coverage, a total below the configured fail_under is reported too, since that fails the test step without a failing test.
"""

import argparse
import html
import os
import sys
import tomllib
from pathlib import Path

from defusedxml import ElementTree


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def coverage_check(report: Path, config: Path = Path("pyproject.toml")) -> tuple[float, float, bool]:
    """Return the total of a Cobertura report, the required total and whether it falls short, using coverage.py's own rule."""
    from coverage.results import should_fail_under

    settings = tomllib.loads(config.read_text(encoding="utf-8")).get("tool", {}).get("coverage", {}).get("report", {})
    fail_under, precision = float(settings.get("fail_under", 0)), int(settings.get("precision", 0))
    root = ElementTree.parse(report).getroot()
    # coverage.py counts executed statements and branches together over all statements and branches.
    covered = int(root.get("lines-covered", "0")) + int(root.get("branches-covered", "0"))
    valid = int(root.get("lines-valid", "0")) + int(root.get("branches-valid", "0"))
    total = 100.0 * covered / valid if valid else 100.0
    return total, fail_under, should_fail_under(total, fail_under, precision)


def failures(report: Path) -> tuple[list[dict[str, str]], list[str]]:
    root = ElementTree.parse(report).getroot()
    counts = [
        f"Tests: {suite.get('tests')}; failures: {suite.get('failures')}; errors: {suite.get('errors')}; skipped: {suite.get('skipped')}"
        for suite in root.iter("testsuite")
    ]
    found = []
    for case in root.iter("testcase"):
        for problem in (*case.findall("failure"), *case.findall("error")):
            found.append({"name": f"{case.get('classname')}.{case.get('name')}", "message": problem.get("message", "")})
    return found, counts


def publish(report: Path, title: str, summary_path: str | None, out=sys.stdout, coverage: Path | None = None) -> int:
    lines, annotations = [f"## {title}\n\n"], []
    found: list[dict[str, str]] = []
    if not report.is_file():
        lines.append("The test runner did not produce a JUnit report. Inspect the preceding step.\n\n")
        annotations.append(f"::error title={title}::No JUnit report at {report}")
    else:
        found, counts = failures(report)
        lines += [f"{line}\n\n" for line in counts]
        if found:
            listing = "\n".join(item["name"] for item in found)
            annotations.append(f"::error title={title} failures ({len(found)} tests)::{_escape(listing)}")
    if coverage is not None and coverage.is_file():
        total, required, short = coverage_check(coverage)
        lines.append(f"Coverage: {total:.2f}% (required: {required:g}%)\n\n")
        if short:
            annotations.append(f"::error title={title} coverage::Total coverage {total:.2f}% is below the required {required:g}%")
    for item in found:
        lines.append(f"<h3>{html.escape(item['name'])}</h3><pre>{html.escape(item['message'][:4000])}</pre>\n")
        annotations.append(f"::error title={title} failure::{_escape(item['name'] + ': ' + item['message'][:2000])}")
    if annotations:
        print(*annotations, sep="\n", file=out)
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.writelines(lines)
    return len(found)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("title")
    parser.add_argument("--coverage", type=Path, help="Cobertura XML report to compare with fail_under in pyproject.toml")
    arguments = parser.parse_args(argv)
    publish(arguments.report, arguments.title, os.environ.get("GITHUB_STEP_SUMMARY"), coverage=arguments.coverage)


if __name__ == "__main__":
    main()
