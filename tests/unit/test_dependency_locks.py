"""The development lock must test exactly what the production image installs."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _pins(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    return {re.sub(r"[-_.]+", "-", package).lower(): version for package, version in re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", text, re.M)}


def test_development_lock_installs_every_runtime_package_at_the_runtime_version():
    runtime, development = _pins("requirements.txt"), _pins("requirements-dev.txt")
    assert runtime, "requirements.txt pins nothing"
    assert {package: (version, development.get(package)) for package, version in runtime.items() if development.get(package) != version} == {}


def test_sbom_tool_stays_out_of_the_tested_environment():
    # cyclonedx-bom requires lxml<6; installing it with the tests would hold them on an lxml the production image does not use.
    assert "cyclonedx-bom" not in _pins("requirements-dev.txt")
    assert "cyclonedx-bom" in _pins("requirements-audit.txt")
