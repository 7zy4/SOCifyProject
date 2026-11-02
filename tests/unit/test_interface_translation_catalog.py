import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_printable_evidence_labels_have_english_translations():
    from socify.autopsy_report_render import ENUM_LABELS, LABELS

    script = (ROOT / "static" / "localization.js").read_text(encoding="utf-8")
    catalog = json.JSONDecoder().raw_decode(script.split("const english = ", 1)[1])[0]
    labels = set(LABELS.values()) | set(ENUM_LABELS.values())
    missing = [label for label in labels if not label.isascii() and label not in catalog]
    assert not missing, missing


def test_all_authored_operational_labels_have_english_translations():
    script = (ROOT / "static" / "localization.js").read_text(encoding="utf-8")
    catalog = json.JSONDecoder().raw_decode(script.split("const english = ", 1)[1])[0]
    missing = []
    for path in [*(ROOT / "static").glob("autopsy*.js"), ROOT / "static" / "soc-workbench.js", ROOT / "static" / "investigation-workspace.js"]:
        for match in re.finditer(r'(?:SOCifyLocale\.text|\bt)\(("(?:\\.|[^"\\])*")\)', path.read_text(encoding="utf-8")):
            original = json.loads(match.group(1))
            if original not in catalog:
                missing.append(f"{path.name}: {original}")
            else:
                assert not re.search(r"[\u0600-\u06ff]", catalog[original]), original
    assert not missing, "Missing English labels:\n" + "\n".join(missing)


def test_configurable_team_permissions_have_human_labels(app):
    from socify.security import effective_permissions
    from socify.teams import allowed_roles

    script = (ROOT / "static" / "autopsy_team.js").read_text(encoding="utf-8")
    labels = json.JSONDecoder().raw_decode(script.split("const teamPermissionLabels = ", 1)[1])[0]
    catalog = json.JSONDecoder().raw_decode((ROOT / "static" / "localization.js").read_text(encoding="utf-8").split("const english = ", 1)[1])[0]
    app.config["LEGACY_TRAINING_TESTS"] = False
    with app.app_context():
        available = set().union(*(effective_permissions({"role": role}) for role in allowed_roles() - {"soc_manager", "admin"}))
    assert available <= labels.keys(), available - labels.keys()
    missing = [label for label in labels.values() if label not in catalog]
    assert not missing, missing
