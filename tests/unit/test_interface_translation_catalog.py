import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_all_authored_operational_labels_have_english_translations():
    script = (ROOT / "static" / "localization.js").read_text()
    catalog = json.JSONDecoder().raw_decode(script.split("const english = ", 1)[1])[0]
    missing = []
    for path in (ROOT / "static").glob("autopsy*.js"):
        for match in re.finditer(r'SOCifyLocale\.text\(("(?:\\.|[^"\\])*")\)', path.read_text()):
            original = json.loads(match.group(1))
            if original not in catalog:
                missing.append(f"{path.name}: {original}")
            else:
                assert not re.search(r"[\u0600-\u06ff]", catalog[original]), original
    assert not missing, "Missing English labels:\n" + "\n".join(missing)
