"""Generate the CSS palette from the same token document used for Figma."""

import argparse
import json
from pathlib import Path


def generate() -> str:
    root = Path(__file__).resolve().parents[1] / "static"
    tokens = json.loads((root / "design-tokens.json").read_text())
    css = "/* Generated from design-tokens.json. Keep Figma aliases and CSS in sync. */\n"
    for index, mode in enumerate(("light", "dark")):
        selector = ':root, :root[data-theme="light"]' if index == 0 else ':root[data-theme="dark"]'
        css += f"{selector} {{\n  color-scheme: {mode};\n"
        css += "".join(f"  --{key}: {values[index]};\n" for key, values in tokens["colors"].items())
        if index == 0:
            css += "".join(f"  --space-{value}: {value}px;\n" for value in tokens["spacing"])
            css += "".join(f"  --radius-{value}: {value}px;\n" for value in tokens["radius"])
        css += "}\n"
    css += "@media print {\n  :root[data-theme] {\n    color-scheme: light;\n"
    css += "".join(f"    --{key}: {values[0]};\n" for key, values in tokens["colors"].items())
    css += "  }\n}\n"
    return css


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the checked-in CSS differs from the token source")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[1] / "static" / "tokens.css"
    result = generate()
    if args.check:
        if target.read_text() != result:
            raise SystemExit("tokens.css differs from design-tokens.json; run python -m scripts.generate_interface_tokens")
    else:
        target.write_text(result)


if __name__ == "__main__":
    main()
