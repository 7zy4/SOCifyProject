"""Build static, embeddable report faces from the licensed bundled web fonts."""

import hashlib
import json
from pathlib import Path

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parents[1] / "static" / "fonts"


def main():
    destination = ROOT / "report"
    destination.mkdir(exist_ok=True)
    manifest = []
    for source, weights in [("Cairo", [400, 700]), ("IBMPlexSans", [400, 700]), ("Bangers-Regular", [400])]:
        for weight in weights:
            original = ROOT / f"{source}.woff2"
            font = TTFont(original, recalcTimestamp=False)
            if font["OS/2"].fsType:
                raise ValueError(f"Embedding permission must be reviewed for {source}")
            if "fvar" in font:
                axes = {axis.axisTag: weight if axis.axisTag == "wght" else axis.defaultValue for axis in font["fvar"].axes}
                font = instantiateVariableFont(font, axes, inplace=True, updateFontNames=True)
            font.flavor = None
            filename = f"{source.removesuffix('-Regular')}-{'Bold' if weight == 700 else 'Regular'}.ttf"
            font.save(destination / filename)
            manifest.append(
                {"file": filename, "source": original.name, "weight": weight, "sha256": hashlib.sha256((destination / filename).read_bytes()).hexdigest()}
            )
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
