import base64
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def design_tokens() -> dict:
    return json.loads((Path(__file__).resolve().parent.parent / "static" / "design-tokens.json").read_text())


def report_fonts() -> list[dict]:
    return design_tokens()["fonts"]


@lru_cache(maxsize=1)
def report_style() -> str:
    root = Path(__file__).resolve().parent.parent / "static"
    faces = []
    for font in report_fonts():
        family, filename, weight = font["family"], font["file"], font["weight"]
        encoded = base64.b64encode((root / "fonts" / filename).read_bytes()).decode()
        faces.append(f'@font-face{{font-family:"{family}";src:url(data:font/woff2;base64,{encoded}) format("woff2");font-weight:{weight};}}')
    tokens = design_tokens()
    palette = ":root{" + "".join(f"--{name}:{values[0]};" for name, values in tokens["colors"].items()) + "}"
    return "".join(faces) + palette + (root / "report.css").read_text()
