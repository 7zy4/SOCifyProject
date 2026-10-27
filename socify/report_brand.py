import base64
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def report_style() -> str:
    root = Path(__file__).resolve().parent.parent / "static"
    faces = []
    for family, filename, weight in (
        ("Almarai", "Almarai-Regular.woff2", "400"),
        ("Almarai", "Almarai-Bold.woff2", "700"),
        ("IBM Plex Sans", "IBMPlexSans.woff2", "100 700"),
    ):
        encoded = base64.b64encode((root / "fonts" / filename).read_bytes()).decode()
        arabic_range = "unicode-range:U+0600-06FF,U+0750-077F,U+08A0-08FF,U+FB50-FDFF,U+FE70-FEFF;" if family == "Almarai" else ""
        faces.append(f'@font-face{{font-family:"{family}";src:url(data:font/woff2;base64,{encoded}) format("woff2");font-weight:{weight};{arabic_range}}}')
    return "".join(faces) + (root / "report.css").read_text()
