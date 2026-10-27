import base64
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def report_style() -> str:
    root = Path(__file__).resolve().parent.parent / "static"
    faces = []
    for family, filename, weight in (
        ("Baloo Bhaijaan 2", "BalooBhaijaan2.woff2", "800"),
        ("IBM Plex Sans Arabic", "IBMPlexSansArabic-Regular.woff2", "400"),
        ("IBM Plex Sans Arabic", "IBMPlexSansArabic-Bold.woff2", "700"),
    ):
        encoded = base64.b64encode((root / "fonts" / filename).read_bytes()).decode()
        faces.append(f'@font-face{{font-family:"{family}";src:url(data:font/woff2;base64,{encoded}) format("woff2");font-weight:{weight};}}')
    return "".join(faces) + (root / "report.css").read_text()


@lru_cache(maxsize=1)
def report_logo() -> str:
    content = (Path(__file__).resolve().parent.parent / "static" / "brand" / "socify-logo.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(content).decode()
