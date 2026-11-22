"""Generate a self-contained SOCify brand reference from the runtime token source."""

import html
from pathlib import Path

from socify.report_brand import design_tokens, report_style


def generate(output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    tokens = design_tokens()
    roles = (
        "bg",
        "panel",
        "panel-2",
        "text",
        "muted",
        "primary-fill",
        "severity-critical",
        "severity-high",
        "severity-medium",
        "status-resolved",
    )
    rows = "".join(
        f"<tr><th>{html.escape(role)}</th><td><code>{tokens['colors'][role][0]}</code></td><td><code>{tokens['colors'][role][1]}</code></td></tr>"
        for role in roles
    )
    content = f"""<section class="report-cover"><p>SOCify</p><h1>دليل الهوية البصرية</h1><p>فرز التنبيهات | التحقيق | التقارير</p></section>
<h2>الأسطح والألوان</h2><p>سطوح رمادية محايدة في الوضعين الداكن والفاتح، ولون ذهبي واحد للإجراء الأساسي والتحديد، وألوان صلبة للخطورة: حرجة، عالية، متوسطة، منخفضة.</p>
<table><thead><tr><th>الدور</th><th>فاتح</th><th>داكن</th></tr></thead><tbody>{rows}</tbody></table>
<h2>الخطوط</h2><p>خطان فقط للعربية والإنجليزية: Kufam للعناوين، وIBM Plex Sans Arabic لبقية النصوص والأرقام والتواريخ بأرقام غربية متراصفة.</p>
<h2>الإيقاع وإمكانية الوصول</h2><p>شبكة مسافات 4px، وأنصاف أقطار 4px و6px و8px، ودعم كامل لاتجاهي RTL وLTR، وتباين لا يقل عن 4.5:1 في جميع الأزواج اللونية.</p>
<h2>التقارير</h2><p>التقارير المطبوعة والمصدرة تستخدم الخطين والألوان نفسها على ورق أبيض بمقاس A4 دون أي موارد خارجية.</p>
<p>مصدر الحقيقة: static/design-tokens.json.</p>"""
    target = output / "SOCify-Visual-Identity.html"
    target.write_text(
        f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>SOCify | دليل الهوية البصرية</title><style>{report_style()}</style></head><body>{content}</body></html>',
        encoding="utf-8",
    )
    return target


if __name__ == "__main__":
    print(generate(Path("artifacts/brand")))
