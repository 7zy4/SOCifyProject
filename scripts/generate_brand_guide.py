"""Generate a self-contained Tactical Workbench brand reference from the runtime token source."""

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
    content = f"""<section class="report-cover"><p>SOCify Tactical Workbench · SOC</p><h1>دليل الهوية البصرية التكتيكية</h1><p>فرز سريع · كشف مدمج · فحص ساكن آمن · تقرير فوري قابل للطباعة</p></section>
<h2>الأسطح والألوان</h2><p>تعتمد الواجهة تدرجًا حبريًا رماديًا محايدًا مريحًا للمناوبات الطويلة، مع لون تمييز تكتيكي واحد للإجراء الأساسي وألوان دلالية مخصصة حصريًا لدرجات خطورة التنبيهات والأحكام.</p>
<table><thead><tr><th>الدور</th><th>فاتح</th><th>داكن</th></tr></thead><tbody>{rows}</tbody></table>
<h2>الطباعة</h2><p>النصوص والعناوين: IBM Plex Sans Arabic / IBM Plex Sans بأوزان هادئة وتباين مقاس واضح. المعرفات والبصمات والعناوين الشبكية والأرقام المتراصفة: JetBrains Mono (tabular-nums).</p>
<h2>الإيقاع وإمكانية الوصول</h2><p>شبكة مسافات 4px صارمة، أنصاف أقطار متداخلة (6px / 8px / 12px / 16px)، دعم كامل لاتجاهي RTL وLTR والوضعين الداكن والفاتح بتباين يتجاوز 4.5:1 في جميع الأزواج اللونية.</p>
<h2>التقارير والطباعة</h2><p>التقارير الفورية وتقارير الأدلة تشارك نفس الخطوط المحلية والألوان الدلالية على ورق أبيض نظيف بمقاس A4 دون أي موارد خارجية.</p>
<p>مصدر الحقيقة: static/design-tokens.json.</p>"""
    target = output / "SOCify-Visual-Identity.html"
    target.write_text(
        f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>SOCify · دليل الهوية البصرية</title><style>{report_style()}</style></head><body>{content}</body></html>',
        encoding="utf-8",
    )
    return target


if __name__ == "__main__":
    print(generate(Path("artifacts/brand")))
