"""Generate a self-contained V4 brand reference from the runtime token source."""

import html
from pathlib import Path

from socify.report_brand import design_tokens, report_style


def generate(output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    tokens = design_tokens()
    roles = ("ink-black", "bg", "panel", "panel-2", "cobalt-highlight", "caption-yellow", "pulp-paper", "severity-critical", "severity-high", "status-resolved")
    rows = "".join(
        f"<tr><th>{html.escape(role)}</th><td><code>{tokens['colors'][role][0]}</code></td><td><code>{tokens['colors'][role][1]}</code></td></tr>"
        for role in roles
    )
    content = f"""<section class="report-cover"><p>SOCify / ISSUE 04</p><h1>دليل الهوية البصرية</h1><p>تحقيق واضح. دليل مقروء. قرار موثّق.</p></section>
<h2>الأحبار والورق</h2><p>ألواح حبرية وحدود كوبالت وصناديق سرد كهرمانية. الزخرفة تبقى خارج نصوص الأدلة والجداول.</p>
<table><thead><tr><th>الدور</th><th>ورقي</th><th>داكن</th></tr></thead><tbody>{rows}</tbody></table>
<h2>الطباعة</h2><p>العناوين: Cairo / Bangers. السرد والأزرار: Tajawal / Comic Neue. النص: IBM Plex Sans Arabic / IBM Plex Sans. السجلات: JetBrains Mono.</p>
<h2>التفاعل وإمكانية الوصول</h2><p>العربية والإنجليزية، سطح المكتب والجوال، وضع داكن وورقي. اتجاه RTL يعكس الظلال. النص الدلالي منفصل عن لون الهوية ليحافظ على تباين AA. التركيز واضح والحركة المخفّضة محترمة.</p>
<h2>المكونات</h2><p>ألواح بفواصل 18px وحدود 3px وزوايا 2px. الأزرار الأساسية كهرمانية بنص حبري. الطوابع تعرض اسم الحالة ولا تعتمد على اللون وحده. الجداول تمرر داخل حاويتها. لا تطبيق لمرشحات التشويه على البيانات.</p>
<h2>التقارير</h2><p>الألوان والخطوط من المصدر نفسه؛ تقارير الطباعة تستخدم ورقًا فاتحًا وهوامش A4. لا يعاد توليد تقارير الأدلة التاريخية.</p>
<p>مصدر الحقيقة: static/design-tokens.json. كتالوج الواجهات: docs/design/noir-atlas/index.html.</p>"""
    target = output / "SOCify-Visual-Identity-v4.html"
    target.write_text(
        f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>SOCify V4 · دليل الهوية</title><style>{report_style()}</style></head><body>{content}</body></html>'
    )
    return target


if __name__ == "__main__":
    print(generate(Path("artifacts/brand")))
