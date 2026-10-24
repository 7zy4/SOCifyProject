from pathlib import Path

from socify.report_brand import report_style


def generate(output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    pages = [
        (
            "rtl",
            "cover",
            """<p class="kicker">SOCify · دليل الهوية البصرية</p><h1>وضوح الدليل.<br>ثقة القرار.</h1><p>هوية موحّدة لتحليل السجلات، والتحقيق في الحوادث، والعمل كفريق.</p><div class="plate"><h2>من السجل إلى التقرير</h2><p>ألوان ثابتة. عناوين واضحة. بيانات مقروءة.<br>الموقع والتقارير يتحدثان بلغة واحدة.</p></div><p class="edition">الإصدار 2 · 2026</p>""",
        ),
        (
            "rtl",
            "",
            """<p class="kicker">01 · لوحة الألوان</p><h2>أزرق يقود القراءة</h2><p>اللون يوجّه الانتباه. النص يشرح الحالة دائمًا.</p><div class="swatches">
<div class="swatch blue"><strong>الأزرق الأساسي</strong><code>#1C4286</code></div><div class="swatch red"><strong>التنبيه المعتم</strong><code>#CB3B24</code></div>
<div class="swatch gold"><strong>الذهبي</strong><code>#F3A257</code></div><div class="swatch pale"><strong>الأزرق الباهت</strong><code>#E4ECF8</code></div>
<div class="swatch"><strong>العاجي</strong><code>#FBF7F0</code></div><div class="swatch white"><strong>الأبيض</strong><code>#FFFFFF</code></div></div><div class="note">النص #1D3461 · الخافت #4A5A7A<br>الفواصل #B9C8E4 · محيط الورق #C9D1DE<br>البرتقالي الأصلي #DD4027 للزخرفة، ونسخته المعتمة للشارات.</div>""",
        ),
        (
            "rtl",
            "",
            """<p class="kicker">02 · الخطوط والمقاسات</p><h2>مقروءة في كل سياق</h2><div class="type-samples"><div class="size64">SOCify</div><div class="size48">عنوان قسم</div><div class="size36">ابدأ التحقيق</div><div class="size30">سجلات القضية</div><div class="size20">عنوان فرعي · 20pt</div><div class="size17">نص أساسي واضح · 17pt</div><div class="size14">تسمية وجدول وملاحظة · 14pt</div></div><div class="note">العناوين: Baloo Bhaijaan 2 · 800<br>النص: IBM Plex Sans Arabic · 400 / 700<br>ارتفاع السطر: العنوان 1.2، والنص 1.6. لا تُصغّر البيانات لملء الصفحة.</div>""",
        ),
        (
            "rtl",
            "",
            """<p class="kicker">03 · مكونات الهوية</p><h2>أشكال متماسكة</h2><div class="steps"><span class="step red">1</span><h3>اجمع السجلات</h3></div><div class="steps"><span class="step gold">2</span><h3>تحقق من الدليل</h3></div><div class="steps"><span class="step blue">3</span><h3>وثّق القرار</h3></div><div class="plate bordered"><h3>لوحة المحتوى</h3><p>إطار أزرق 3pt. زوايا 18pt.<br>فراغ داخلي لا يقل عن 12pt.</p><span class="button-example">فتح التحقيق</span></div><div class="note">الملاحظات على أزرق باهت بزوايا 16pt. لا ظلال، ولا تدرجات، ولا حركات. يظهر المعنى بالنص مع اللون.</div>""",
        ),
        (
            "rtl",
            "",
            """<p class="kicker">04 · الموقع والتفاعل</p><h2>مساحة عمل واضحة</h2><div class="plate bordered"><h3>تحقيقات الفريق</h3><div class="stats"><div><strong>12</strong><span>سجلًا مرتبطًا</span></div><div><strong>3</strong><span>أدلة موثقة</span></div></div><p>عنوان واحد يشرح المهمة، ومحتوى مترابط، وإجراء واضح.</p><span class="button-example">عرض الخط الزمني</span></div><ul><li>تتكدس الأعمدة على الجوال.</li><li>تبقى الجداول مقروءة بتمرير محلي.</li><li>كل عنصر تحكم يدعم لوحة المفاتيح.</li><li>لا يُستخدم اللون وحده لشرح الخطورة.</li></ul><div class="note">الموقع متجاوب، ولا تُفرض عليه أبعاد ورقة A4. تبقى جميع المميزات والبيانات الحالية محفوظة.</div>""",
        ),
        (
            "ltr",
            "",
            """<p class="kicker">05 · Direction and language</p><h2>One identity.<br>Both directions.</h2><div class="plate bordered"><h3>Incident evidence</h3><p>Headings use Baloo Bhaijaan 2. Body text uses IBM Plex Sans Arabic.</p><span class="button-example">Open investigation</span></div><ul><li>Mirror layout with logical spacing.</li><li>Keep IDs, timestamps and hashes readable.</li><li>Use 14pt or larger for interface labels.</li><li>Use explicit status text beside color.</li></ul><div class="note">Arabic example: تحليل السجلات · ATT&amp;CK T1110<br>Do not force uppercase or stretch Arabic letters.</div>""",
        ),
        (
            "rtl",
            "",
            """<p class="kicker">06 · التقارير المطبوعة</p><h2>كل معلومة محفوظة</h2><table><tr><th>الورقة</th><td>595 × 842pt · A4</td></tr><tr><th>الهوامش</th><td>أعلى 42 · جانبان 44 · أسفل 40pt</td></tr><tr><th>منطقة المحتوى</th><td>507 × 760pt</td></tr></table><div class="plate bordered"><h3>دليل مرتبط بالقضية</h3><p class="size14"><strong>المصدر</strong><br>سجل مصادقة مستورد<br><strong>التقييم</strong><br>تقنية ATT&amp;CK موثّقة بسجل دليل.</p></div><div class="note">السجل العريض يصبح بطاقة حقول. يُقسّم المحتوى الطويل عبر الصفحات دون قص أو تصغير. تُضمّن الخطوط للعمل دون إنترنت. لا تُغيّر تقارير قديمة محفوظة ببصمة.</div>""",
        ),
        (
            "rtl",
            "cover",
            """<p class="kicker">SOCify · مرجع التطبيق</p><h1>هوية واحدة.<br>دليل واضح.</h1><div class="plate"><h2>قبل كل تسليم</h2><ul><li>راجع التباين والخطوط.</li><li>افحص العربية والإنجليزية.</li><li>تحقق من الهوامش وعدم التجاوز.</li><li>اختبر الجوال وسطح المكتب والطباعة.</li><li>حافظ على وظائف المنصة.</li></ul></div><p class="edition">الخطوط مضمّنة وفق SIL Open Font License 1.1.<br>ملفات التراخيص محفوظة في المستودع مع الخطوط.</p>""",
        ),
    ]
    style = (
        report_style()
        + """
@page { size:595pt 842pt; margin:0; @bottom-left {content:none;} @bottom-right {content:none;} }
body {max-width:none;padding:0;margin:0;}
.guide-page {position:relative;width:595pt;height:842pt;padding:42pt 44pt 40pt;background:#FBF7F0;margin:24pt auto;break-after:page;}
.guide-page:last-child {break-after:auto;}
.guide-page h1 {font-size:64pt;line-height:1.1;margin:30pt 0;}
.guide-page h2 {font-size:48pt;margin:0 0 17pt;}
.guide-page h3 {font-size:20pt;margin:0 0 12pt;}
.guide-page ul {padding-inline-start:24pt;line-height:1.6;}
.guide-page li {margin-block:10pt;}
.kicker,.edition {font-size:14pt;}
.cover {background:#1C4286;color:#FFFFFF;}
.cover h1 {color:#FFFFFF;}
.plate {background:#FFFFFF;color:#1D3461;border-radius:26pt;padding:17pt;margin-block:17pt;}
.plate h2 {font-size:30pt;}
.bordered {border:3pt solid #1C4286;border-radius:18pt;}
.note {background:#E4ECF8;color:#1D3461;border:3pt solid #1C4286;border-radius:16pt;padding:12pt;font-size:14pt;margin-block-start:17pt;}
.swatches {display:grid;grid-template-columns:1fr 1fr;gap:12pt;}
.swatch {min-height:92pt;padding:12pt;border:3pt solid #1C4286;border-radius:18pt;background:#FBF7F0;font-size:14pt;display:grid;align-content:center;}
.swatch code {display:block;direction:ltr;text-align:start;}
.blue {background:#1C4286;color:#FFFFFF;}.red {background:#CB3B24;color:#FFFFFF;}.gold {background:#F3A257;color:#1C4286;}.pale {background:#E4ECF8;}.white {background:#FFFFFF;}
.size64 {font:800 64pt/1.2 "Baloo Bhaijaan 2";}.size48 {font:800 48pt/1.2 "Baloo Bhaijaan 2";}.size36 {font:800 36pt/1.2 "Baloo Bhaijaan 2";}.size30 {font:800 30pt/1.2 "Baloo Bhaijaan 2";}.size20 {font-size:20pt;font-weight:700;}.size17 {font-size:17pt;}.size14 {font-size:14pt;}
.type-samples {display:grid;gap:10pt;}
.steps {display:flex;align-items:center;gap:12pt;margin-block:17pt;}.steps h3 {margin:0;font-size:30pt;}
.step {display:grid;place-items:center;width:44pt;height:44pt;border-radius:50%;font:800 20pt "Baloo Bhaijaan 2";}
.button-example {display:inline-block;border:3pt solid #1C4286;border-radius:18pt;background:#1C4286;color:#FFFFFF;font-size:14pt;font-weight:700;padding:10pt 16pt;}
.stats {display:grid;grid-template-columns:1fr 1fr;gap:12pt;margin-block:17pt;}.stats>div {border:3pt solid #1C4286;border-radius:18pt;padding:12pt;}.stats strong {display:block;font:800 48pt/1.2 "Baloo Bhaijaan 2";color:#1C4286;}.stats span {font-size:14pt;}
.page-number {position:absolute;bottom:20pt;inset-inline-start:44pt;font-size:11pt;color:#4A5A7A;}
@media print {.guide-page {margin:0;print-color-adjust:exact;-webkit-print-color-adjust:exact;}}
"""
    )
    content = "".join(
        f'<section class="guide-page {kind}" dir="{direction}"><main>{body}</main>'
        + (f'<span class="page-number">{index + 1}</span>' if 0 < index < len(pages) - 1 else "")
        + "</section>"
        for index, (direction, kind, body) in enumerate(pages)
    )
    target = output / "SOCify-Visual-Identity-v2.html"
    target.write_text(
        f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>SOCify · دليل الهوية البصرية</title><style>{style}</style></head><body>{content}</body></html>'
    )
    return target


if __name__ == "__main__":
    print(generate(Path("artifacts/brand")))
