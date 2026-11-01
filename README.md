# SOCify Tactical Workbench (V6)

منصة فرز وتحقيق أمني سريع مصممة كـ**«سكين سويسرية»** لمحللي ومديري مراكز العمليات الأمنية (SOC) والمحققين وتحديات التحليل السريع (CTF). تمنحك صورة أولية شاملة وسريعة (عمق 1، سطح 10) دون الحاجة لتثبيت ترسانة ثقيلة من أدوات التحليل المنفصلة، سواء أثناء المناوبات، أو لطلبات التقارير الطارئة خارج أوقات العمل، أو لفحص ملف سجلات ومرفقات مشبوهة بسرعة قبل التعمق بالأدوات المتخصصة عند الحاجة.

A fast-triage security workbench built as a **Swiss Army knife** for SOC analysts, managers, incident responders, off-hours triage, and rapid CTF investigations. SOCify delivers wide initial visibility across SIEM logs, built-in detection rules, one-click safe static file and email attachment inspection, suspicious IP and email watchlists, and dropdown-guided instant printable reports with direct manager escalation.

## الركائز الأساسية في V6

- **سجلات SIEM وقواعد كشف مدمجة فورية:** استيراد ملفات السجلات (CSV, JSON, JSONL, Syslog, Linux Auth, Web, Sysmon XML, EVTX, PCAP) أو ربطها مباشرة مع أنظمة الـ SIEM، مع قواعد كشف مدمجة تعمل تلقائياً فور دخول السجلات لإنتاج التنبيهات.
- **فحص أولي آمن بضغطة زر للملفات ومرفقات البريد:** فحص ساكن فوري لرسائل `.eml` ومرفقاتها وأي ملف مشبوه دون تشغيله مطلقاً (البصمات `SHA-256`، كشف خداع الامتدادات والنوع الحقيقي، السلاسل والروابط المدمجة، ومؤشرات الملفات التنفيذية والمستندات).
- **قائمة مراقبة مرنة (Watchlist) للإيميلات والـ IPs المشبوهة:** بناء وحفظ قوائم بالعناوين والإيميلات والمؤشرات المشبوهة للرجوع إليها ومطابقتها تلقائياً أو رجعياً مع السجلات والتنبيهات.
- **استلام ملكية القضايا فوراً بدون بيروقراطية مسبقة:** يفتح المحلل أو المحقق القضية أو يستلم ملكيتها (Ownership) مباشرة ويبدأ التحقيق دون انتظار موافقة مدير مسبقة، ويكون دور المدير في النهاية عند استلام التقرير المصعّد.
- **تقرير نهائي فوري بقوائم منسدلة وتصعيد مباشر للمدير:** إجابة سريعة على أسئلة التحقيق عبر قوائم منسدلة تختصر وقت الكتابة اليدوية، لتوليد تقرير نظيف قابل للطباعة الفورية وتصعيده مباشرة لمدير مركز العمليات.
- **واجهة ثنائية اللغة وخفيفة:** واجهة عربية (RTL) وإنجليزية (LTR) مع وضع داكن وفاتح، تحافظ على النصوص الأصلية للسجلات والمؤشرات والبصمات دون تحريف.

> الفحص الأولي الساكن يدعم قرار الفرز السريع ولا يُعد بديلاً عن التحليل الديناميكي العميق أو إثباتاً لخلو الملف من البرمجيات الخبيثة؛ ولا تُرسل العينات أو البصمات إلى خدمات خارجية عامة تلقائياً.

## خارطة طريق V6

تُوثّق خطة التعديلات الكاملة لفرع `V6` في [خطة تطوير V6](docs/v6-plan.md).

## التشغيل المحلي السريع

يتطلب التشغيل Python 3.12 أو أحدث:

```bash
python -m venv .venv
# على لينكس وماك:
. .venv/bin/activate
# على ويندوز (PowerShell):
.\.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
python run.py
```

لإعداد بيئة النشر المؤسسي (Gunicorn والعمّال المستقلين والنسخ الاحتياطي وعزل الخدمات الاختياري على لينكس/Docker) راجع [دليل التشغيل](docs/operations-v4.md) و[ضوابط الأمان](docs/security-guide.md).

## التحقق قبل النشر

```bash
python -m pip install -r requirements-dev.txt
python -m ruff format --check .
python -m ruff check .
python -m mypy --platform linux socify scripts app.py run.py
python -m scripts.generate_interface_tokens --check
python -m scripts.audit_brand --tokens-only
python -m bandit -c pyproject.toml -r socify scripts app.py run.py
python -m pip_audit -r requirements.txt
```

تشغّل GitHub Actions اختبارات التكامل والأمان والتغطية والمتصفح والحاويات على Linux، بما فيها خدمة التحليل المعزولة. تتطلب المجموعة الكاملة هذه البيئة؛ تشغيل Python على Windows وحده لا يوفّر عزل Landlock/seccomp أو إخراج التقارير الأصلي. تفاصيل الخدمة في [دليل التشغيل](docs/operations-v4.md).

لفحص الواجهة محليًا:

```bash
npm install --no-save --ignore-scripts --package-lock=false axe-core@4.14.0
python -m playwright install chromium
python -m pytest -m e2e tests/e2e/test_interface_theme.py tests/e2e/test_interface_languages.py
```

يمكن استخدام Edge المثبت على Windows بدل تنزيل Chromium بتعيين `$env:SOCIFY_BROWSER_CHANNEL = 'msedge'` في PowerShell قبل أمر pytest. تُحفظ لقطات الاختبار في `work/` و`artifacts/` المستبعدين من Git؛ تستخدم الاختبارات قواعد بيانات مؤقتة منفصلة.

## بنية المشروع

| المسار | المسؤولية |
| --- | --- |
| `socify/` | محركات استيعاب السجلات، القواعد المدمجة، الفحص الساكن للبريد والملفات، قوائم المراقبة، القضايا، والتقارير |
| `templates/` | صفحات الدخول ومساحة الفرز والتحقيق |
| `static/` | منطق الواجهة التفاعلية، القوائم المنسدلة، الطباعة، والترجمة الثنائية والخطوط المحلية |
| `scripts/` | أدوات التشغيل، إدارة الحسابات، العمّال، النسخ الاحتياطي، وفحص المواصفات |
| `deploy/` | إعداد الوسيط العكسي للنشر المؤسسي |
| `tests/` | اختبارات الوحدات، التكامل، الأمان، وواجهة المتصفح |
| `docs/` | خطة V6، المعمارية، نموذج البيانات، مواصفات OpenAPI، وأدلة الاستخدام |

## المراجع

- [خطة تطوير V6](docs/v6-plan.md)
- [المعمارية](docs/architecture.md) و[نموذج البيانات](docs/data-model.md)
- [مواصفات التكامل OpenAPI](docs/api/openapi.yaml)
- [دليل المحلل والفرز السريع](docs/analyst-guide.md) و[سيناريوهات الفرز السريع وCTF](docs/example-scenarios.md)
- [الأمان](docs/security-guide.md) و[نموذج التهديد](docs/threat-model.md)

## الترخيص والإفصاح الأمني

الكود مرخّص تحت رخصة MIT. تراخيص البيانات والخطوط موضحة في [إشعارات الأطراف الثالثة](THIRD_PARTY_NOTICES.md). للإفصاح المسؤول عن الثغرات راجع [SECURITY.md](SECURITY.md).
