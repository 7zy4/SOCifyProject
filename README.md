# SOCify Digital Autopsy

> **النسخة الثالثة:** [socify-version-3](https://github.com/7zy4/SOCifyProject/tree/socify-version-3) — التوجه الجديد **SOCify Digital Autopsy** للتحليل والتحقيق والتوثيق داخل الشركة. منصة داخلية تربط القضية بالسجلات والمؤشرات والتحقيق والتصعيد والتحليل المحلي والتقارير. حالة القبول وأدلتها في [محضر V3](docs/qa/v3-final-acceptance-2026-10-26.md). [التشغيل والحساب الداخلي](docs/operations-v3.md) · [البرومت التنفيذي](docs/plans/v3-digital-autopsy-implementation-prompt-ar.md) · [سجل الاستكمال](docs/plans/v3-progress.md) · [مصفوفة V3](docs/qa/v3-acceptance.csv). لا تُستخدم بيانات شركة حقيقية في Codespaces أو بيئة سحابية غير معتمدة داخل الشركة.
>
> **مرجع النسخة الثانية:** [socify-version-2](https://github.com/7zy4/SOCifyProject/tree/socify-version-2) — يشمل أعمال المرحلة الأولى والمنصة المؤسسية وتحسين تشغيل Codespaces، دون تعديل `main`. [تقرير تدقيق الفروع والمتطلبات](docs/qa/branch-consolidation-2026-10-20.md). هذه روابط مرحلة V2 التاريخية؛ يُقيّم V3 بمصفوفته ومحضر قبوله المستقلين.
>
> [تجربة Codespaces من المتصفح](docs/codespaces.md) · [مصفوفة 132 مطلبًا](docs/qa/requirements-traceability.csv) · [60 رحلة قبول](docs/qa/e2e-acceptance.csv)

V3 مساحة تحقيق داخلية تبدأ بقضية وهدف، ثم تحفظ السجلات والأدلة وتربط الأصول والمؤشرات والخط الزمني والتصعيد والتحليل المحلي والتقرير المعتمد. لا ترسل العينات أو البصمات إلى VirusTotal؛ تستورد نتائجه يدويًا. وظائف التدريب القديمة محفوظة في التاريخ ومرجع V2، ومساراتها متقاعدة في الوضع التشغيلي.

آخر تحقق على المصدر `93a86ba`: **746 اختبارًا ناجحًا، تغطية 90.71%، و19 رحلة Chromium**، مع قبول إنتاج وتعافٍ ناجحين وتطابق 108 ملفات عبر خدمات المعالجة الأربع. مصفوفة V3: **75/75 VERIFIED ضمن الحدود الموثقة**. اكتمل مرجع مليون سجل مستورد و20 مستخدمًا عبر TLS و10 تقارير فعلية؛ تفاصيل الأزمنة وحدود القياس في [محضر القبول](docs/qa/v3-final-acceptance-2026-10-26.md). [الأدلة الخام والملخص](docs/qa/v3-verification-summary-2026-10-26.json) · [مصفوفة الرحلات](docs/qa/v3-acceptance.csv).

حالة V3 تُحدّث في [محضر القبول الحالي](docs/qa/v3-final-acceptance-2026-10-26.md). تقارير NO-GO القديمة تخص checkpoints ومرحلة V2؛ لا تستبدل نتائج التحقق من المصدر الحالي. التسليم يستمر من `socify-version-3` دون دمج `main` أو تغيير V2.

## التشغيل السريع

يتطلب التشغيل Python 3.12 أو أحدث وDocker لخدمة التحليل المحلية المعزولة في المسار المختبر. لا توجد حسابات افتراضية في الإنتاج ولا تُنشأ بيانات تجريبية دون طلب صريح.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
docker build --target analysis -t socify-v3-verification-analysis .
bash scripts/start_local_analysis.sh
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-v3-dev-analysis-ipc/analysis.sock
python -m scripts.bootstrap_team --email manager@example.test --name "مدير الفريق" --team "فريق التحقيق الداخلي"
python run.py
```

افتح `http://127.0.0.1:5000`. يطلب bootstrap كلمة مرور ولا يغير حسابًا موجودًا. تُحفظ مفاتيح التطوير بين التشغيلات، ويشغّل `python run.py` عاملي الاستيراد والتحليل/التقارير تلقائيًا. التسجيل العام مغلق؛ يدعو المدير أعضاء الفريق بأدوارهم. إن كان لديك حساب وقاعدة سابقة فلا تنشئ مديرًا جديدًا لمجرد إعادة التشغيل.

للنشر داخل الشركة وتعريف المفاتيح الدائمة والعزل راجع [تشغيل V3](docs/operations-v3.md). مدخل Docker الافتراضي localhost:5000، ويمكن تغييره بـ`SOCIFY_HTTP_PORT` دون تغيير منافذ الخدمات الداخلية. بقية توثيق وظائف التدريب أدناه مرجع توافق V2، ولا يعني إتاحتها في V3.

## بيانات تطوير صريحة

يمكن إنشاء مستخدمين وسيناريو وقواعد وPlaybook اصطناعية في بيئة التطوير فقط:

```bash
export SOCIFY_ENV=development
export SOCIFY_SEED_DEMO=1
export SOCIFY_DEMO_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
python create_db.py
printf 'Temporary demo password: %s\n' "$SOCIFY_DEMO_PASSWORD"
```

الحسابات المنشأة موثقة في `socify/seeding.py`، وجميع المؤشرات تستخدم نطاقات التوثيق المحجوزة أو نطاق `.test`. لا ترسل السيناريوهات رسائل ولا تتصل بخدمات عامة.

## الاختبارات والبوابات

```bash
python -m pip install -r requirements-dev.txt
ruff check .
mypy socify scripts
pytest --cov=socify --cov-report=term-missing --cov-report=xml
bandit -r socify scripts -q
pip-audit -r requirements.txt
```

توجد اختبارات الوحدات والتكامل والأمن والقبول في `tests/`. يثبت CI المتصفح ثم يشغل Playwright على واجهة RTL. لا تُعامل أي بوابة أمن Critical/High كاختبار اختياري.

## Docker

يُجهّز المسؤول ملف البيئة الخاص خارج المستودع مرة واحدة بمفتاحين مستقلين وعشوائيين لا يقل كل منهما عن 32 بايت: `SOCIFY_SECRET_KEY` و`SOCIFY_CREDENTIAL_KEY`، وصلاحية 0600. استخدم نفس الملف والمفاتيح عند إعادة تشغيل Volume موجود؛ لا تولدهما من جديد في كل جلسة.

```bash
docker compose --env-file /secure/socify/production.env up --build
```

خدمة الويب مربوطة بـ`127.0.0.1` افتراضيًا، ويشغّل Compose عاملي Import وPlaybook منفصلين يستهلكان قوائم المهام المحفوظة. تعمل الخدمات كمستخدم غير root وتستخدم Volume مستمرًا وقاعدة ملفات للقراءة فقط عدا `/data` و`/tmp`. النشر العام يحتاج Reverse Proxy موثوقًا وTLS ونسخًا احتياطية ومراقبة.

## Codespaces

للتجربة اليدوية بعد إيقاف الخادم السابق: `python run.py`. أكد المستخدم نجاح تسجيل الدخول بهذا المسار. هذا خادم تطوير بعملية واحدة، ويستخدم مفاتيح البيئة الموجودة دون تحميل ملف مفاتيح Codespaces تلقائيًا.

بعد إيقاف الخادم السابق، شغّل `SOCIFY_HOST=0.0.0.0 python -m scripts.start_codespace` من الفرع `socify-version-2`. يحمّل الأمر المفاتيح المحفوظة تلقائيًا قبل بدء Gunicorn. افتح المنفذ 5000 بوضع Private في نافذة متصفح مستقلة.

افتح المستودع في Codespaces؛ يثبت Dev Container الاعتمادات، يرحّل القاعدة، ويشغل Gunicorn على المنفذ 5000 بظهور `Private`. التفاصيل في [دليل Codespaces](docs/codespaces.md).

## البيانات والتكاملات

- CSV وJSON Array وJSONL/NDJSON وSyslog RFC3164/5424 وسجلات Linux auth وApache/Nginx وSysmon XML وEVTX.
- raw evidence وSHA-256 وprovenance وidempotency ومهام استيراد مع المقبول والمرفوض والمتكرر.
- موصل HTTP في وضع Default Deny؛ لا يُجري اتصالًا ما لم يكن المضيف في قائمة السماح والعامل المعزول مهيأ. نتيجة الاختبار `unsupported` أو `not_configured` صادقة.
- ATT&CK snapshot مرجعي يعمل دون اتصال، مع أداة تحميل STIX 2.1 كاملة في `scripts/load_attack_snapshot.py`.

## التوثيق

- [الهندسة وقرارات التصميم](docs/architecture.md)
- [نموذج البيانات](docs/data-model.md)
- [عقد OpenAPI](docs/api/openapi.yaml)
- [دليل الأمان](docs/security-guide.md)
- [Threat Model](docs/threat-model.md)
- [دليل المحلل](docs/analyst-guide.md)
- [دليل المدرّب](docs/instructor-guide.md)
- [التشغيل والنسخ الاحتياطي](docs/operations.md)
- [خطة الاختبار](docs/qa/test-plan.md)
- [مصفوفة التتبّع](docs/qa/requirements-traceability.csv)

## الإفصاح الأمني

راجع [SECURITY.md](SECURITY.md). لا تضع ثغرات أو بيانات اعتماد في Issues عامة.

## الترخيص

الكود تحت رخصة MIT. بيانات ATT&CK تخضع لشروط MITRE المبينة في [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
