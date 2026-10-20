# SOCify

> **فرع التطوير الموحد:** [feature/socify-browser-review-2026-10-20](https://github.com/7zy4/SOCifyProject/tree/feature/socify-browser-review-2026-10-20) — يشمل أعمال المرحلة الأولى والمنصة المؤسسية وتحسين تشغيل Codespaces، دون تعديل `main`. [تقرير تدقيق الفروع والمتطلبات](docs/qa/branch-consolidation-2026-10-20.md). النسخة **NO-GO** حتى إغلاق متطلبات القبول.
>
> [تجربة Codespaces من المتصفح](docs/codespaces.md) · [مصفوفة 132 مطلبًا](docs/qa/requirements-traceability.csv) · [60 رحلة قبول](docs/qa/e2e-acceptance.csv)

SOCify منصة عربية مفتوحة المصدر لتدريب محللي مراكز العمليات الأمنية داخل بيئة محاكاة معزولة. تربط المنصة الاستيراد والتطبيع بقواعد الكشف والتنبيهات والتحقيقات وMITRE ATT&CK والصيد والرسم الزمني وخطط الاستجابة والتقييم، مع حفظ مصدر الدليل وسجل التدقيق.

حالة القبول الحالية: **NO-GO**. النسخة فرع تطوير للاختبار المعزول، ولم يثبت اجتياز جميع متطلبات الإصدار النهائي. راجع [تقرير القبول](docs/qa/final-acceptance-report.md) و[نتائج المراجعة](docs/qa/final-audit-findings.md) قبل استخدامها أو دمجها.

## التشغيل السريع

يتطلب التشغيل Python 3.12 أو أحدث. لا توجد حسابات افتراضية في الإنتاج ولا تُنشأ بيانات تجريبية دون طلب صريح.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export SOCIFY_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SOCIFY_CREDENTIAL_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SOCIFY_DATABASE="$PWD/instance/socify.db"
mkdir -p instance
python create_db.py
gunicorn --config gunicorn.conf.py app:app
```

افتح `http://127.0.0.1:5000`. التسجيل متاح افتراضيًا في بيئة `development` وينشئ دور `analyst` فقط.

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

```bash
export SOCIFY_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SOCIFY_CREDENTIAL_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker compose up --build
```

الخدمة مربوطة بـ`127.0.0.1` افتراضيًا، تعمل كمستخدم غير root، وتستخدم Volume مستمرًا وقاعدة ملفات للقراءة فقط عدا `/data` و`/tmp`. النشر العام يحتاج Reverse Proxy موثوقًا وTLS ونسخًا احتياطية ومراقبة.

## Codespaces

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
