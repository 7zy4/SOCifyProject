# دليل التشغيل

## المسارات

- [تشغيل محلي](#تشغيل-محلي) للعمل على جهازك.
- [Docker Compose](#docker-compose) للخدمات المنفصلة.
- [Codespaces](codespaces.md) لبيئة خاصة عبر GitHub.
- [النسخ الاحتياطي](#النسخ-الاحتياطي) و[الاستعادة](#الاستعادة) لحماية البيانات.
- [دليل الأمان](security-guide.md) لإعداد المفاتيح وTLS والشبكة.

## تشغيل محلي

- المتطلبات الكاملة: Python 3.12 وDocker على Linux أو WSL.
- اتبع أوامر [البدء](../README.md#البدء) لتثبيت المتطلبات وإنشاء المدير وخدمة التحليل.
- `python run.py` يشغّل التطبيق وعمال الاستيراد والتقارير وإجراءات القضية.
- التحليل يحتاج خدمة Linux المعزولة؛ لا يكفي تشغيل واجهة Python على Windows وحدها.
- المفاتيح المحلية محفوظة في `instance/codespaces.env`.
- يستخدم المشغّل قاعدة `socify.db` الجذرية إذا كانت موجودة، وإلا `instance/socify.db`؛ يسبقها المسار الصريح `SOCIFY_DATABASE`.
- للتحقق من القاعدة والحساب دون تعديل:

```bash
python -m scripts.bootstrap_team --email owner@example.com --status
```

- لتعيين قاعدة محددة، اضبط المسار نفسه قبل إنشاء الحساب والتشغيل:

```bash
export SOCIFY_DATABASE=/absolute/path/socify.db
python run.py
```

- بيئة Python على Windows تُفعّل عبر `.\.venv\Scripts\Activate.ps1`؛ استخدم WSL أو Codespaces لمسار التحليل الكامل.

## Docker Compose

1. جهّز قيمتين مستقلتين وقويتين لـ`SOCIFY_SECRET_KEY` و`SOCIFY_CREDENTIAL_KEY` في مدير الأسرار، ثم مررهما إلى بيئة Compose.
2. تأكد من حفظ المفاتيح لاستعادة الأدلة؛ لا تعتمد على قيم مؤقتة تتغير مع إعادة التشغيل.
3. ابنِ الخدمات وشغّلها، ثم أنشئ حساب المدير داخل خدمة التطبيق:

```bash
docker compose up -d --build
docker compose exec socify python -m scripts.bootstrap_team --email owner@example.com --name "مالك المنصة" --team "فريق العمليات"
curl -fsS http://127.0.0.1:5000/health/ready
```

4. افتح <http://127.0.0.1:5000>. للنشر الخارجي، اضبط TLS والمضيف الفعلي كما هو موضح أدناه.

| الخدمة | وظيفتها | الوصول |
|---|---|---|
| ingress | مدخل NGINX | ينشر المنفذ على loopback فقط؛ بلا قاعدة أو مفاتيح |
| socify | الواجهة وAPI عبر Gunicorn | شبكة داخلية وقاعدة ومقبس التحليل |
| import-worker | معالجة الاستيرادات | بلا شبكة؛ قاعدة ومفاتيح فك أدلة الرفع |
| autopsy-worker | التحليل والتقارير | بلا شبكة؛ قاعدة ومقبس التحليل |
| playbook-worker | إجراءات القضية المعتمدة | بلا شبكة؛ قاعدة مشتركة |
| analysis | الفحص الساكن وإخراج المستندات | بلا شبكة أو قاعدة أو مفاتيح التطبيق |

- تخزن البيانات في حجم `socify-data`؛ يتبادل التطبيق والتحليل الطلبات عبر `analysis-ipc`.
- اضبط وكيل الشركة لإنهاء TLS، ومرّر `SOCIFY_HTTPS=1` و`SOCIFY_TRUSTED_HOSTS` الصحيحين إلى خدمة التطبيق.
- Compose المرفق يستخدم HTTP على loopback. لا تعرضه مباشرة كإعداد TLS مكتمل.
- التطبيق على شبكة داخلية لا تملك خروجًا افتراضيًا؛ سحب مصادر HTTPS يحتاج مسار خروج مصرحًا. دفع السجلات إلى موصل القضية لا يتطلب خروج التطبيق.
- لا تستخدم `docker compose down -v` للإيقاف المعتاد؛ الخيار يحذف أحجام البيانات.
- لإيقاف الخدمات مع الاحتفاظ بالبيانات: `docker compose down`.

## الإعدادات الأساسية

| المتغير | الغرض |
|---|---|
| `SOCIFY_ENV=production` | إعداد الإنتاج، مع مفاتيح صريحة وعمال منفصلة |
| `SOCIFY_DATABASE` | مسار قاعدة البيانات المشتركة بين التطبيق والعمال |
| `SOCIFY_SECRET_KEY` | توقيع الجلسات والحماية المرتبطة بها |
| `SOCIFY_CREDENTIAL_KEY` | تشفير بيانات الاعتماد والأدلة |
| `SOCIFY_HTTPS` و`SOCIFY_TRUSTED_HOSTS` | HTTPS والمضيفون المسموحون |
| `SOCIFY_ALLOW_REGISTRATION` | التسجيل الجديد، بما فيه الدعوات |
| `SOCIFY_ANALYSIS_SOCKET` | مسار مقبس خدمة التحليل |
| `SOCIFY_SOURCE_ALLOWLIST` | أسماء مصادر HTTPS المصرح بها |
| `SOCIFY_MAX_UPLOAD_BYTES` و`SOCIFY_MAX_IMPORT_ROWS` | حدود الرفع والصفوف؛ الافتراضي 10 MiB و100000 صف |
| `SOCIFY_MAX_PENDING_IMPORT_JOBS` | حد طابور الاستيراد |
| `SOCIFY_MAX_PENDING_PLAYBOOK_RUNS` | حد طابور إجراءات القضية |
| `SOCIFY_REQUIRE_CASE_APPROVAL` | اعتماد القضية عند تفعيل سياسة المؤسسة |
| `SOCIFY_REQUIRE_INVESTIGATION_SELECTION` | قصر مساحة العمل على اختيار تحقيق محدد |

## العمال المستقلون

- Compose يشغّل العمال؛ الأوامر التالية لمسؤول ينشر الخدمات منفردة.
- استخدم قاعدة البيانات ومفاتيح التشفير نفسها في التطبيق والعمال.
- أبق `SOCIFY_IMPORT_INLINE_EXECUTION=0` و`SOCIFY_PLAYBOOK_INLINE_EXECUTION=0` في الإنتاج.

```bash
python -m scripts.run_import_worker --lease-seconds 120
python -m scripts.run_autopsy_worker
python -m scripts.run_playbook_worker
```

- لكل عامل طرفية أو مشرف خدمة مستقل؛ الأوامر مستمرة.
- عامل الاستيراد يستأنف من نقطة محفوظة ذرية كل 100 سجل.
- إجراءات القضية تحفظ حالة كل خطوة مع أثرها، وتستعيد الحجوزات المنتهية؛ الفشل القابل للإعادة ينتظر مهلة متزايدة.
- طلب الإلغاء محفوظ ويُفحص قبل الأثر التالي.
- حالة `queued` تعني انتظار المعالجة، وليست نتيجة تحليل.

## صحة الخدمة

| المسار | ما يفحصه |
|---|---|
| `/health/live` | حياة عملية التطبيق |
| `/health/ready` | اتصال القاعدة ومخططها |
| `/api/health` | بعد المصادقة: الطوابير وإخفاقات القواعد وحالة التشغيل |

- راقب زمن الاستجابة و5xx وحجم القاعدة وWAL والأعمال الفاشلة والحجوزات المنتهية وتأخر outbox.
- نجاح readiness لا يثبت اكتمال كل خدمة؛ تحقق من العمال وخدمة التحليل أيضًا.
- استخدم `X-Correlation-ID` لربط الطلب بسجلاته دون نسخ محتوى الأدلة أو الأسرار.

```bash
docker compose ps
docker compose logs --tail 100 analysis autopsy-worker import-worker playbook-worker
```

## النسخ الاحتياطي

- حدّد القاعدة الفعلية أولًا. الأمثلة أدناه تفترض `instance/socify.db`.
- أوقف الكتابة أو ضع الخدمة في صيانة إذا احتجت نقطة استعادة متسقة مع بقية الملفات.
- أنشئ نسخة باسم جديد؛ أداة النسخ تستخدم SQLite Online Backup وتفحص سلامة القاعدة والمفاتيح الخارجية.

```bash
python -m scripts.backup backups/socify-backup.db --source instance/socify.db
python -m scripts.migrate --database instance/socify.db --dry-run
```

- احفظ نسخة محمية من مفاتيح التشغيل خارج القاعدة؛ النسخ لا ينقل المفاتيح تلقائيًا.
- شفّر النسخة وحدد صلاحياتها، وسجل تاريخها ومسار القاعدة ومرجع التطبيق المتوافق معها.
- في Compose، تنفذ الأداة داخل الخدمة حيث المسار `/data/socify.db`:

```bash
docker compose exec socify python -m scripts.backup /data/backups/socify-backup.db --source /data/socify.db
```

- انقل النسخة إلى تخزين احتياطي محمي مستقل؛ بقاؤها في حجم البيانات نفسه لا يحميها من فقد الحجم.

## الاستعادة

1. أوقف التطبيق وجميع العمال.
2. استعد إلى مسار جديد فارغ، مع المفاتيح الأصلية المتوافقة. احتفظ بالقاعدة القديمة.
3. افحص النسخة وطبّق الترحيل على المسار الجديد:

```bash
python -m scripts.restore backups/socify-backup.db instance/socify-restored.db --confirm RESTORE
python -m scripts.migrate --database instance/socify-restored.db
```

4. اضبط `SOCIFY_DATABASE` للمسار الجديد في التطبيق والعمال.
5. تحقق من readiness والحسابات وأعداد القضايا والأدلة، وافتح دليلًا مشفرًا وتقريرًا محفوظًا قبل إعادة التوجيه.
6. اختبر الاستعادة دوريًا في بيئة منفصلة.

## تحديث التطبيق والكتالوج

- خذ نسخة احتياطية، وحدد commit أو صورة التشغيل الحالية، واختبر الترحيل قبل تبديل الخدمة.
- للرجوع، استخدم التطبيق وقاعدة متوافقة؛ الترحيلات تراكمية وقد تحتاج استعادة النسخة السابقة.
- لتحديث ATT&CK، استورد ملف Enterprise STIX محليًا باسم كتالوج يطابق مصدره. مثال:

```bash
python -m scripts.load_attack_snapshot enterprise-attack.json --version 20.1 --database instance/socify.db
python -m scripts.load_attack_snapshot --activate-version 20.0 --database instance/socify.db
```

- هذه الأرقام تخص كتالوج MITRE. استخدم الرقم الصحيح للملف لديك، وافحص `GET /api/attack/catalogs`.
- تُحفظ بصمة الحزمة، ولا يُعاد استخدام اسم كتالوج محفوظ لمحتوى مختلف.
- حزم YARA وSigma واستخبارات التهديدات محلية؛ وثّق المصدر والترخيص ونتيجة الفحص قبل تفعيلها.

## عزل التحليل وحدود البيانات

- مقبس التحليل بصلاحية `0660`؛ طابق هوية المستخدم والمجموعة بين العميل والخدمة.
- حجم IPC لدى العميل للقراءة فقط؛ اتصال UNIX socket لا يحتاج تحويل الحجم إلى قابل للكتابة.
- يعيد العميل محاولة الاتصال فقط عند غياب المقبس أو رفضه؛ لا يعيد إرسال طلب وصل إلى الخدمة.
- عند تعذر العزل، أصلح الخدمة بدل نقل التحليل إلى عملية غير معزولة.
- البريد: حد 2 MiB، عمق MIME حتى 5، و100 جزء و200 رأس و25 مرفقًا.
- تصدير السجلات: حتى 100000 سجل للطلب. البيانات الوصفية المحجوبة لا تعادل تحقيقًا كاملًا؛ تنزيل الأصل يحتاج صلاحية مستقلة.
- PCAP/PCAPNG: بيانات وصفية دون التقاط حي أو فك TLS أو إعادة تجميع TCP؛ بعض DNS وSNI المجزأ أو المشفر قد لا يُستخرج.
- SQLite: استخدم تخزينًا محليًا متوافقًا مع WAL، وراقب التنافس بين العمال. لا تنسخ ملف قاعدة مفتوحة وحده كبديل عن أداة النسخ.

## شهادة بناء مؤسسية

- يدعم Dockerfile سر بناء اختياريًا `build_ca` لشهادة الثقة العامة فقط.
- لا تمرر مفتاحًا خاصًا أو بيانات proxy إلى الصورة، ولا تعطل TLS:

```bash
docker build --secret id=build_ca,src=/path/to/trusted-ca-bundle.pem --target runtime .
```

- [استكشاف الأعطال](troubleshooting.md) · [دليل الأمان](security-guide.md).
