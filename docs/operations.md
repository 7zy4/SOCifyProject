# تشغيل SOCify

## التشغيل المحلي

ثبّت Python 3.12 أو أحدث وDocker، ثم جهّز البيئة والحساب وفق [البدء](../README.md#البدء). شغّل خدمة التحليل قبل التطبيق:

```bash
docker build --target analysis -t socify-analysis .
bash scripts/start_analysis.sh
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-local-analysis-ipc/analysis.sock
python run.py
```

تحتاج أوامر خدمة التحليل إلى بيئة Linux تدعم Docker. على Windows يمكن تشغيلها داخل WSL أو استخدام بيئة [Codespaces](codespaces.md).

خدمة التحليل مستقلة بلا شبكة أو قاعدة بيانات أو مفاتيح التطبيق. تفحص الملفات دون تنفيذها. يشغّل `python run.py` عمال الاستيراد والتحليل وإجراءات القضية، ويحتفظ بقاعدة البيانات والمفاتيح داخل `instance`.

## حسابات الفريق

أنشئ المدير باستخدام `scripts.bootstrap_team`، ثم أضف الأعضاء ووزّع الأدوار والصلاحيات من صفحة الفريق. لإنشاء قضية لا يلزم انتظار اعتماد المدير في الإعداد المعتاد. يمكن للمؤسسة تفعيل سياسة اعتماد القضايا عند الحاجة. يقتصر الوصول إلى القضايا والأدلة والتقارير على مساحة العمل والصلاحيات المعتمدة.

ابدأ بقضية وارفع سجلاتها؛ تعمل قواعد الكشف على البيانات المستوردة. افتح التنبيه لمراجعة تفاصيله، ثم سجّل نتائج التحقيق وإجاباته وإجراءاته قبل إصدار التقرير.

## عامل الاستيراد

PCAP وPCAPNG يعالجان عبر عامل منفصل حتى في التطوير؛ في الإنتاج توضع جميع الاستيرادات في الطابور. شغّل العامل في طرفية خدمة ثانية بعد تحميل **نفس قاعدة البيانات ونفس مفاتيح الجلسة/التشفير** المستخدمة بالخادم:

```bash
python -m scripts.run_import_worker --lease-seconds 120
```

خدمة `import-worker` موجودة في Compose وتشارك Volume القاعدة ومفاتيحها. لا يعني وصول الملف إلى حالة `queued` أنه حُلّل؛ تظهر الحالة والعدادات والأخطاء داخل القضية. التحليل الشبكي الحالي metadata لحزمة واحدة دون التقاط حي أو فك TLS أو إعادة تجميع TCP؛ DNS المضغوط وSNI المشفر/المجزأ قد لا يُستخرجان.

قائمة السجلات مرقمة من الخادم وبحثها مفهرس باستخدام SQLite FTS5. التصدير الحالي بحد 100000 سجل لكل طلب، ويلتقط قائمة المعرفات قبل البث ثم يقرأها باتصال مستقل للقراءة فقط. النسخة المحجوبة تستخدم سياسة `metadata_only_v1` فتزيل النصوص الحرة والمعرفات الحساسة؛ ليست نسخة تحقيق كاملة. النسخة غير المنقحة وتنزيل الأصل يتطلبان صلاحية `evidence.download` مستقلة.

## حدود البيانات

Codespaces لتطوير الكود والبيانات الاصطناعية فقط. نشر وتحليل بيانات الشركة يكون داخل بنيتها المعتمدة. حظر APIs الخارجية في التطبيق لا يغني عن منع خروج الشبكة من الحاويات والعمال ومحرك التقرير في بيئة الشركة.

لا تنقل سجلات شركة أو عينات أو نسخ قاعدة أو تقارير إلى GitHub أو إلى أدلة الاختبارات. تتبع نتيجة فحوص العزل والأداء على بيئة ممثلة؛ لا تُعامل نتائج fixture صغيرة كاختبار تحميل إنتاجي.
## النشر المؤسسي وعزل الخدمات

يشغّل `python run.py` العمال الثلاثة مع الخادم ومفاتيح التطوير المحفوظة، ولا يغير قاعدة `socify.db` الجذرية الموجودة. التشغيل الإنتاجي يبقى عبر Gunicorn وCompose ومفاتيح دائمة منفصلة عن بيئة التطوير.

يضم Compose مدخل NGINX داخلي النشر، وخدمة التطبيق على شبكة داخلية بلا default route، وعمال import/autopsy/playbook على `network_mode: none`. مدخل HTTP وحده ينشر `127.0.0.1:${SOCIFY_HTTP_PORT:-5000}` ولا يتلقى volume قاعدة القضية أو مفاتيحها. يلزم تطبيق TLS وسياسة الخروج على مدخل الشركة؛ لا تعادل الشبكة الداخلية وحدها عزل كل بيئة الشركة.

إذا كانت بيئة البناء تتطلب CA مؤسسية، يدعم Dockerfile secret اختياريًا اسمه `build_ca` يحتوي **شهادة الثقة العامة**، لا مفتاحًا خاصًا. تمرر بمثال `docker build --secret id=build_ca,src=/path/to/trusted-ca-bundle.pem --target runtime .`؛ لا تُضمّن الشهادة في الصورة ولا يُعطل التحقق من TLS. لا تحفظ بيانات proxy أو مفاتيح الشركة في المستودع.

التحليل الساكن لا ينفذ العينات. توجد علامة EICAR اصطناعية للاختبار، ويمكن للمدير نشر حزم YARA محلية ثابتة بعد أمثلة إيجابية وسلبية ومصدر وترخيص وبصمة، وفحصها في الخدمة المعزولة. مكتبة TI/GeoIP وSigma subset محلية؛ تُرفض الصيغ والمؤثرات غير المدعومة صراحة، ولا يحدث إثراء شبكي.


## Health وMonitoring

- `/health/live`: العملية تعمل ولا يكشف بيانات حساسة.
- `/health/ready`: اتصال DB وschema version.
- `/api/health`: بعد المصادقة يعرض import jobs قيد العمل وإخفاقات القواعد وإصدار ATT&CK.
- كل Response يعيد `X-Correlation-ID` وتكتب أخطاء الخادم نوع الخطأ فقط بلا payload أو secret.

راقب زمن الاستجابة ومعدل 5xx وحجم/WAL القاعدة وjobs في `processing` و`failed_evaluations` وتأخر استهلاك outbox.

## عامل إجراءات القضية

في الإنتاج تكون `SOCIFY_PLAYBOOK_INLINE_EXECUTION=0`، وتضيف API التشغيل إلى قائمة محفوظة. يشغّل Compose خدمة `playbook-worker`، أو شغّلها مستقلًا:

```bash
python -m scripts.run_playbook_worker --database instance/socify.db
python -m scripts.run_playbook_worker --database instance/socify.db --once
```

يعرض `/api/health` أعداد queued/running/failed وleases المنتهية. يسترد العامل أي تشغيل انقضت مدة ملكيته، وينفذ أثر كل خطوة مع تحديث حالتها في transaction واحدة. الفشل القابل للإعادة ينتظر backoff أسيًا حتى `retry_limit`. الإلغاء أثناء التنفيذ يضع طلبًا محفوظًا ويفحصه العامل قبل الأثر التالي. اضبط `SOCIFY_MAX_PENDING_PLAYBOOK_RUNS` لتحديد backpressure، ولا تشغّل inline في الإنتاج.

يعمل استيراد الإنتاج بالطريقة نفسها عبر خدمة `import-worker`، ويستأنف من checkpoint ذري كل 100 سجل:

```bash
SOCIFY_DATABASE=instance/socify.db python -m scripts.run_import_worker
SOCIFY_DATABASE=instance/socify.db python -m scripts.run_import_worker --once
```

استخدم مفتاح الاعتماد نفسه الذي شفّر دليل الرفع. يعرض `/api/health` queued/processing/failed وleases المنتهية. يحدد `SOCIFY_MAX_PENDING_IMPORT_JOBS` backpressure، ويجب أن تبقى `SOCIFY_IMPORT_INLINE_EXECUTION=0` في الإنتاج.

## النسخ الاحتياطي

أوقف الكتابة أو ضع الخدمة في وضع صيانة، ثم:

```bash
python scripts/backup.py backups/socify-$(date +%Y%m%d).db --source instance/socify.db
python scripts/migrate.py --database instance/socify.db --dry-run
```

تستخدم الأداة SQLite Online Backup API وتفحص `integrity_check` وforeign keys. خزّن الناتج مشفرًا وبصلاحيات محدودة واختبر الاستعادة خارج مسار الإنتاج.

## الاستعادة

أوقف جميع workers وتحقق من نسخة المصدر ثم:

```bash
python scripts/restore.py backups/socify-20261015.db instance/socify-restored.db --confirm RESTORE
SOCIFY_DATABASE=instance/socify-restored.db python scripts/migrate.py
SOCIFY_DATABASE=instance/socify-restored.db gunicorn --config gunicorn.conf.py app:app
```

تحقق من `/health/ready` وعدد users/events/alerts/cases وتقارير audit قبل تبديل المسار. احتفظ بالقاعدة القديمة إلى نهاية التحقق.

## ترقية ATT&CK والرجوع

حمّل نسخة MITRE Enterprise STIX محفوظة محليًا مع اسم إصدار صريح. يرفض الأمر الحزمة الناقصة افتراضيًا، ويحسب SHA-256، ويحفظ الإصدار دون تعديل الإصدارات السابقة، ثم يفعّله ذريًا:

```bash
python -m scripts.load_attack_snapshot enterprise-attack.json --version 20.1 --database instance/socify.db
python -m scripts.load_attack_snapshot --activate-version 20.0 --database instance/socify.db
```

راجع `GET /api/attack/catalogs` وسجل `attack_catalog_transitions` بعد الترقية. لا تعِد استخدام اسم إصدار لمحتوى مختلف؛ يرفضه النظام بدل الكتابة فوق الدليل السابق.

## Rollback التطبيق

ابنِ image سابقًا من commit SHA موثق، أوقف الجديد، أعد Volume إلى نسخة متوافقة عند وجود migration غير عكوسة، شغّل readiness ثم أعد توجيه Proxy. ترحيلات قاعدة البيانات تراكمية؛ الاستعادة إلى مخطط أقدم تتطلب نسخة احتياطية متوافقة.

## تشخيص التحليل والتنافس

المقبس `analysis.sock` يملك صلاحيات `0660`؛ يجب أن تتطابق هوية المستخدم/المجموعة بين الخادم والعميل. يبقى حجم IPC للعميل للقراءة فقط، ويُقفل مجلد الخدمة قبل استقبال الأعمال. تركيب الحجم `ro` لا يمنع اتصال UNIX socket بحد ذاته؛ لا تحوله إلى `rw` لمعالجة خطأ صلاحيات دون تشخيص.

يعيد العميل محاولة **الاتصال فقط** ثلاث مرات بعد 100 ثم 200 ثم 400ms عند غياب المقبس أو رفض الاتصال، ثم يفشل برسالة محددة. لا يُعاد إرسال طلب وصل إلى الخدمة. افحص `docker compose logs analysis` وهوية الحاويات وصلاحية inode عند رفض الإذن؛ لا تنسخ مفاتيح التطبيق إلى خدمة التحليل.

يتطلب التحليل المحلي Linux وprocfs وseccomp وعزل الملفات. على مضيف غير مدعوم، شغّل هدف Docker المخصص واضبط `SOCIFY_ANALYSIS_SOCKET`. يبقى التحليل fail-closed عند تعذر العزل؛ لا يوجد fallback غير معزول. لا تضبط علامة الحاوية المعزولة على عملية مضيف عادية.

تستخدم القواعد الملفية WAL، و`busy_timeout=15000`، ومفاتيح خارجية مفعّلة. تظل حجوزات العمال بمعاملات `BEGIN IMMEDIATE` قصيرة؛ يخفف عامل الاستيراد والتحليل الانتظار عند تنافس الحجز. لا تستخدم filesystem شبكيًا غير متوافق مع WAL، واحتفظ بملفات القاعدة/WAL معًا عند صيانة الملفات؛ أداة backup تستخدم SQLite Online Backup.

حدود البريد: 2MiB، عمق MIME حتى 5 (الجذر عمق 0)، 100 جزء، 200 رأس و25 مرفقًا. تُفحص الحدود قبل فك payloads. يُحفظ الأصل مشفرًا وببصمته؛ أسماء العرض آمنة وتحتفظ بالامتداد، والأسماء غير القابلة للتحويل تستبدل باسم مشتق من SHA-256. أسماء العميل لا تستخدم مسارًا للتخزين. تُرفض DTD والكيانات الخارجية في XML حتى مع مقدمة طويلة أو ترميز UTF-16.
