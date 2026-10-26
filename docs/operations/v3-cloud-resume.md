# استكمال V3 دون إعادة البدء

استخدم checkout الموجود وفرع `socify-version-3`. لا تنشئ فرعًا أو worktree ولا تعمل reset ولا تغير `main` أو V2. افحص `git status` وآخر commit والمصفوفة `docs/qa/v3-acceptance.csv` قبل التعديل. لا تفسر نجاح اختبارات التراجع على أنه قبول كل الرحلات.

## البيئة المحفوظة

Python المثبت في البيئة الحالية: `/workspace/.venv/bin/python`؛ اعتمادياته مفحوصة بـ`pip check`. نسخة fork المستخدم `7zy4/rea` المثبتة موجودة في `/workspace/.cache/socify-v3-tools/rea`، وهويتها `2250e67bc271c83f9e200ee298aa04a2457438a6` و6.7.0 في `rea-tool-identity.json`. ليست checkout مشروع إضافيًا.

لا تفترض أن عملية حية أو صورة Docker تبقى بعد إيقاف البيئة. تحفظ الصورة كملف `/workspace/.cache/socify-v3-tools/analysis-image.tar` للتحميل المحلي في snapshot البيئة. عند غياب ذلك الملف في clone مستقل، ابن الصورة من المصدر:

```bash
docker build --target analysis -t socify-v3-verification-analysis .
bash scripts/start_local_analysis.sh
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-v3-dev-analysis-ipc/analysis.sock
python run.py
```

استخدم `docker load -i /workspace/.cache/socify-v3-tools/analysis-image.tar` بدل البناء إذا كان الملف المحفوظ موجودًا. أداة البدء تستخدم UID غير مميز وشبكة none وجذرًا للقراءة فقط وtmpfs، وتتحقق من هوية backend سابقة قبل إعادة استخدامها. لا تغير صلاحيات IPC أثناء وجود عمل. في النواة الحالية Landlock غير متاح؛ التحليل يفشل مغلقًا ما لم تتوفر الخدمة المعزولة الفعلية. لا تتجاوز هذه الحدود لتسهيل الاختبار.

في البيئة السحابية الحالية فعّل venv أو استخدم مساره الصريح. `python run.py` يحافظ على مفاتيح التطوير الموجودة عبر `scripts.environment`؛ لا تحذف ملف المفاتيح أو تعِد توليدها لقاعدة قديمة. تأسيس المدير يتم عبر `python -m scripts.bootstrap_team` وبكلمة مرور تختارها؛ لا يوجد حساب أو سر افتراضي للإنتاج.

## التحقق والاستكمال

اجتازت فحوص GitHub بعد إصلاح نطاق مفاتيح Compose وتزامن اختبارَي المهمة وMITRE؛ الدليل في `../qa/v3-ci-corrections-2026-10-26.md`. فحص dependency-review مخصص لـpull_request، وتخطيه عند push متوقع. يختبر CI التكبير الأصلي في Chromium الكامل داخل Xvfb، مع بقاء بقية الرحلات فعالة. لمطابقة جلسة سطح المكتب محليًا عند توفر Xvfb استخدم `xvfb-run --auto-servernum --server-args='-screen 0 1600x1200x24' pytest -q -m e2e --no-cov tests/e2e`. في هذه البيئة فقط توجد أدوات Xvfb المفكوكة تحت `/workspace/.cache/socify-v3-tools/xvfb/root/usr/bin`؛ أضفها إلى PATH عند الحاجة. ليست مطلوبة لتشغيل المنصة نفسها.

```bash
export PATH=/workspace/.venv/bin:$PATH
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-v3-dev-analysis-ipc/analysis.sock
pytest -q --cov=socify
pytest -q -m e2e --no-cov tests/e2e
ruff check .
ruff format --check .
mypy socify scripts app.py create_db.py init_db.py run.py
bandit -q -c pyproject.toml -r socify scripts app.py create_db.py init_db.py run.py
SOCIFY_REA_CLI=/workspace/.cache/socify-v3-tools/rea/scripts/rea.mjs bash scripts/run_rea_analysis.sh /tmp/socify-rea-current.json
```

احفظ دليل REA والـmanifest ببصمات المدخلات بعد أي تعديل واجهة. اختبار الإنتاج الاصطناعي في `tests/container/verify_autopsy.py`؛ وأداة `verify_recovery.py` تختبر جلسة مصادقًا عليها وأعمالًا معلقة وإعادة تشغيل الخدمات ثم توقف backend وتعافيه التلقائي. استخدم مشروع Docker الاصطناعي المخصص فقط، دون بيانات الشركة أو حذف volumes.

الأداء قابل للإعادة عبر `python -m scripts.benchmark_autopsy --events 1000000 --concurrency 20 --requests 100 --output /tmp/capacity.json`. يفسر 10,000 سجل فعليًا ويزيد الباقي بـSQL لقياس التخزين والقراءة؛ لا تسوّق ذلك على أنه قياس استيراد مليون سجل أو TLS أو موارد خدمة التحليل.

لقياس الاستيراد الإنتاجي الفعلي استخدم `tests/container/benchmark_production.py` مع ملفي Compose الأساسي و`tests/container/compose.performance.yml` ومشروع `socify-v3-performance` فقط. يتحقق البرنامج من marker اصطناعي على الخدمات الخمس قبل تأسيس حسابات الاختبار، ويرفع ملفات JSONL فعلية على دفعات 10,000 سجل، ويستخدم 20 جلسة مستقلة وTLS محليًا موثقًا وCSRF فعليًا. يسجل التوزيعات والموارد والتقارير والبصمات ولا يزيد عدد الأحداث عبر SQL.

في البيئة الحالية ملفا الحالة الخاصان بالمشغل محفوظان خارج المستودع في `/workspace/.cache/socify-v3-tools/`: `performance.env` و`capacity-million-state.json`. لا تطبعهما أو ترفعهما إلى Git، ولا تغير مفاتيحهما أثناء استكمال قاعدة الاختبار. الحالة تحتوي بيانات دخول اصطناعية بصلاحيات 0600 وحارس flock. عند انقطاع البرنامج استأنف بنفس الملف؛ يجري التحقق من الدفعات المحفوظة ولا تعاد معالجة المكتمل. بعد اكتمال الاستيراد يمكن إعادة قياس القراءات والتقارير بـ`--measure-only` دون استيراد مليون سجل ثانية.

```bash
SOCIFY_HTTP_PORT=15006 PYTHONPATH=. python tests/container/benchmark_production.py \
  --env-file /workspace/.cache/socify-v3-tools/performance.env \
  --state /workspace/.cache/socify-v3-tools/capacity-million-state.json \
  --events 1000000 --output /tmp/socify-capacity-production.json
```

احترم اختبارات TLS والفشل ولا تضف retries تخفي أخطاء HTTP. أوقف driver عند تحديث صور خدمات القياس ثم تحقق من اكتمال الدفعة وسجل حيازتها قبل إعادة تشغيل العامل؛ حافظ على volumes. مدة الحائط تشمل التوقفات والتحديثات، بينما تحفظ طوابع الدفعات الأصلية زمن المعالجة الفعلي؛ لا تحول هذه التجربة الاصطناعية إلى SLO للشركة.

تواصل GitHub عبر proxy المثبت؛ لا تطلب token ما دامت عمليات Git تعمل. افحص الأسرار قبل commit، وارفع commits واضحة على V3، ثم حدث أدلة القبول دون تعطيل اختبارات أو خفض شرط التغطية. Codespaces وهذه البيئة للتطوير ببيانات اصطناعية؛ بيانات الشركة تعالج في نشرها الداخلي المعزول.
