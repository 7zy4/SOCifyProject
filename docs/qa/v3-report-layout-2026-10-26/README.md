# قبول التقرير الطويل والخط الزمني — 2026-10-26

أُنتجت ملفات PDF وDOCX وJSON وHTML وMarkdown فعليًا عبر خدمة التحليل المحلية المعزولة. كل المحتوى اصطناعي. يحفظ كل manifest بصمات ملفات التشغيل ومصدر renderer ونتيجة فحص الهندسة؛ تحفظ هنا PDF وDOCX والمدخلات ولقطات المراجعة. لم تُعد كتابة تقارير قضايا سابقة.

## الدليل

- `bilingual/`: تقرير عربي/إنجليزي من 24 صفحة، عنوان 255 حرفًا، رابط 4096 حرفًا وسلسلة متصلة 2048 حرفًا، أسباب جذرية و5 Whys وأدلة وخط زمني مشترك. فُحصت حدود 2938 كلمة على كل الصفحات، والغلاف والوسط والنهاية وصورة تجمع كل الصفحات بصريًا.
- `wide-title/`: تقرير من 24 صفحة بعنوان `W` مكررًا 255 مرة. اجتازت حدود 2881 كلمة، وفُحص الغلاف بصريًا؛ لا يُعرض نجاح العينة الأولى وحده بوصفه دليلًا لكل النصوص الممكنة.
- أصلح الاختبار غلافًا كان ينفصل عن عنوانه الطويل، وصفحة إضافية شبه فارغة للبصمة، وانعكاس ترتيب أجزاء timestamp في سياق عربي. بقيت الخطوط محلية وهوية الألوان ثابتة. يُخفض عنوان الغلاف الأطول من 100 حرف إلى 24pt للحفاظ على اكتماله، ويبقى العنوان القصير 48pt.
- يُطبع توقيت المصدر وأساس التوقيت ومراجع التحقيق والإجراءات في الخط الزمني المشترك. API والمتصفح يثبتان ترتيب الميكروثواني، وبقاء الوقت المجهول في النهاية، والفصل بين وقت التوثيق ووقت الهجوم، وعدم إدراج ملاحظات خاصة في التقرير المشترك.

## إعادة التحقق

شغّل backend المحلي المعزول وفق `docs/operations-v4.md` وثبت Poppler في بيئة الاختبار، ثم:

```bash
export SOCIFY_ANALYSIS_SOCKET=/tmp/socify-v4-dev-analysis-ipc/analysis.sock
python -m tests.container.verify_report_layout --output /tmp/socify-report-layout
pdftotext -bbox-layout /tmp/socify-report-layout/long-report.pdf /tmp/socify-report-layout/bbox.xml
python -m tests.container.verify_report_layout --output /tmp/socify-report-layout --bbox /tmp/socify-report-layout/bbox.xml
python -m tests.container.verify_report_layout --unbroken-title --output /tmp/socify-report-wide
pdftotext -bbox-layout /tmp/socify-report-wide/long-report.pdf /tmp/socify-report-wide/bbox.xml
python -m tests.container.verify_report_layout --output /tmp/socify-report-wide --bbox /tmp/socify-report-wide/bbox.xml
```

يتحقق الفحص من جميع حدود الكلمات، وجود مرجع القضية والبصمة على الغلاف، وعدم إنشاء صفحة خالية، وبقاء timestamp كاملًا بالترتيب اللاتيني الصحيح. تحفظ CI الفحص الأول إلزاميًا بعد اختبارات التراجع، وتبقى المعاينة البصرية جزءًا مستقلًا من دليل القبول.
