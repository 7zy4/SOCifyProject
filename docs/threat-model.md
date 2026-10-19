# Threat model

## الأصول

- حسابات وجلسات المتدربين والمدربين.
- raw logs والأدلة ونتائج التحقيق والتقييم.
- مفاتيح مصادر البيانات وإعدادات الاتصال.
- سلامة القواعد والسيناريوهات وGround Truth.
- سجل التدقيق والنسخ الاحتياطية.

## حدود الثقة

المتصفح غير موثوق. الملفات المرفوعة غير موثوقة. DSL واستعلام الصيد غير موثوقين. الشبكة الخارجية محظورة افتراضيًا. قاعدة البيانات محلية للتطبيق ويجب ألا توضع تحت `static` أو Web Root.

## STRIDE والضوابط

| الخطر | مثال | الضابط | اختبار |
|---|---|---|---|
| Spoofing | سرقة جلسة | HttpOnly/SameSite، Secure عند HTTPS، rotation، DB revocation، MFA | E2E-02/05 |
| Tampering | تعديل Evidence | hash، immutable event policy، history، report fingerprint | E2E-23/25 |
| Repudiation | إنكار تغيير Rule | audit actor/time/result/correlation | F01/F09 integration |
| Information disclosure | IDOR على Run أو Case | workspace + training ownership في الخادم | E2E-44/51 |
| Denial of service | JSON عميق أو ملف ضخم | size/rows/line/nesting budgets، query/result limits | E2E-17/45 |
| Elevation | Analyst يستدعي admin API | deny-by-default RBAC decorator | E2E-43 |
| SSRF | مصدر HTTP إلى metadata IP | HTTPS allowlist، DNS resolution، منع private/loopback/reserved | E2E-45 |
| Injection | DSL/SQLi/XSS/CSV formula | typed parser، parameterized SQL، textContent/escaping، CSV prefix | E2E-45/55 |
| Supply chain | dependency خبيث | pinning، SCA، SBOM، SAST، pinned Actions | CI security gate |

## إساءة الاستخدام

- Scenario step يحوي URL أو Authorization أو password: يرفض قبل الحفظ.
- Playbook action غير موجودة في allowlist: يرفض؛ لا Shell أو HTTP executor.
- Ground Truth عبر API كمحلل: 403 ولا يضمّن في DOM.
- إعادة POST أو double click: idempotency في events/imports/playbook runs/detection dedup.
- مصدر اتصال عام: النتيجة `not_configured/failed/unsupported` بدل نجاح وهمي.

## مخاطر متبقية

SQLite مناسب لعملية تطبيق واحدة أو عدد محدود من workers؛ تنافس الكتابة العالي يحتاج PostgreSQL. CSP لا تستخدم inline scripts، لكن تقرير HTML المرفق ذاتي التنسيق وقد يحجبه CSP عند المعاينة داخل المتصفح دون التأثير على سلامته. مخاطر العامل الموزع غير مقبولة كميزة مكتملة حتى ينفذ Worker مستقل واختبار kill/restart.
