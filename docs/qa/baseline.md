# Repository reality check

## نقطة البداية

- Base branch: `feature/phase-1-security-detection-incidents` at `30735cfcdd186750305a619f7542d5f71ab5ac53`.
- Target branch: `feature/enterprise-platform-implementation`.
- Existing PR: draft PR #1 from Phase 1 to `main`; البرنش الحالي stacked فوق Phase 1 لحفظ التاريخ.
- Baseline test: 6/6 اختبارات Phase 1 مرت قبل التغيير في 4.033s.
- Existing implementation: Flask + SQLite، صفحات منفصلة، CRUD جزئي للأحداث والقواعد والحالات، JavaScript يحوي نجاحات وهمية وبيانات متولدة في المتصفح، schema init منفصل وغير شامل.

## مخاطر البداية

| الخطر | الأولوية | المعالجة |
|---|---:|---|
| نجاحات UI وهمية و`Math.random` | P0 | استبدال الواجهة كاملة بطبقة API فعلية وحذف الملفات القديمة |
| IDOR عبر workspace/training run | P0 | RBAC + workspace + owner scope + negative tests |
| schema متضارب وحذف محتمل | P0 | idempotent additive migration وbackup/dry-run |
| DSL غير typed | P0 | parser allowlist وbudgets بلا eval/SQL |
| أسرار مصدر تعاد في API | P0 | Fernet at rest وحذف الحقول في serializer |
| محاكاة قد تنفذ اتصالًا | P0 | لا network executor وdefault deny وdocumentation ranges |
| وقت حدث قديم يقارن بـnow | P1 | event-time windows وallowed lateness وdedup |
| SQLite concurrency | P1 | WAL/busy timeout/transactions/optimistic lock وحد تشغيلي موثق |
| تغطية ATT&CK كاملة | P1 | loader رسمي كامل + subset offline معلن؛ لا ادعاء Full عند count ناقص |
| Worker restart | P1 | نموذج Job موجود؛ العامل الموزع لم يكتمل ويظل Release blocker إن طُلب إثبات kill/restart |
