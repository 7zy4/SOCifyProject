# التشغيل والاستعادة

## Health وMonitoring

- `/health/live`: العملية تعمل ولا يكشف بيانات حساسة.
- `/health/ready`: اتصال DB وschema version.
- `/api/health`: بعد المصادقة يعرض import jobs قيد العمل وإخفاقات القواعد وإصدار ATT&CK.
- كل Response يعيد `X-Correlation-ID` وتكتب أخطاء الخادم نوع الخطأ فقط بلا payload أو secret.

راقب زمن الاستجابة ومعدل 5xx وحجم/WAL القاعدة وjobs في `processing` و`failed_evaluations` وتأخر استهلاك outbox.

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

## Rollback التطبيق

ابنِ image سابقًا من commit SHA موثق، أوقف الجديد، أعد Volume إلى نسخة متوافقة عند وجود migration غير عكوسة، شغّل readiness ثم أعد توجيه Proxy. الإصدار الحالي يدعم migrations إضافية forward-only؛ لا توجد أداة downgrade آلية ويجب ألا يدّعي CI خلاف ذلك.
