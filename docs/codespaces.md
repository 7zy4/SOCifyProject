# تشغيل GitHub Codespaces

1. افتح المستودع واختر **Code → Codespaces → Create codespace** على البرنش المطلوب.
2. ينتظر `postCreateCommand` حتى يثبت runtime/dev dependencies ويهيئ `instance/socify.db` بلا حذف بيانات سابقة.
3. يشغّل `postStartCommand` Gunicorn على `0.0.0.0:5000` داخل الحاوية فقط.
4. افتح تبويب **Ports** وتحقق أن المنفذ 5000 يحمل Visibility بقيمة `Private` قبل فتحه.
5. أنشئ حساب Analyst من `/register`، أو نفذ seed صريحًا من Terminal بعد وضع كلمة مرور تطوير قوية.

```bash
export SOCIFY_SEED_DEMO=1
export SOCIFY_DEMO_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
python create_db.py
printf 'Temporary demo password: %s\n' "$SOCIFY_DEMO_PASSWORD"
```

إذا لم يبدأ الخادم، راجع `/tmp/socify-gunicorn.log` ثم نفذ `curl -fsS http://127.0.0.1:5000/health/ready`. لا تجعل المنفذ Public للتجربة العادية.

## فتح الموقع في المتصفح بعد إنشاء Codespace

- أنشئ Codespace من البرنش `feature/socify-browser-review-2026-10-20`، وليس `main` (ما زال يحتوي النسخة القديمة).
- يقوم Dev Container بتثبيت المتطلبات وإنشاء `instance/codespaces.env` وتشغيل Gunicorn تلقائيًا. قد يستغرق الإعداد الأول بعض الوقت.
- افتح تبويب **Ports** داخل Codespaces. تأكد من أن المنفذ `5000` ظاهر وأن Visibility = **Private** ثم اضغط أيقونة فتح المتصفح بجواره.
- يسمح التطبيق تلقائيًا بعنوان Codespaces الذي يطابق `CODESPACE_NAME-5000.app.github.dev` فقط، ولا يتطلب ضبط `TRUSTED_HOSTS` إلى `*`.
- افتح `/register` لإنشاء حساب Analyst بكلمة مرور قوية لا تقل عن 12 حرفًا؛ لا يوجد حساب Admin افتراضي في هذا الفرع.
- للتحقق من صحة الخادم من داخل Terminal: `curl -fsS http://127.0.0.1:5000/health/ready`.
- لو لم يظهر المنفذ أو الموقع، راجع `tail -n 100 /tmp/socify-gunicorn.log` وابدأ الخادم يدويًا: `bash -lc 'set -a; source instance/codespaces.env; set +a; gunicorn --config gunicorn.conf.py app:app'`.
- إذا ظهر خطأ `400 Bad Request` تأكد أن عنوان المتصفح هو المنفذ 5000 الخاص بنفس Codespace. لا تعطل حماية المضيف.
- قاعدة البيانات محفوظة داخل مساحة Codespace على `instance/socify.db`؛ لا تحذف Codespace إذا أردت الاحتفاظ بالبيانات دون نسخة احتياطية.
