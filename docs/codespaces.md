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
