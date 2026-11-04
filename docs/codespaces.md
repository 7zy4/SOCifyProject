# التشغيل في Codespaces

## تجهيز البيئة

- افتح Codespace خاصًا من مستودع SOCifyProject.
- للتحديث: `git pull --ff-only` من الفرع الذي تعمل عليه.
- اختر **Codespaces: Rebuild Container** إذا تغيّرت الحاوية أو متطلباتها.
- احتفظ بقاعدة البيانات و`instance/codespaces.env`؛ تغيير المفاتيح يمنع فك الأدلة القديمة.
- استخدم بيانات غير حساسة في البيئة الخاصة؛ بيانات المؤسسة تُعالج في بنيتها المعتمدة.

## أول تشغيل

```bash
bash scripts/try_codespace.sh owner@example.com --create-manager
```

- يجهز المشغّل خدمة التحليل المعزولة ثم التطبيق والعمال.
- يعرض مسار ملف بيانات الدخول الخاص داخل بيئتك.
- افتح **Ports → 5000 → Open in Browser** وأبق المنفذ **Private**.
- سجّل الدخول، أنشئ قضية، وارفع سجلاتها.

## التشغيل التالي

```bash
bash scripts/try_codespace.sh owner@example.com
```

- تبقى الحسابات والبيانات محفوظة.
- أوقف التطبيق بـ Ctrl+C من طرفيته.
- إذا كان المنفذ مشغولًا، أوقف التطبيق السابق أو اختر منفذًا آخر:

```bash
SOCIFY_PORT=5001 bash scripts/try_codespace.sh owner@example.com
```

## استعادة الدخول

- لتعيين كلمة مرور تفاعليًا مع إلغاء الجلسات السابقة:

```bash
bash scripts/try_codespace.sh owner@example.com --reset-password
```

- لإيداع كلمة مرور مولدة في ملف محلي خاص:

```bash
bash scripts/try_codespace.sh owner@example.com --recover-access
```

- لا تغيّر استعادة كلمة المرور إعداد MFA أو دور الحساب أو أدلة القضية.
- لا ترفع ملف الدخول أو المفاتيح إلى المستودع.

## التحقق

```bash
docker info
curl -fsS http://127.0.0.1:5000/health/ready
```

- إذا غاب Docker، أعد بناء الحاوية.
- إذا فشل فك الأدلة، استعد المفاتيح الأصلية بدل إنشاء مفاتيح جديدة.
- [استكشاف الأعطال](troubleshooting.md) · [التشغيل المؤسسي](operations.md).
