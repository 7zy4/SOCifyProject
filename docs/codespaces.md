# تشغيل SOCify في Codespaces

افتح بيئة Codespace المرتبطة بفرع `final` في مستودع SOCifyProject. لتحديث البيئة الموجودة:

```bash
git fetch origin
git switch final
git pull --ff-only
```

من لوحة الأوامر اختر **Codespaces: Rebuild Container** عند تغيير إعداد الحاوية أو متطلباتها. احتفظ بمجلد `instance` وملفات مفاتيحه؛ فهي ضرورية لفتح الأدلة المحفوظة.

## أول تشغيل

أنشئ حساب المدير وشغّل التطبيق وخدمة التحليل:

```bash
bash scripts/try_codespace.sh owner@example.com --create-manager
```

يعرض الأمر مسار ملف بيانات الدخول داخل بيئتك. افتح **Ports → 5000 → Open in Browser**، مع إبقاء المنفذ **Private**، ثم سجّل الدخول وأنشئ قضيتك وارفع سجلاتها.

## التشغيل اللاحق

```bash
bash scripts/try_codespace.sh owner@example.com
```

يبقى الحساب والبيانات محفوظين. استخدم Ctrl+C لإيقاف التطبيق من طرفيته. إذا كان المنفذ مستخدمًا، أوقف العملية السابقة أو اختر منفذًا آخر:

```bash
SOCIFY_PORT=5001 bash scripts/try_codespace.sh owner@example.com
```

## استعادة الدخول

```bash
bash scripts/try_codespace.sh owner@example.com --reset-password
```

لإيداع كلمة مرور مولّدة في ملف محلي خاص:

```bash
bash scripts/try_codespace.sh owner@example.com --recover-access
```

## فحص الاتصال

```bash
docker info
curl -fsS http://127.0.0.1:5000/health/ready
```

إذا لم يتوفر Docker، أكمل إعادة بناء الحاوية. إذا تعذّر فك تشفير الأدلة، راجع وجود مفاتيح القاعدة الأصلية بدل إنشاء مفاتيح بديلة. للتشغيل المؤسسي راجع [دليل التشغيل](operations.md).
