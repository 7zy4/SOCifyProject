# دليل الأمان

## أسرار الإنتاج

اضبط قيمًا مستقلة عالية entropy لـ`SOCIFY_SECRET_KEY` و`SOCIFY_CREDENTIAL_KEY` في مدير أسرار. تغيير مفتاح الاعتماد يمنع فك بيانات المصادر القديمة؛ نفذ rotation بخطة إعادة إدخال. لا تضع `.env` في Git.

## TLS وReverse Proxy

شغّل Gunicorn خلف Proxy ينهي TLS، ثم فعّل `SOCIFY_HTTPS=1` لتطبيق Secure cookie وHSTS. اضبط `SOCIFY_TRUSTED_HOSTS` للأسماء الفعلية. لا تمرر forwarded headers إلا من Proxy موثوق، ولا تعرض خادم Flask التطويري.

## الشبكة

`SOCIFY_SOURCE_ALLOWLIST` قائمة أسماء مضيفين دقيقة لموصل Sandbox. حتى مع القائمة تمنع الدالة loopback وprivate وlink-local وreserved بعد DNS. الإصدار الحالي لا ينفذ HTTP fetch من Web Request؛ يحتاج worker معزولًا ليصبح مدعومًا.

## الاحتفاظ والنسخ

الأحداث لا تحذف عبر API لأنها Evidence. طبق retention بعد موافقة وسياسة موثقة، مع export وhash وسجل تدقيق. شفّر Volume والنسخ الاحتياطية خارج التطبيق، واختبر الاستعادة دوريًا.

## الاستجابة للثغرات

أوقف النشر، احفظ logs وcorrelation IDs، دوّر الأسرار المتأثرة، ألغ الجلسات، أصلح مع test regression، ثم أعد SAST/SCA/secret scan والاختبارات الأمنية. مسار الإفصاح في `SECURITY.md`.

## قائمة نشر

- `SOCIFY_ENV=production` وفشل الإقلاع دون secret.
- TLS وSecure cookie وTrusted Hosts.
- Volume مستمر مشفر ونسخة استعادة مجربة.
- 0 Findings مفتوحة Critical/High.
- التسجيل العام معطل ما لم يكن مقصودًا.
- لا demo seed أو demo password.
- ATT&CK snapshot version/count موثقان.
- Health endpoint داخلي ومراقبة error rate وqueue lag.
- `SOCIFY_PLAYBOOK_INLINE_EXECUTION=0` وعامل Playbook منفصل على Volume القاعدة نفسه، مع تنبيه على failed وexpired leases.
- `SOCIFY_IMPORT_INLINE_EXECUTION=0` وعامل Import منفصل يملك مفتاح فك دليل الرفع، مع حد queue وتنبيه على failed وexpired leases.
