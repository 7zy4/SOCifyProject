# السيناريوهات المرجعية

## سلسلة التصيد وسوء استخدام الاعتماد

ست مراحل: رسالة تصيد اصطناعية، وصول إلى مخزن اعتماد اصطناعي، خمس محاولات دخول من `198.51.100.20`، اكتشاف حسابات وعلاقة `winword.exe → powershell.exe`، وصول إلى ملف تدريبي، ثم تسريب محاكى إلى `203.0.113.50`.

Expected detections: correlation للتصيد، brute force، suspicious parent-child. Expected evidence: sender/attachment وsource IP/user وhost/process وfile hash وdestination. Allowed response: `contain_simulated_exfiltration`.

## سيناريوهات قابلة للبناء

- Password spraying: مستخدمون متعددون ومصدر واحد ونافذة event time.
- Ransomware behavior: سلسلة file rename وshadow-copy simulation بلا تنفيذ process حقيقي.
- Lateral movement: authentication وservice creation اصطناعيان بين documentation hosts.
- Cloud anomaly: login من documentation IP مع device/session mismatch.
- Insider access: حجم قراءة غير معتاد لحساب تدريبي مع false-positive decoys.

هذه القائمة أمثلة تصميم وليست ادعاء بأنها seeded أو منشورة ما لم تظهر في `/api/scenarios`.
