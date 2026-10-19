# استكشاف الأعطال

| العرض | الفحص | الحل |
|---|---|---|
| 403 CSRF | Response code ووقت الصفحة | حدّث الصفحة وأعد الإرسال؛ لا تعطل CSRF خارج الاختبارات |
| 401 بعد الدخول | `auth_sessions` ووقت UTC | تحقق من secret ثابت وsession expiry وعدم إلغاء الجلسة |
| `MFA_KEY_MISMATCH` | مفتاح الاعتماد | استعد المفتاح الصحيح أو أعد MFA عبر Admin بمسار مدقق |
| DB locked | عدد workers ومدة transactions | استخدم workers محدودة مع SQLite أو انتقل إلى PostgreSQL |
| Import rejected | `/api/imports/{id}` | صحح UTF-8/format/timezone/line size ثم أعد ملفًا جديدًا |
| HTTP source `not_configured` | allowlist | النتيجة متوقعة؛ لا يوجد اتصال فعلي قبل worker Sandbox |
| ATT&CK technique missing | metadata count/version | حمّل Bundle STIX الرسمي عبر script ثم أعد الاستعلام |
| Playbook awaiting approval | الدور والحالة | Manager فقط يوافق؛ لا تتجاوز البوابة عبر DB |
| Codespace لا يفتح | Ports وlog | اجعل 5000 Private وافحص `/tmp/socify-gunicorn.log` |
