# دليل المحلل

1. راجع Dashboard؛ الأرقام من الاستعلام الحالي وليست عينات.
2. افتح Events وراجع المصدر ووقت الحدث وraw provenance قبل اتخاذ قرار.
3. افرز Alert؛ حالة false positive أو suppress تتطلب سببًا.
4. أنشئ Case من Alert، ثم اربط الأدلة ذات الصلة فقط.
5. أضف Notes بصيغة نصية آمنة ومهامًا واضحة؛ لا تضع أسرارًا أو بيانات شخصية غير لازمة.
6. انتقل بالحالة وفق المسار New → Triaged → Investigating → Contained → Remediated → Recovered → Closed.
7. اطلب Playbook محاكى بعد المعاينة. الخطوة الحساسة تنتظر Manager ولا تؤثر خارج المختبر.
8. أكمل evidence والمهام وحقول الإغلاق؛ يحتفظ التقرير بنسخة وتاريخ.

Hunt query أمثلة:

```text
severity = critical
event_type = failed_login AND source_ip = "198.51.100.20"
process_name ~ powershell AND NOT outcome = success
mitre_id = T1110
```

الاستعلام parser محدد ولا يقبل SQL أو functions حرة.
