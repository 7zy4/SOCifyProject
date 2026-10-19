# دليل المدرّب

## تصميم السيناريو

يحتاج السيناريو name/description/objectives/difficulty/duration/environment/steps/scoring. كل خطوة تحوي Event Template اصطناعيًا وMITRE IDs وGround Truth. يرفض الخادم URLs الخارجية وحقول authorization/password.

مرّر السيناريو عبر Draft → Validated → Published → Ready. التعديل ينشئ version جديدًا ويعيده إلى Draft؛ التشغيل القديم يبقى مرتبطًا بإصداره.

## الصعوبة والحتمية

- Beginner: hints ظاهرة ولا Noise.
- Intermediate: حدث benign إضافي لكل خطوة.
- Advanced: ثلاثة Noise events وتأخر/تداخل أكبر.

نفس scenario version وseed وdifficulty ينتج ids منطقية ومحتوى متكررًا؛ مفاتيح idempotency تمنع مضاعفة events عند إعادة Play. Restart يلغي التشغيل القديم وينشئ تشغيلًا جديدًا بنفس seed.

## Ground Truth والتقييم

لا يصل Analyst إلى Ground Truth قبل نهاية التشغيل؛ Instructor/Manager يملك endpoint المخصص. عرّف expected detections وrelevant evidence وallowed responses وأوزانًا مجموعها 100. يحفظ التقييم inputs/weights/components/fingerprint ولا يعاد حساب Snapshot بصورة متغيرة.

## السلامة

استخدم `.test` وعناوين RFC 5737 فقط. لا تُدخل بريد ضحية أو credential حقيقية أو endpoint عام. Playbooks من allowlist وتغيّر DB المحاكاة فقط.
