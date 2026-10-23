# نموذج البيانات

## الكيانات المحورية

| المجال | الجداول | قواعد النزاهة |
|---|---|---|
| الهوية | `users`, `auth_sessions`, `mfa_enrollments`, `workspace_memberships` | بريد فريد، جلسة hashed قابلة للإلغاء، MFA مشفر |
| السجلات | `security_events`, `event_sources`, `ingestion_jobs`, `ingestion_errors` | event public ID فريد، idempotency فريد لكل workspace، raw hash وprovenance |
| الكشف | `rules`, `rule_versions`, `alerts`, `alert_events`, `detection_matches` | إصدار ثابت في Alert، dedup key فريد، روابط events بقيود FK |
| التحقيق | `incident_cases`, `case_events`, `case_alerts`, `case_evidence`, `case_notes`, `case_tasks`, `case_history`, `case_reports` | reference فريد، optimistic version، hash للأدلة، report revisions |
| التدريب | `attack_scenarios`, `scenario_versions`, `scenario_steps`, `scenario_ground_truth`, `training_runs`, `trainee_actions` | version immutable، seed محفوظ، idempotency للأفعال |
| المعرفة | `attack_techniques`, `attack_catalog_versions`, `attack_technique_versions`, `attack_catalog_transitions`, `saved_hunt_queries`, `ioc_indicators`, `ioc_enrichment_results` | ATT&CK active read model ذري، snapshots ثابتة مع SHA-256 وسجل انتقال/رجوع، IoC فريد ضمن workspace |
| الاستجابة | `playbooks`, `playbook_versions`, `playbook_steps`, `playbook_runs`, `playbook_step_runs`, `response_simulation_state` | run مرتبط بإصدار، idempotency key، حالة محاكاة فقط |
| القياس | `assessment_snapshots`, `security_audit_logs`, `outbox_events`, `schema_meta` | snapshot input/weights ثابت، audit redacted، schema version |

## الوقت

كل timestamp محفوظ ISO 8601 UTC من السيرفر. `event_time` يمثل وقت الملاحظة، و`ingested_at` وقت قبول المنصة. parser يرفض timestamp بلا timezone في API structured؛ Syslog legacy يعلن افتراض السنة الحالية وUTC داخل normalized metadata.

## العزل

تبدأ الاستعلامات بـ`workspace_id`. المستخدم ذو صلاحية الفريق يرى كل Training Runs داخل المساحة؛ Analyst يرى أحداثًا مشتركة غير مرتبطة بجلسة، إضافة إلى جلساته فقط. أي وصول مباشر إلى معرف خارج النطاق يرجع 404 لتقليل كشف وجود المورد.

## الترحيل

`ensure_schema` idempotent ولا يحذف قاعدة. يضيف الأعمدة والجداول والفهارس ثم يرحّل `incidents` القديمة مرة واحدة. `scripts/migrate.py --dry-run` ينسخ القاعدة ويفحص integrity وforeign keys ثم يطبق الترحيل على النسخة.
