# خطة الاختبار

## الطبقات

| الطبقة | الأدوات | النطاق |
|---|---|---|
| Unit | pytest + Hypothesis | time, DSL, normalization, parsers, password/TOTP, query compiler, scoring |
| Integration | Flask client + SQLite حقيقية | auth/RBAC/CSRF، ingest→detect→alert→case، migrations، backup |
| Security negative | pytest + Bandit + pip-audit | XSS/SQLi/SSRF/IDOR/upload/CSV/secret redaction/rate limit |
| E2E browser | Playwright Chromium | landing/login/nav/RTL/responsive/forms/network persistence |
| Operational | Docker + health + schema scripts | non-root image، persistent DB، backup/restore/readiness |
| Performance smoke | pytest marker | ingest/detection/query budgets على ملف مرجعي محلي |

## البيانات

Fixtures كلها اصطناعية وموسومة: CSV/JSON/JSONL/Syslog/Linux/Web/Sysmon XML وEVTX base64. لا بيانات إنتاج ولا credentials حقيقية. يحتفظ الاختبار بقاعدة مؤقتة لكل حالة من Template seeded مرة واحدة.

## معايير البوابات

- P0 = 100% pass.
- P1 ≥ 99% ولا رحلة حرجة حمراء.
- Critical/High security findings المفتوحة = 0.
- coverage statements ≥ 85% وbranches ≥ 75% للنسخة الحالية، مع رفع الهدف تدريجيًا إلى 90% للوحدات الحرجة.
- لا flaky retry؛ تكرار الاختبار الحتمي يعطي fingerprint نفسه.
- Performance يقاس p95 على GitHub runner ويخزن artifact؛ الهدف المرجعي API read p95 < 300ms محليًا وingest 1000 event < 10s.

## E2E-01..60

الأسماء نفسها مستخدمة كـmarkers أو test IDs داخل `tests/e2e/test_acceptance.py` و`tests/e2e/test_browser.py`. البنود التشغيلية التي تحتاج Docker/Codespaces منفصلة في CI ولا تُحوّل إلى pass عبر فحص نصي فقط. النتيجة الفعلية تنسخ إلى RTM وتقرير القبول بعد آخر HEAD.
