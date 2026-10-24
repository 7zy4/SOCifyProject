# بحث V3: من الأدلة إلى متطلبات SOCify Digital Autopsy

التاريخ: 2026-10-24. الحالة: بحث مرجعي وتأسيس مواصفة قبل تعديل التطبيق. النتيجة ليست اعتماد إصدار V3 أو اختبار تكامل مع منتجات الموردين.

## المنهج وحدود الوصول

جُرب الوصول إلى 18 صفحة توثيق رسمية، لكن وكيل الشبكة أعاد `Tunnel connection failed: 403 Forbidden`. استُخدمت بدلًا منها وثائق ومحتويات ومستودعات رسمية عامة متاحة عبر GitHub، مع تثبيت commits وبصمات الملفات. تفاصيل المحاولات الناجحة والفاشلة في [سجل المصادر](source-manifest.json).

شمل الفحص قائمة المالك العشر، ومراجع إضافية من Security Onion وDFIR-IRIS وMISP وSigma ومحتوى Microsoft Sentinel. لم يتاح المرجع الذي جُرب لـGoogle SecOps؛ لا يُنسب إليه سلوك غير متحقق. لم يُدخل حساب إلى خدمة تجارية ولم يُشغّل SIEM كامل أو منصة استجابة مورّد. لذلك المقارنة أدناه مقارنة لأنماط سير العمل الموثقة أو المشاهدة في المصدر، وليست شهادة تطابق كامل أو ترتيبًا لأفضل المنتجات عالميًا.

المصادر قُرئت كبيانات بحث؛ لم تُنفذ تعليمات المستودعات أو integrations أو نماذج API الخاصة بالموردين. لم تُرسل سجلات شركة أو عينات أو مؤشرات إليها، ولم تُستدعَ VirusTotal. لا توجد تبعية تشغيلية جديدة في SOCify نتيجة البحث.

## المنصات العشر وماذا تغير في المواصفة

| المنصة والمصدر الأولي | الملاحظة المثبتة وحدودها | قرار التصميم في V3 |
|---|---|---|
| [Timesketch](https://github.com/google/timesketch/blob/8f86c29f1fa86c5c0fb016f51fc76959f8e2ced6/docs/guides/user/basic-concepts.md)؛ دليل `sketch-overview.md` في الالتزام نفسه | sketch يجمع timelines، مع تعليقات ووسوم ومناظر وقصة تحقيق؛ التعليق مرتبط بسياق sketch وليس بكل نسخة timeline في كل تحقيق | القضية سياق التعاون؛ bookmarks وتعليقات ومناظر مشتركة وخط زمني وأحداث بدليل؛ لا تسرب تعليق إلى قضية أخرى تشترك في ملف |
| [TheHive](https://github.com/TheHive-Project/TheHive/blob/47072312bfc5fd56ae4892addbb140b6be833468/README.md) و[Cortex](https://github.com/TheHive-Project/Cortex)؛ الروابط الدقيقة المثبتة في manifest | القضايا والمهام والقوالب والتعاون والـobservables موثقة. فُحص أيضًا مصدر frontend أقدم مثبت عند `d390a0316ccd7780df6a49eccc773e5c28b43cc2` بأداة REA؛ لا يمثل أحدث منتج تجاري | قوالب قضية ومهام وObservable/IOC مترابط؛ محللات محلية فقط؛ نشر قالب لا يعدّل نسخة قضية قديمة؛ Cortex هنا مختلف عن XSOAR |
| [Autopsy: IngestModule](https://github.com/sleuthkit/autopsy/blob/cb3dacdcad67abe7cf863c74f10dcdb8e25a5c21/Core/src/org/sleuthkit/autopsy/ingest/IngestModule.java) | واجهة module بدورة بدء/معالجة/إيقاف وعزل instance لكل خيط بحسب عقد المصدر؛ ليست مجرد اسم «تشريح آلي» | وحدات إدخال بإصدارات وحدود وأخطاء ومراحل واضحة؛ لا تشغيل plugin يرفعه المحلل ولا مشاركة حالة غير مضبوطة بين المهام |
| [Splunk Security Content](https://github.com/splunk/security_content) | README يصف Analytic Stories وعمليات بحث وارتباط ATT&CK وPlaybooks وأدوات اختبار المحتوى؛ لا يثبت تشغيل Enterprise Security أو أداء SPL هنا | قواعد محلية بإصدارات واختبار، قرار وفرز قابلان للتفسير، وروابط تحليل/أدلة؛ لا ادعاء دعم SPL أو توافق ثنائي |
| [Elastic Timeline](https://github.com/elastic/docs-content/blob/01d5e64efb0141cc55076dd96c932f0f2d059b18/solutions/security/investigate/timeline.md) | workspace للتحقيق يجمع alerts/events، أعمدة وفلاتر وnotes وpin وحفظ وSave as new؛ دليل detection-rules يوضح محتوى كشف قابلًا للاختبار | مناظر زمنية محفوظة، فصل نسخة جديدة عن استبدال الأصل، وترقيم/فهرسة وقياس أداء؛ لا وعد «ملايين فورًا» بلا benchmark |
| [Velociraptor Artifacts](https://github.com/Velocidex/velociraptor-docs) | artifacts تجمع استعلامات VQL وparameters ووصفًا لتجميع أدلة محددة. هذه قدرة جمع أوسع من رفع ملفات SOCify | وصفات جمع وحزم أدلة داخلية مع الأداة والوقت والنطاق؛ جمع endpoint/VQL فعلي ليس قدرة موجودة ويحتاج توسعة مصرحًا بها |
| [Wazuh Decoders](https://github.com/wazuh/wazuh-documentation) | الوثيقة تفصل pre-decoding لاستخراج معلومات الرأس عن decoding للحقول قبل التحليل | مراحل parser وتطبيع واستخراج واضحة مع تشخيص أخطاء واختبارات، دون ادعاء Agent أو FIM أو ماسح ثغرات |
| [Cortex XSOAR Content](https://github.com/demisto/content) | محتوى رسمي لـPlaybooks وintegrations وقوالب تقارير؛ فُحص أيضًا GenericPolling YAML كعينة مهام/انتقالات ومخرجات. War Room التجارية لم تُجرب تفاعليًا | خطوات محلية بإصدارات وموافقات وأدلة نتائج؛ War Room تصميم مطلوب من المالك يدعم سجل القرارات، لا ادعاء إعادة إنشاء XSOAR أو تشغيل استجابة خارجية |
| [Graylog Pipeline/Stage](https://github.com/Graylog2/graylog2-server) | المصدر الحالي المثبت يعرّف stages مرتبة وruleReferences وMatch وعداد تنفيذ. مستودع plugin القديم يعلن أنه مدمج ومتقادم؛ لم يُعتمد كتوثيق للنسخة الحالية | Pipeline قابلة للملاحظة وإعادة المعالجة دون تعديل الأصل، بإصدارات ومقاييس وحدود، وعدم نقل DSL/كود خارجي مباشرة إلى التطبيق |
| [Rootly Terraform provider](https://github.com/rootlyhq/terraform-provider-rootly) | مصدر رسمي يصف workflow لإنشاء postmortem مرتبط بـincident وقالب، وخطوات retrospective بعناوين وأدوار ومواعيد. لم تُشغّل خدمة Rootly | مسودة Postmortem من بيانات القضية، مراجعة واعتماد، ثم إجراءات تصحيحية مستقلة بعد الإغلاق؛ لا اعتماد على Slack أو SaaS |

كل رابط مختصر إلى مستودع في الجدول يقابله URL ملف مثبت وcommit وبصمة في manifest. لا تُفسر خصائص هذه المصادر على أنها خصائص منفذة في SOCify.

## مراجع إضافية مؤثرة

- **Security Onion Cases:** تصف الوثائق title/description/assignee/status/severity/priority، ومكونات comments/attachments/observables/events/history. يدعم ذلك تنظيم القضية كسياق موحد بدل قائمة أدوات منفصلة.
- **DFIR-IRIS:** المصدر يصف تعاون فرق الاستجابة والتحقيق. لا يُدّعى تشغيل النسخة الثالثة أو تكاملها؛ الاستفادة نمط ربط مشاركة التفاصيل بالقضية.
- **MISP:** المصدر يوضح correlation وتصنيفات قابلة للتكييف. في V3 تستخدم حزم TI مستوردة ومحلية مع الثقة والعمر والمصدر، دون مشاركة خارجية.
- **Sigma:** مستودع قواعد ومرجع لصيغة قابلة للنقل، وليس ضمانًا أن backend محلي يفهم كل operator. وثيقة Timesketch نفسها تذكر قيود دعم Sigma ومخاطر تشغيل عدد كبير من القواعد. أُضيفت مصفوفة قدرات ورفض غير المدعوم وحصص تنفيذ.
- **Microsoft Sentinel content:** قواعد وصيد وworkbooks وPlaybooks كمحتوى قابل للمراجعة؛ لا يستخدم Azure لمعالجة بيانات المنتج المعزول.
- **VirusTotal vt-py:** المرجع الرسمي يوضح أن التكامل المعتاد API خارجي، لذلك **لم يُدمج ولم يُنفذ**. قرار المالك يحسم الاستيراد اليدوي فقط ويمنع إرسال hash أيضًا.

## الاستخدام الفعلي لـREA

أُعيد استخدام التثبيت المحلي العامل للمشروع الذي حدده المالك: `7zy4/rea` عند `2250e67bc271c83f9e200ee298aa04a2457438a6`، وإصدار الحزمة `rea-agents@6.7.0`. استُخدم CLI المحلي دون تغيير إعدادات العميل أو احتياج Hopper/Ghidra لأن الهدف JavaScript. أداة REA قرأت artifacts كنص ساكن ولم تشغل bundles أو أي samples.

| الهدف | الدليل | ما شمله التحليل | الحدود |
|---|---|---|---|
| واجهة SOCify الموروثة في V3 | `ev_dc938af8c5fda9d0283cb124eb941bc5c3ebd78c8afa3facceb042a10d9e2a55` | `static/app.js` و`templates/app.html` و`templates/register.html`؛ 83,379 بايت، ملف JS واحد، 11,624 عقدة AST، 27 graph nodes و29 edges | ثلاث ملفات فقط، ليست كل Python أو CSS أو APIs؛ 2,005 علاقات/حالات مجهولة في semantic graph |
| مقتطف frontend قديم من TheHive | `ev_a157ac9fc8f595234a45a4b357c334c6cdd88dd27c5149460634a4342a0c0457` | CaseCreation/CaseDetails/CaseTasks/CaseObservables، أربعة ملفات و43,074 بايت و4,747 عقدة AST | عينة مصدر مثبتة، ليست تشغيلًا ولا frontend تجاريًا حديثًا؛ 1,240 unknowns |
| bundle مبني موجود في مستودع Timesketch | `ev_5176e36e1d0b0e2259c5838de6cbb4f23932d420b75815e596d6977521625e4a` | `frontend-ng/dist/js/index.d93f0885.js` عند `8f86c29f1fa86c5c0fb016f51fc76959f8e2ced6`؛ 434,127 بايت و109,705 عقدة AST و19 modules، و106 graph nodes/127 edges | bundle frontend-ng وحده، ليس frontend-v3 ولا كل vendor chunks أو backend؛ 20,000 unknowns، فلا تغطية كاملة |

التحليلات الثلاثة أكملت parsing بلا parse failures أو integrity contradictions. هذه مؤشرات اكتمال التحليل الساكن المحدد فقط؛ ليست صفر ثغرات أو دليل صحة صلاحيات أو تكافؤ وظيفي. مخرجات REA نفسها تحتفظ بقيود العلاقات الديناميكية وعدم تنفيذ الكود. لم تُجرَ مقارنة تنفيذ تجاري حي بالمتصفح في هذه المرحلة.

الأدلة الكاملة المضغوطة وبصماتها وقائمة ملفات كل هدف متاحة في [manifest الأدلة](rea-evidence-manifest.json). تحفظ artifacts المصدرية خارج مستودع المنتج؛ لم يُنسخ كود الموردين إلى وظائف SOCify أو اعتماداته.

### إعادة التشغيل

مع وجود نسخة REA العاملـة مثبتة عند commit أعلاه:

```bash
SOCIFY_REA_CLI=/path/to/rea/scripts/rea.mjs bash scripts/run_rea_analysis.sh /tmp/socify-v3-rea.json
node /path/to/rea/scripts/rea.mjs analyze-javascript-application /tmp/thehive-selected-artifacts --json > /tmp/thehive-rea.json
node /path/to/rea/scripts/rea.mjs analyze-javascript-application /tmp/timesketch-selected-artifacts --json > /tmp/timesketch-rea.json
```

أعد بناء مجلدات الهدف من المسارات والـcommits وSHA-256 المسجلة في manifest. ملفات TheHive وضعت بأسمائها القصيرة في جذر هدفها، وكذلك bundle Timesketch؛ SOCify حافظ على مجلدي static/templates. الأهداف عينات مقصودة وليست تصديرًا كاملًا للتطبيقات. قد يختلف Evidence ID عند اختلاف بيئة/مسار التشغيل؛ قارن بصمات المدخلات ونطاق التحليل، لا الاسم فقط.

## التحسينات الناتجة التي تجاوزت قائمة المالك

1. **عزل مكان الاستضافة:** Codespaces للتطوير الاصطناعي فقط؛ وضع بيانات الشركة فيه يناقض شرط المعالجة داخل الشركة حتى دون أي API خارجي.
2. **سلسلة حيازة:** بصمة الملف وحدها لا توثق من جمعه ونقله واطلع عليه. أضيف سجل حيازة ومشتقات ومنقح وسياسة احتفاظ وlegal hold.
3. **حدود الاستنتاج:** Patient Zero هو أقدم دليل ضمن نطاق، وBlast Radius يفصل المؤكد عن المحتمل وغير المفحوص، وGeoIP ليس هوية المهاجم.
4. **ضجيج الكشف:** grouping قابل للفك، suppression مؤقتة مدققة، وrisk score بأسباب، لا حذف أدلة أو تحويل رقم إلى يقين.
5. **فصل الاستجابة الحقيقية:** تغيير حالة تدريب لا يعزل جهازًا. التوثيق هو الافتراضي، والتنفيذ الداخلي يحتاج موصلًا وموافقة واختبار أثر مستقلًا.
6. **الاستمرارية:** جرى رصد تبعيات `training_run_id` و`training_workspaces` قبل تقاعد التدريب، وحماية تقارير وأدلة V2 من إعادة الكتابة.
7. **اتساق التقارير:** PDF/DOCX/Markdown/HTML من نموذج واحد بإصدارات ومراجعة، دون محتوى نشط أو طلبات شبكة في محرك العرض.
8. **المقاييس:** تعريف نقاط زمن MTTD والاستجابة والاحتواء والاستعادة والإغلاق، وإظهار المجهول بدل اختراع قيم موجبة.

## ما بقي قبل الادعاء بجاهزية V3

تطبيق المتطلبات نفسها لم يبدأ ضمن هذه المرحلة. يلزم تحويل المواصفة إلى مصفوفة تنفيذ، migrations، تصميم سياق القضية، ثم الاختبارات الـ75 والأمن والعزل والأداء والتقارير والمراجعة البصرية. وثائق الموردين وREA لا تعوض هذه الخطوات. تفاصيل تحميل الشركة والأدوار وسياسة الاحتفاظ وبنية النشر تؤخذ عند بدء التنفيذ المعتمد عليها؛ لا تتطلب قرارًا جديدًا عن العزل الذي حسمه المالك بالفعل.
