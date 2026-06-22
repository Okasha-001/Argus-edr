# ARGUS Platform v2 — The XDR Leap (Master Plan)

> **النسخة:** 2.0 · **الحالة:** رؤية + خطة تنفيذ قابلة للشحن · **يكمل:** `docs/ROADMAP.md` (Phases 1–11 ✅)
>
> **الهدف:** نقل ARGUS من *أداة EDR كاملة لمضيف/أسطول صغير* إلى **منصة XDR/SOC مفتوحة المصدر
> بالكامل** — تتسع لآلاف المضيفين ومليارات الأحداث، بواجهة SOC عصرية بسيطة جداً، صيد تهديدات،
> أتمتة استجابة، ومحلّل ذكاء اصطناعي مستقل. **مجانية ومفتوحة المصدر 100%، بلا أي تكاليف خفية،
> وبلا أي إرسال بيانات للخارج (zero phone-home).**

---

## 0. لماذا هذه نقلة، وليست مجرد ميزات (The North Star)

ARGUS اليوم (v1) **أداة ممتازة**: مستشعرات eBPF، 57 قاعدة، ML، حماية ذاتية، control plane،
وواجهة بسيطة. لكنها لا تزال **أداة لمحلّل واحد على أسطول صغير**: التخزين SQLite، الواجهة 449
سطر vanilla JS، ولا يوجد صيد تهديدات ولا أتمتة استجابة ولا تحقيق بصري.

**الرؤية (v2):** ARGUS يصبح ما هو عليه *SOC حديث كامل*، لكن **مفتوح ومجاني ويُستضاف ذاتياً**:

```
        v1 (اليوم)                              v2 (هذه الخطة)
  ┌──────────────────────┐            ┌───────────────────────────────────────────┐
  │ agent → control plane │            │ آلاف الـ agents → بثّ → بحيرة بيانات         │
  │ SQLite store          │   ──────▶  │ صيد تهديدات + رسم بياني للهجوم + إدارة حالات │
  │ واجهة 449 سطر بسيطة    │            │ console عصري + SOAR + محلّل AI مستقل          │
  │ أداة لمحلّل واحد        │            │ منصّة فريق SOC كامل، cloud-native, FOSS       │
  └──────────────────────┘            └───────────────────────────────────────────┘
```

> **المعيار:** بعد v2، أي فريق أمن يقدر يستبدل أداة تجارية تكلّف عشرات آلاف الدولارات سنوياً
> بـ ARGUS مجاناً، يستضيفه على سيرفره، بدون أي بيانات تخرج لأي طرف ثالث، وبدون قيود ترخيص.

---

## 1. المبادئ الحاكمة (Non-negotiable principles)

هذه المبادئ **تعلو على كل ميزة**. أي PR يكسر واحداً منها يُرفض.

### 1.1 مجاني ومفتوح بالكامل — لا تكاليف خفية (FOSS-first)
- **كل شيء Apache-2.0** أو ترخيص متوافق. لا "نسخة enterprise" مدفوعة، لا ميزات محجوبة خلف
  جدار، لا "open core". كل قدرة في هذا الملف **مجانية للجميع**.
- **لا اعتماد على خدمة سحابية مدفوعة إلزامية.** كل مكوّن خارجي (قاعدة بيانات، صفّ رسائل،
  بحث) لازم يكون **له بديل مفتوح يُستضاف ذاتياً** يعمل افتراضياً.
- **تدقيق تراخيص في CI:** أي اعتمادية جديدة بترخيص غير متوافق (GPL متضارب، تجاري، AGPL في
  مكتبة مرتبطة) تُرفض آلياً. أداة: `go-licenses` / `trivy`.

### 1.2 خصوصية أولاً — صفر phone-home (Privacy-first)
- **ARGUS لا يرسل أي بيانات لأي خادم لا يملكه المستخدم. أبداً.** لا telemetry، لا "تحسين
  المنتج"، لا فحص تحديثات تلقائي يسرّب معلومات.
- **اختبار CI يثبت الصفر-اتصال:** تشغيل المنصّة في sandbox بلا شبكة خارجية ويتأكد أن لا
  اتصال صادر إلا لما يضبطه المستخدم صراحةً (مثل feed تهديدات اختياري أو LLM اختياري).
- **ميزة الـ LLM (Phase 18) تبقى opt-in بمفتاح صريح**، مع خيار **نموذج محلي بالكامل** (Ollama)
  حتى لا تخرج بيانات أبداً.

### 1.3 لا بيانات شخصية أو تسريب في الملفات (No personal data — hard gate)
> يوسّع Golden Rule 1 في `CLAUDE.md` ويجعله **بوّابة CI**.
- لا أسماء مستخدمين، مسارات منزلية، إيميلات، أسماء مضيفين حقيقية، IPs داخلية، أو مسارات
  مطلقة من جهاز مطوّر — في أي ملف يُرفع. أمثلة محايدة فقط: `web-01`, `/opt/argus`,
  `203.0.113.0/24` (TEST-NET), `github.com/argus-edr/argus`.
- **بوّابة CI جديدة** (`scripts/check-no-secrets.sh`): تفحص الـ diff بأنماط (إيميل، مفتاح
  خاص، مسار `/home/...` أو `C:\Users\...`، توكن) وتفشل البناء عند أي تطابق. أداة:
  `gitleaks` + سكربت أنماط مخصّص.

### 1.4 بساطة ونظافة — التصميم والكود (Simple & clean)
- **التصميم:** بسيط جداً، عصري، هادئ. مساحات بيضاء، تسلسل بصري واضح، لا فوضى، لا زخرفة.
  راجع *Design System* (قسم 3). القاعدة: *لو عنصر مش بيخدم قرار المحلّل، يتشال.*
- **الكود:** يتبع skills المشروع (`clean-code`, `go-style`, `ebpf-sensors`, `detection-rules`).
  دوال تفعل شيئاً واحداً، أسماء تكشف النية، أخطاء ملفوفة بسياق، لا أرقام سحرية.
- **اعتماديات قليلة في الـ core:** فلسفة `go.mod` الحالية (اعتماديات أقل ممكنة) تستمر في
  الـ agent والـ core. المكوّنات الثقيلة (بحيرة البيانات، البحث) تبقى **اختيارية وخلف واجهات**.

### 1.5 التوافق الخلفي والـ ABI المقدّس (Compatibility)
- الـ ABI (`bpf/common.h` ↔ `internal/decode/wire.go`) يظل عقداً واحداً بلغتين. كل تغيير
  متزامن في commit واحد مع `wire_test.go` و `WireSize`.
- المخطّط الخارجي للأحداث ينتقل إلى **معيار مفتوح (OCSF)** للتشغيل البيني — راجع Phase 12.

---

## 2. معمارية المنصّة v2 (Target Architecture)

```
                              ┌──────────────────────── ARGUS Platform v2 ───────────────────────────┐
  مضيفون (آلاف)                │                                                                       │
  ┌──────────┐   gRPC/mTLS    │   ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────┐ │
  │ agent eBPF│──────────────▶│──▶│  Ingest /     │──▶│  Stream bus   │──▶│  Data Lake (columnar)    │ │
  │ (Linux)  │   OCSF events  │   │  Gateway      │   │ (NATS/Redpanda│   │  (ClickHouse / DuckDB)   │ │
  └──────────┘                │   └──────────────┘   │  — self-host) │   └────────────┬─────────────┘ │
  ┌──────────┐                │          │           └───────────────┘                │               │
  │ agent ETW │───────────────│          ▼                                            ▼               │
  │ (Windows) │                │   ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────┐ │
  └──────────┘                │   │ Detection /   │   │ Hunting Query │   │  Investigation Graph     │ │
                              │   │ Correlation   │   │ Engine (ARQL) │   │  + Case Management       │ │
                              │   └──────┬────────┘   └───────┬───────┘   └────────────┬─────────────┘ │
                              │          │                    │                        │               │
                              │          ▼                    ▼                        ▼               │
                              │   ┌──────────────┐   ┌────────────────────────────────────────────┐   │
                              │   │ SOAR /        │   │   ARGUS Console (modern, minimal SOC UI)   │   │
                              │   │ Playbooks     │   │   + AI SOC Analyst (agentic, opt-in)       │   │
                              │   └──────────────┘   └────────────────────────────────────────────┘   │
                              │                                                                       │
                              │   كله يُستضاف ذاتياً · FOSS · zero phone-home · Kubernetes-native       │
                              └───────────────────────────────────────────────────────────────────────┘
```

**القاعدة المعمارية:** كل مكوّن ثقيل خلف **واجهة Go** مع تطبيق افتراضي خفيف يعمل بلا
بنية تحتية (single-binary mode)، وتطبيق قابل للتوسّع للإنتاج. يعني المنصّة تشتغل على لابتوب
واحد (تجربة/تطوير) **و** على عنقود Kubernetes (إنتاج) بنفس الكود.

---

## 3. نظام التصميم (Design System) — عصري · بسيط جداً · نظيف

> هذا أهم قسم لطلبك "تصميم احترافي وعصري وسيمبل جداً". الـ console الحالي (449 سطر vanilla)
> يُعاد بناؤه على نظام تصميم حقيقي. **الفلسفة: هدوء، وضوح، كثافة معلومات بلا فوضى** — جمالية
> SOC احترافية أقرب لأدوات مثل Linear / Grafana / Datadog لكن أبسط.

### 3.1 المبادئ البصرية
- **Dark-first**، بخلفية شبه سوداء هادئة (ليست سوداء صريحة)، لتقليل إجهاد العين في غرفة SOC.
  مع وضع فاتح متاح.
- **لون أساسي محايد + لون تمييز واحد** فقط (cyan/teal مثلاً) للإجراءات والروابط الحيّة.
  الخطورة بألوان دلالية مقيّدة (critical/high/medium/low/info) — لا قوس قزح.
- **مساحات بيضاء سخيّة** و**شبكة 8px**. لا حدود ثقيلة؛ الفصل بالمساحة والظل الخفيف.
- **خط أحادي (mono)** للبيانات التقنية (PIDs, hashes, IPs, أوامر)، وخط sans هندسي نظيف
  للواجهة (Inter / Geist — كلها مفتوحة ومستضافة ذاتياً، لا CDN خارجي).
- **مدفوع بلوحة المفاتيح:** كل إجراء له اختصار، وpalette أوامر (Cmd/Ctrl+K) للتنقل والصيد.
- **إمكانية الوصول (a11y):** تباين WCAG AA، تركيز واضح، قارئ شاشة، حركة مخفّضة محترمة.

### 3.2 رموز التصميم (Design tokens — أمثلة محايدة)
```css
/* ألوان (CSS variables، dark-first) */
--bg:        #0b0e14;   --surface: #121722;   --surface-2: #1a2130;
--text:      #e6e9ef;   --muted:   #8b94a7;   --border:    #232b3a;
--accent:    #2dd4bf;   /* لون تمييز واحد */
--sev-critical:#f43f5e; --sev-high:#fb923c; --sev-medium:#fbbf24;
--sev-low:   #38bdf8;   --sev-info:#64748b;
/* تباعد: شبكة 8px */  --s-1:4px; --s-2:8px; --s-3:12px; --s-4:16px; --s-6:24px; --s-8:32px;
/* أنصاف أقطار */      --r-1:6px; --r-2:10px; --r-3:14px;
/* الخطوط */           --font-sans:'Inter',system-ui;  --font-mono:'JetBrains Mono',monospace;
```

### 3.3 المكدّس التقني للواجهة (Frontend stack — كله FOSS)
- **React + TypeScript + Vite** (أو SvelteKit — اختيار واحد، يبقى بسيطاً).
- **Tailwind CSS** + مكوّنات headless على نمط **shadcn/ui** (كلها MIT، تُنسخ داخل الريبو،
  بلا اعتماد runtime ثقيل).
- **رسوم بيانية:** مكتبة خفيفة مفتوحة (uPlot للسلاسل الزمنية — سريعة جداً وصغيرة).
- **رسم بياني للهجوم (graph):** Cytoscape.js أو d3-force (مفتوحة).
- **بلا أي CDN خارجي:** كل الأصول (خطوط، سكربتات) تُبنى وتُضمّن عبر `go:embed` في
  `argus-server` — يخدم نفسه، يتسق مع *zero phone-home*.

### 3.4 مكتبة المكوّنات الأساسية (تُبنى مرة وتُعاد)
`Button`, `Badge` (للخطورة/ATT&CK), `Card`, `Table` (افتراضية مع فرز/تصفية افتراضية),
`Drawer` (تفاصيل الحدث/التنبيه), `Timeline`, `GraphCanvas`, `CommandPalette`, `QueryBar`,
`StatTile`, `SeverityDot`, `Toast`, `EmptyState`, `KeyboardHint`.

### 3.5 الشاشات الأساسية (Information architecture)
| الشاشة | الغرض | البساطة |
|--------|-------|---------|
| **Overview** | صحة الأسطول + أحدث الحوادث + اتجاه التنبيهات | بطاقات قليلة كبيرة، رقم واحد مهم لكل بطاقة |
| **Alerts** | خلاصة حيّة + فرز/تصفية + triage سريع | جدول كثيف، drawer للتفاصيل، لا تنقّل صفحات |
| **Hunt** | صيد تفاعلي بلغة ARQL (Phase 14) | شريط استعلام واحد + نتائج + حفظ |
| **Investigation** | رسم بياني للهجوم + timeline + حالة (Phase 15) | لوحة واحدة، تكبير/تصغير، بلا حشو |
| **Detections** | كتالوج القواعد + تغطية ATT&CK + اختبار (Phase 16) | مصفوفة Navigator + بحث |
| **Automation** | playbooks SOAR (Phase 17) | محرّر تدفّق بسيط |
| **Fleet** | المضيفون + صحّتهم + سياساتهم | جدول + صحة |
| **Settings** | المستخدمون/RBAC/التكاملات/المفاتيح | نماذج بسيطة |

**Acceptance criteria للتصميم (Definition of beautiful & simple).**
- كل شاشة تجاوب على الأسئلة المهمّة **بدون scroll أفقي وبأقل من 3 نقرات**.
- لا شاشة فيها أكثر من **لون تمييز واحد** + ألوان الخطورة الدلالية.
- palette الأوامر (Cmd/Ctrl+K) تصل لأي شاشة/إجراء.
- اختبار Lighthouse: a11y ≥ 95، أداء ≥ 90.
- لا أصول من شبكة خارجية (تأكيد عبر فحص الشبكة).

---

## 4. مراحل التنفيذ (Phases 12–21)

> ترقيم يكمل `ROADMAP.md`. كل مرحلة: What/Why · المكوّنات · الملفات · أثر ABI · Acceptance · Agent prompt.

---

### Phase 12 — البثّ وبحيرة البيانات (Streaming & Data Lake) — *أساس الـ 100x*

**What / Why.** هذا حجر الأساس للمقياس. اليوم كل شيء SQLite على عقدة واحدة. للوصول لآلاف
المضيفين ومليارات الأحداث القابلة للبحث، نحتاج خطّ بثّ + مخزن عمودي.

**المكوّنات.**
- **مخطّط مفتوح OCSF:** انقل تمثيل الحدث الخارجي إلى [OCSF](https://schema.ocsf.io)
  (Open Cybersecurity Schema Framework) — معيار صناعي مفتوح، يجعل ARGUS قابلاً للتشغيل
  البيني فوراً. `internal/model` يكتسب projection لـ OCSF بجانب ECS الحالي.
- **ناقل بثّ ذاتي الاستضافة:** واجهة `EventBus` مع تطبيقين: `inproc` (افتراضي، single-binary)
  و**NATS JetStream** (إنتاج، FOSS، خفيف). لا Kafka إلزامي.
- **بحيرة بيانات عمودية:** واجهة `EventStore` مع تطبيقين: `sqlite` (موجود) و**ClickHouse**
  أو **DuckDB** (إنتاج) — كلاهما FOSS ويُستضاف ذاتياً، يخزّن مليارات الصفوف ويبحث في ثوانٍ.
- **استبقاء + تقسيم زمني (retention/partitioning)** قابل للضبط.

**الملفات.** `internal/model/ocsf.go` (جديد)، `internal/bus/*` (جديد، واجهة + inproc + nats)،
`internal/eventstore/*` (جديد، واجهة + clickhouse/duckdb)، `server/api/*` (ingest)،
`internal/config`، `docs/DATA_LAKE.md` (جديد), `deploy/` (compose لـ nats+clickhouse).

**ABI impact.** لا (OCSF projection في userspace؛ wire ABI كما هو).

**Acceptance.**
- وضع single-binary يعمل بلا nats/clickhouse (inproc + sqlite).
- وضع الإنتاج يستوعب ≥ 100k حدث/ثانية في اختبار حِمل ويبحث في < 2s على مليار صف.
- مخرجات OCSF صالحة مقابل مخطّط OCSF الرسمي (اختبار تحقّق).
- `make fmt vet lint test` خضرا.

**Agent prompt.**
```
أضف طبقة مقياس FOSS قابلة للاستضافة الذاتية. (1) internal/model/ocsf.go: projection لمعيار
OCSF بجانب ECS الحالي، مع اختبار تحقّق ضد المخطّط. (2) internal/bus: واجهة EventBus مع تطبيق
inproc افتراضي و NATS JetStream للإنتاج. (3) internal/eventstore: واجهة EventStore مع sqlite
(موجود) و ClickHouse/DuckDB للإنتاج، مع retention وتقسيم زمني. أبقِ وضع single-binary يعمل
بلا أي بنية تحتية. أضف compose في deploy/ و docs/DATA_LAKE.md. لا تمسّ wire ABI. اختبر الحِمل
والبحث على VM لينكس. خلّي الشجرة خضرا واتبع clean-code/go-style.
```

---

### Phase 13 — إعادة بناء الـ Console على نظام التصميم (Modern SOC Console)

**What / Why.** ينفّذ قسم *Design System* (قسم 3). الواجهة الحالية بسيطة جداً؛ نبنيها console
احترافي عصري نظيف — أكبر قفزة مرئية في v2.

**المكوّنات.** كل ما في قسم 3: نظام تصميم (tokens + مكتبة مكوّنات) + الشاشات الثماني +
palette الأوامر + a11y + بثّ حيّ. تُبنى وتُضمّن عبر `go:embed` (لا CDN، تتسق مع zero phone-home).

**الملفات.** `ui/` (إعادة بناء كاملة: مشروع React/Vite/TS/Tailwind)، `ui/embed.go`،
`cmd/argus-server/admin.go` (نقاط REST + SSE/WebSocket للبثّ)، `Makefile` (`make ui`)،
`.github/workflows/ci.yml` (بناء + Lighthouse + فحص لا-شبكة-خارجية)، `docs/CONSOLE.md` (جديد).

**ABI impact.** لا.

**Acceptance.** كل Acceptance في قسم 3.5 + الشاشات تستهلك بحيرة بيانات Phase 12 + بثّ حيّ يعمل.

**Agent prompt.**
```
أعد بناء ui/ كـ console احترافي عصري بسيط جداً على نظام التصميم في docs/PLATFORM_V2_MASTER_PLAN.md
قسم 3: React + TypeScript + Vite + Tailwind + مكوّنات headless (shadcn-style، منسوخة داخل الريبو).
نفّذ design tokens (dark-first، لون تمييز واحد، شبكة 8px، خط mono للبيانات)، مكتبة المكوّنات
الأساسية، الشاشات الثماني (Overview/Alerts/Hunt/Investigation/Detections/Automation/Fleet/Settings)،
palette أوامر Cmd/Ctrl+K، وبثّ حيّ عبر SSE. كل الأصول مضمّنة go:embed بلا CDN خارجي. أضف make ui
وفحوص Lighthouse (a11y≥95) ولا-شبكة-خارجية في CI. وثّق في docs/CONSOLE.md. خلّي الشجرة خضرا.
```

---

### Phase 14 — محرّك صيد التهديدات (Threat Hunting — ARQL)

**What / Why.** يحوّل ARGUS من "ينبّهك على المعروف" إلى "تقدر تدوّر بنفسك على المجهول".
لغة استعلام بسيطة قوية فوق بحيرة البيانات.

**المكوّنات.**
- **ARQL** (ARgus Query Language): لغة صيد بسيطة مقروءة، مستوحاة من KQL/EQL لكن أبسط، تُترجم
  إلى استعلام `EventStore`. مثال: `process where name in ("bash","sh") and parent.name == "nginx" | sequence by host within 5m`.
- محرّك تنفيذ + `sequence`/`join` زمني للصيد عبر الأحداث.
- **صيد محفوظ** يتحوّل لقاعدة كشف بنقرة (يغذّي Phase 16)، وصيد مجدول.
- شريط استعلام في شاشة Hunt مع إكمال تلقائي للحقول من `fields.go`.

**الملفات.** `internal/hunt/*` (lexer/parser/planner/executor، جديد)، `server/api` (نقطة
استعلام)، `ui/` (شاشة Hunt)، `docs/HUNTING.md` (جديد)، اختبارات وفيكسترات.

**ABI impact.** لا.

**Acceptance.** استعلامات ARQL ترجع نتائج صحيحة على فيكسترات؛ `sequence` يكتشف سلسلة الهجوم؛
تحويل صيد لقاعدة يعمل؛ أخطاء نحوية رسائلها واضحة. تغطية اختبار للـ parser (+ fuzz).

**Agent prompt.**
```
أضف محرّك صيد تهديدات. صمّم ARQL: لغة استعلام بسيطة مقروءة فوق internal/eventstore، تدعم
الترشيح بحقول fields.go والتسلسل الزمني (sequence/join within N). نفّذها في internal/hunt
(lexer→parser→planner→executor) مع رسائل خطأ واضحة و fuzz للـ parser. أضف نقطة استعلام في
server/api وشاشة Hunt في ui/ مع إكمال تلقائي وحفظ الصيد وتحويله لقاعدة كشف. وثّق ARQL في
docs/HUNTING.md مع أمثلة. اختبر على فيكسترات سلاسل هجوم. خلّي الشجرة خضرا واتبع go-style.
```

---

### Phase 15 — التحقيق: رسم الهجوم + إدارة الحالات (Investigation & Case Mgmt)

**What / Why.** عند وقوع حادثة، المحلّل يحتاج يفهم القصّة كاملة بصرياً ويديرها. نبني إعادة
بناء بياني للهجوم + timeline جنائي + نظام حالات (cases).

**المكوّنات.**
- **رسم بياني للهجوم (attack graph):** من شجرة العملية + الأحداث المرتبطة، نبني رسماً
  (عُقد = عمليات/ملفات/اتصالات؛ حواف = علاقات سببية) قابل للتكبير/التصفية، مع ربط ATT&CK.
- **timeline جنائي** قابل للتمرير عبر الزمن.
- **نظام حالات (cases):** تجميع تنبيهات في حالة، إسناد، حالة (open/triage/closed)، تعليقات،
  دلائل، تصدير تقرير (يعيد استخدام `internal/triage` للسرد).
- لقطة سياق (context snapshot) قابلة للمشاركة بلا بيانات حسّاسة.

**الملفات.** `server/investigate/*` (جديد: بناء الرسم البياني)، `server/cases/*` (جديد +
تخزين في `eventstore`)، `ui/` (شاشة Investigation)، `internal/triage` (تكامل التقرير)،
`docs/INVESTIGATION.md` (جديد).

**ABI impact.** لا.

**Acceptance.** حادثة `killchain` تُرسم كرسم بياني صحيح مربوط بـ ATT&CK؛ إنشاء حالة وإسنادها
وإغلاقها وتصدير تقريرها يعمل؛ كل ذلك بلا أي بيانات شخصية في المخرجات.

**Agent prompt.**
```
أضف التحقيق وإدارة الحالات. server/investigate: يبني رسماً بيانياً للهجوم من شجرة العملية
والأحداث المرتبطة (عُقد عمليات/ملفات/شبكة، حواف سببية، ربط ATT&CK). server/cases: نظام حالات
(إنشاء/إسناد/حالة/تعليقات/أدلة/تصدير تقرير) مخزّن في eventstore، يعيد استخدام internal/triage
للسرد. أضف شاشة Investigation في ui/ (رسم بياني تفاعلي + timeline جنائي). وثّق في
docs/INVESTIGATION.md. تأكد أن المخرجات بلا بيانات شخصية. اختبر على حادثة killchain. خلّي
الشجرة خضرا.
```

---

### Phase 16 — الكشف ككود + منظومة القواعد (Detection-as-Code Ecosystem)

**What / Why.** يرفع الكشف لمستوى منظومة: حزم قواعد، إطار اختبار، تغطية ATT&CK مرئية، ودعم
Sigma كامل — كله مفتوح ومجاني للمجتمع.

**المكوّنات.**
- **حزم قواعد (rule packs)** قابلة للإصدار والمشاركة، مع تواقيع تحقّق.
- **إطار اختبار الكشف:** كل قاعدة معها فيكستر "should-fire" و"should-not-fire"؛ `make test-rules`
  يشغّلها عبر `replay` ويقيس **معدّل الإيجابيات الكاذبة**.
- **ATT&CK Navigator** مدمج في شاشة Detections (مصفوفة التغطية الحيّة).
- **Sigma كامل** (يكمل `internal/sigma`): تغطية أوسع للمحوّلات والشروط.
- **استيراد/تصدير** قواعد من/إلى مستودعات المجتمع.

**الملفات.** `rules/packs/*` (جديد)، `internal/detect/test_harness.go` (جديد)،
`internal/sigma` (توسعة)، `ui/` (Detections + Navigator)، `docs/DETECTION_AS_CODE.md` (جديد)،
`Makefile` (`make test-rules`).

**ABI impact.** لا.

**Acceptance.** `make test-rules` يثبت كل قاعدة تطلق على should-fire ولا تطلق على should-not-fire؛
مصفوفة Navigator حيّة وصحيحة؛ استيراد حزمة Sigma كبيرة ينجح بنسبة تغطية موثّقة.

**Agent prompt.**
```
حوّل الكشف لمنظومة كود. أضف حزم قواعد قابلة للإصدار والتوقيع في rules/packs. أضف إطار اختبار
internal/detect/test_harness.go وهدف make test-rules: لكل قاعدة فيكستر should-fire و
should-not-fire عبر replay مع قياس الإيجابيات الكاذبة. وسّع internal/sigma لتغطية أكبر. ادمج
ATT&CK Navigator (مصفوفة تغطية حيّة) في شاشة Detections بـ ui/. وثّق في docs/DETECTION_AS_CODE.md.
خلّي الشجرة خضرا واتبع skill detection-rules.
```

---

### Phase 17 — أتمتة الاستجابة (SOAR / Playbooks)

**What / Why.** يربط الكشف بالفعل آلياً. عند تطابق شرط، يشغّل ARGUS playbook استجابة — كله
محلي، آمن، خلف نموذج `off → dry-run → enforce`.

**المكوّنات.**
- **محرّك playbook** بسيط: trigger (قاعدة/درجة/تقنية) → شروط → خطوات (عزل، قتل، حظر، إشعار،
  فتح حالة، تشغيل صيد).
- **تكاملات إشعار FOSS-friendly:** webhook عام، Slack/Mattermost، email/SMTP، syslog —
  كلها اختيارية ولا واحدة منها إلزامي أو مدفوع.
- **محرّر تدفّق بسيط** في شاشة Automation (لا-كود)، مع dry-run إجباري قبل التفعيل.
- يحترم الـ allowlist والـ kill switch وكل ضمانات `docs/SAFETY.md`.

**الملفات.** `server/soar/*` (جديد: محرّك + خطوات)، `internal/respond` (تكامل الأفعال)،
`internal/integrations/*` (جديد: webhook/slack/smtp/syslog)، `ui/` (Automation)،
`docs/SOAR.md` (جديد).

**ABI impact.** لا.

**Acceptance.** playbook على حادثة `killchain` يشغّل خطواته في dry-run ويُسجّلها؛ التفعيل يحترم
`response.mode`؛ كل تكامل اختياري ويعمل بلا اعتماد على خدمة مدفوعة.

**Agent prompt.**
```
أضف أتمتة استجابة (SOAR). server/soar: محرّك playbook (trigger→شروط→خطوات: عزل/قتل/حظر/إشعار/
فتح حالة/تشغيل صيد) يحترم off→dry-run→enforce والـ allowlist و kill switch. internal/integrations:
تكاملات FOSS اختيارية (webhook عام، Slack/Mattermost، SMTP، syslog) لا واحدة إلزامية. أضف محرّر
تدفّق بسيط في شاشة Automation بـ ui/ مع dry-run إجباري. وثّق في docs/SOAR.md. اختبر playbook على
killchain في dry-run. خلّي الشجرة خضرا، واحترم docs/SAFETY.md.
```

---

### Phase 18 — محلّل SOC الذكي المستقل (Autonomous AI SOC Analyst) ⭐

**What / Why.** يبني على `internal/triage` الموجود ويحوّله من "ملخّص" إلى **محلّل يحقّق**:
وكيل يأخذ تنبيهاً، يطرح أسئلة صيد (ARQL)، يجمع السياق، يبني فرضية، ويوصي بقرار — كله opt-in
ومع **خيار نموذج محلي بالكامل** حفاظاً على zero phone-home.

**المكوّنات.**
- **حلقة وكيل (agent loop):** أدوات = استعلام ARQL، جلب رسم الهجوم، بحث IOC، فتح حالة. الوكيل
  يخطّط ويستدعي الأدوات ويكتب سرد التحقيق + درجة ثقة + توصية.
- **مزوّدان للنموذج:** Claude API (موجود، opt-in بمفتاح) **و Ollama محلي** (zero phone-home).
  واجهة `Reasoner` تجرّدهما.
- **حواجز أمان:** الوكيل **لا ينفّذ استجابة بنفسه** — يوصي فقط؛ التنفيذ يمر بـ SOAR + موافقة.
  كل استدعاء أداة مُسجّل (audit).
- يعرض خط تفكيره في شاشة Investigation.

**الملفات.** `internal/aiagent/*` (جديد: حلقة + أدوات + reasoner interface)،
`internal/triage` (إعادة استخدام)، `internal/llm/{claude,ollama}.go`، `ui/` (لوحة المحلّل)،
`docs/AI_ANALYST.md` (جديد).

**ABI impact.** لا.

**Acceptance.** على حادثة `killchain`: الوكيل يصدر سرداً متماسكاً + توصية بلا أي تنفيذ تلقائي؛
وضع Ollama المحلي يعمل بلا أي اتصال خارجي؛ الميزة مطفأة افتراضياً.

**Agent prompt.**
```
حوّل internal/triage لمحلّل SOC مستقل في internal/aiagent: حلقة وكيل بأدوات (استعلام ARQL،
رسم الهجوم، بحث IOC، فتح حالة) يخطّط ويحقّق ويكتب سرداً + درجة ثقة + توصية، بدون تنفيذ أي
استجابة بنفسه (يوصي فقط، التنفيذ عبر SOAR بموافقة). جرّد النموذج خلف واجهة Reasoner بتطبيقين:
Claude API (opt-in بمفتاح) و Ollama محلي (zero phone-home). سجّل كل استدعاء أداة. اعرض خط
التفكير في شاشة Investigation. الميزة مطفأة افتراضياً. وثّق في docs/AI_ANALYST.md. راجع skill
claude-api لمعرّفات النماذج. اختبر على killchain. خلّي الشجرة خضرا.
```

---

### Phase 19 — Cloud-native / Kubernetes

**What / Why.** ينقل ARGUS لبيئات الحاويات الحديثة — حيث تعيش معظم أعباء العمل اليوم.

**المكوّنات.**
- **DaemonSet** ينشر الـ agent على كل عقدة، مع امتيازات eBPF المضبوطة بدقّة.
- **Operator (CRD):** `ArgusPolicy`, `ArgusRulePack`, `ArgusCluster` — إدارة تصريحية.
- **إثراء Kubernetes:** ربط كل حدث بالـ pod/namespace/workload/labels (من الـ cgroup id الموجود).
- **Helm chart** كامل للمنصّة (server + nats + clickhouse + console) — استضافة ذاتية بأمر واحد.
- (اختياري) **admission/runtime policy** على نمط Tetragon.

**الملفات.** `deploy/helm/*` (توسعة)، `deploy/k8s/*` (DaemonSet/RBAC)، `operator/*` (جديد)،
`internal/enrich/k8s.go` (جديد)، `docs/KUBERNETES.md` (جديد).

**ABI impact.** لا (الإثراء userspace).

**Acceptance.** `helm install` يقيم المنصّة كاملة على عنقود اختبار (kind/minikube)؛ الأحداث
مُثراة بسياق k8s؛ الـ operator يطبّق سياسة عبر CRD.

**Agent prompt.**
```
اجعل ARGUS cloud-native. أضف DaemonSet و RBAC في deploy/k8s مع امتيازات eBPF مضبوطة، Helm
chart كامل للمنصّة (agent+server+nats+clickhouse+console) في deploy/helm، و operator بـ CRDs
(ArgusPolicy/ArgusRulePack/ArgusCluster). أضف internal/enrich/k8s.go يربط الأحداث بـ
pod/namespace/workload/labels من cgroup id. وثّق في docs/KUBERNETES.md. اختبر على kind/minikube.
لا تمسّ ABI. خلّي الشجرة خضرا.
```

---

### Phase 20 — منظومة مفتوحة وتكاملات (Open Ecosystem & API)

**What / Why.** يجعل ARGUS نقطة في منظومة مفتوحة، لا جزيرة — قابل للتوسعة من المجتمع.

**المكوّنات.**
- **OpenTelemetry / OCSF export:** تصدير الأحداث/التنبيهات لأي SIEM أو data lake مفتوح.
- **API عامة موثّقة (OpenAPI)** + **SDKs** (Go أولاً، ثم Python) لبناء أدوات فوق ARGUS.
- **نظام إضافات (plugins):** واجهة `Sink`/`Source`/`Reasoner` تسمح بإضافات خارجية بلا تعديل
  الـ core.
- **مستودع محتوى مجتمعي** لحزم القواعد و playbooks و dashboards.

**الملفات.** `internal/output` (OTel/OCSF sinks)، `api/openapi.yaml` (جديد)، `sdk/*` (جديد)،
`docs/API.md` + `docs/PLUGINS.md` (جديد).

**ABI impact.** لا.

**Acceptance.** تصدير OTel/OCSF صالح يُستهلك بأداة طرف ثالث مفتوحة؛ SDK Go ينفّذ سيناريو
end-to-end؛ إضافة sink خارجية تعمل بلا تعديل الـ core.

**Agent prompt.**
```
افتح المنظومة. أضف sinks لـ OpenTelemetry و OCSF في internal/output. وثّق API عامة بـ
api/openapi.yaml وولّد SDK Go (ثم Python) في sdk/. عرّف نظام إضافات عبر واجهات Sink/Source/
Reasoner تسمح بإضافات خارجية بلا تعديل الـ core. وثّق في docs/API.md و docs/PLUGINS.md. اختبر
التصدير ضد أداة مفتوحة. خلّي الشجرة خضرا واتبع go-style.
```

---

### Phase 21 — ميثاق FOSS والخصوصية وبوّابات النظافة (Governance Gates)

**What / Why.** يحوّل المبادئ (قسم 1) إلى **بوّابات CI تلقائية** لا يمكن تجاوزها — ضمان دائم
أن المنصّة تبقى مجانية، خاصّة، ونظيفة.

**المكوّنات.**
- **بوّابة لا-بيانات-شخصية:** `scripts/check-no-secrets.sh` (gitleaks + أنماط مخصّصة لمسارات
  `/home`/`C:\Users`، إيميلات، مفاتيح) تفشل CI عند أي تطابق.
- **بوّابة الترخيص:** `go-licenses` + فحص اعتماديات الواجهة — أي ترخيص غير متوافق يفشل CI.
- **بوّابة zero-phone-home:** اختبار تكامل يشغّل المنصّة في sandbox بلا منفذ خارجي ويتأكد من
  عدم وجود اتصال صادر غير مُعلن.
- **بناء قابل للتكرار (reproducible builds)** + **SBOM موقّع** (يكمل Phase 10).
- **CONTRIBUTING/SECURITY/CODE_OF_CONDUCT** + قالب PR يتضمّن checklist المبادئ.

**الملفات.** `scripts/check-no-secrets.sh`, `scripts/check-licenses.sh`,
`test/integration/no_phone_home_test.go` (جديد)، `.github/workflows/ci.yml`,
`.github/PULL_REQUEST_TEMPLATE.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
`docs/GOVERNANCE.md` (جديد).

**ABI impact.** لا.

**Acceptance.** كل بوّابة تفشل عمداً على مدخل مخالف وتنجح على نظيف؛ اختبار zero-phone-home
أخضر؛ SBOM يُولّد ويُوقّع لكل release.

**Agent prompt.**
```
حوّل مبادئ المنصّة لبوّابات CI. أضف scripts/check-no-secrets.sh (gitleaks + أنماط مسارات
/home و C:\Users وإيميلات ومفاتيح) و scripts/check-licenses.sh (go-licenses + فحص اعتماديات
الواجهة) واجعلهما يفشلان CI عند المخالفة. أضف test/integration/no_phone_home_test.go يشغّل
المنصّة بلا منفذ خارجي ويتأكد من صفر اتصال صادر غير مُعلن. فعّل reproducible builds و SBOM
موقّع. أضف SECURITY.md و CODE_OF_CONDUCT.md وقالب PR فيه checklist المبادئ، ووثّق في
docs/GOVERNANCE.md. خلّي الشجرة خضرا.
```

---

## 5. المعالم وترتيب التنفيذ (Milestones)

> الترتيب يبني الأساس أولاً ثم الطبقات المرئية ثم الذكاء ثم الحوكمة.

| Milestone | المراحل | المحصّلة |
|-----------|---------|----------|
| **M1 — الأساس القابل للتوسّع** | 12 | بثّ + بحيرة بيانات + OCSF. الـ 100x ممكن. |
| **M2 — التجربة العصرية** | 13, 14 | console احترافي + صيد تهديدات. القفزة المرئية. |
| **M3 — التحقيق والكشف** | 15, 16 | رسم الهجوم + حالات + كشف-ككود. عمق المحلّل. |
| **M4 — الأتمتة والذكاء** | 17, 18 | SOAR + محلّل AI مستقل. التمييز. |
| **M5 — السحابة والمنظومة** | 19, 20 | Kubernetes + API + إضافات. الانتشار. |
| **M6 — الحوكمة الدائمة** | 21 | بوّابات FOSS/خصوصية/نظافة. الضمان. |

**تعريف "تمّ" لكل مرحلة:**
- [ ] يتبع skills المشروع (`clean-code`, `go-style`, `ebpf-sensors`, `detection-rules`).
- [ ] `make fmt vet lint test` خضرا (+ `replay`/`bench`/`fuzz`/`test-rules` حيث ينطبق).
- [ ] اختبارات تغطّي الحدود؛ التوثيق محدّث في `docs/`.
- [ ] **المبادئ الخمسة محفوظة** (FOSS · zero phone-home · لا بيانات شخصية · بساطة/نظافة · ABI).
- [ ] وضع single-binary لا يزال يعمل بلا أي بنية تحتية (كل ثقيل اختياري خلف واجهة).
- [ ] الافتراضيات الآمنة محفوظة (`response.mode: off`, `fleet.enabled: false`, AI/feeds opt-in).

---

## 6. المخاطر وكيف نتجنّبها (Risks)

| الخطر | التخفيف |
|-------|---------|
| التعقيد يقتل البساطة | كل ثقيل خلف واجهة + وضع single-binary افتراضي؛ قاعدة التصميم "احذف لو لا يخدم قرار" |
| اعتماد على مكوّن مدفوع/مغلق | المبدأ 1.1 + بوّابة ترخيص CI (Phase 21) |
| تسريب بيانات للخارج | المبدأ 1.2 + اختبار zero-phone-home + خيار LLM محلي (Ollama) |
| بيانات شخصية في الريبو | المبدأ 1.3 + بوّابة check-no-secrets في CI |
| انحدار الأداء مع المقياس | `make bench` + اختبار حِمل 100k/s + عدّادات Prometheus الموجودة |
| الوكيل الذكي ينفّذ إجراءً خاطئاً | الوكيل يوصي فقط؛ التنفيذ عبر SOAR بموافقة و dry-run إجباري |
| كسر الـ ABI | المبدأ 1.5: تغيير متزامن `common.h` ↔ `wire.go` ↔ `wire_test.go` |

---

## 7. خلاصة الرؤية (One-paragraph pitch)

> **ARGUS v2** منصّة XDR/SOC مفتوحة المصدر بالكامل، تُستضاف ذاتياً، وتنافس الأدوات التجارية
> التي تكلّف عشرات آلاف الدولارات — *مجاناً، بلا تكاليف خفية، وبلا إرسال أي بيانة للخارج*.
> مستشعرات eBPF على آلاف المضيفين تتدفّق عبر بثّ قابل للتوسّع إلى بحيرة بيانات تُبحث في ثوانٍ؛
> محلّلون يصطادون التهديدات بلغة ARQL بسيطة، يحقّقون عبر رسم بياني تفاعلي للهجوم، ويؤتمتون
> الاستجابة بـ playbooks آمنة؛ ومحلّل ذكاء اصطناعي مستقل (محلي أو سحابي، opt-in) يحقّق نيابةً
> عنهم — كل ذلك خلف console عصري بسيط جداً ونظيف، Kubernetes-native، ومحمي ببوّابات حوكمة
> تضمن بقاءه حرّاً وخاصّاً ونظيفاً إلى الأبد.

---

*نهاية خطة v2. ابدأ من M1 → Phase 12. كل مرحلة قائمة بذاتها وقابلة للشحن، وتحترم المبادئ الخمسة.*
