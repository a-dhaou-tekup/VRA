# VRA — Vulnerability Remediation Assistant

> **TEK-UP University · End-of-Study Project · 2025–2026**  
> Hardware: RTX 4070 Ti Super (16 GB VRAM) · Ryzen 7600X · Windows

Semi-automated vulnerability remediation platform: ingests scanner exports, enriches with live threat intelligence, scores with a transparent 5-factor risk model, groups findings into SLA-tracked remediation jobs, and serves a React dashboard backed by a fully local AI engine (Qwen2.5-14B via Ollama + RAG).

---

## Feature Overview

| Capability | Detail |
|---|---|
| **Multi-format ingestion** | Nessus XML, OpenVAS XML, generic CSV; LLM parser for unknown vendor formats |
| **Threat intelligence** | CISA KEV (7 d TTL), FIRST EPSS (30 d TTL), NVD API v2 |
| **Risk scoring** | CVSS × 40 + KEV × 20 + EPSS × 15 + Criticality × 15 + Exposure × 10 (max 100) |
| **Remediation jobs** | SHA-256 fingerprint, 8-state lifecycle, SLA deadlines, audit trail |
| **Re-scan detection** | Auto-detects Fixed / Resurfaced on every new import |
| **Local AI advice** | RAG over NVD + CISA + vendor runbooks; Qwen2.5-14B; structured JSON output |
| **AI auto-triage** | Per-finding triage classification (valid / needs investigation / false positive) with confidence score |
| **Chat with finding** | SSE-streamed conversational follow-up on any job; multi-turn memory |
| **Knowledge graph** | NetworkX in-process graph: CVE → component → asset → owner → service; blast-radius BFS; graph+embedding similarity |
| **Threat alerts** | CPE/KEV-driven alert generation per asset; dismissal / resolution workflow |
| **Compliance mapping** | Control catalogue (NIST / ISO); tag jobs to controls; coverage dashboard |
| **Risk register** | Risk acceptances with justification, compensating controls, expiry review |
| **Executive PDF reports** | LLM-narrated 5-page PDF (cover + summary + KPI charts + top findings + glossary); template fallback; on-demand or scheduled |
| **RBAC** | 5 roles: Admin, Analyst, Remediation Owner, Risk Owner, Auditor; JWT auth |
| **Ticketing** | Jira + console providers; bidirectional status sync |
| **Demo instance** | Isolated DB, zero pre-seeded data, separate ports — runs side-by-side with dev |

---

## Architecture

```
Scanner files (Nessus XML / OpenVAS XML / CSV / unknown vendor)
        │
        ▼
   Ingestion  ──  adapter pattern (Nessus · OpenVAS · CSV-generic · LLM parser)
        │
        ▼
   Enrichment  ── CISA KEV · FIRST EPSS · NVD API v2  →  enrichment.db (cache)
        │           └── auto-writes advisory .txt files to RAG corpus
        ▼
   Risk Scoring  ── 5-factor formula → risk_score [0–100] → CRITICAL/HIGH/MEDIUM/LOW
        │
        ▼
   Job Builder  ── group by (asset, product) · SHA-256 fingerprint · SLA policy
        │
        ▼
   FastAPI  ──────────────────────────────────────────────────────────────────┐
        │                                                                     │
        ├── Jobs & Lifecycle  (8-state machine + audit log)                   │
        ├── Re-scan Detection (fingerprint diff → RESURFACED / DONE)          │
        ├── Findings & Auto-Triage  (per-finding AI classification)           │
        ├── RAG Recommendations  (ChromaDB + MiniLM + Qwen2.5-14B)           │
        ├── Chat with Finding  (SSE stream · multi-turn · RAG-grounded)       │
        ├── Knowledge Graph  (NetworkX · blast-radius BFS · embedding sim.)  │
        ├── Threat Alerts  (CPE/KEV matching per asset)                       │
        ├── Compliance  (control catalogue · job tagging · coverage)          │
        ├── Risk Register  (acceptances · workarounds · lifecycle)            │
        ├── Executive Reports  (LLM prose · matplotlib charts · fpdf2 PDF)   │
        ├── Assets · Tickets · Users · Metrics · Enrichment · Uploads        │
        │                                                                     │
        └── SQLite WAL (platform.db)   +   enrichment.db                     │
                                                                              │
   React 18 SPA  ◄─────────────────────────────────────────────────────────┘
   (16 pages · Tailwind · Recharts · React Router v6)
```

---

## Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11+, FastAPI 0.111+, SQLite WAL, raw sqlite3, repository pattern |
| **AI / LLM** | Ollama + Qwen2.5-14B (~10 GB VRAM on RTX 4070 Ti Super) |
| **RAG** | ChromaDB, sentence-transformers `all-MiniLM-L6-v2`, hybrid retrieval + cross-encoder reranker |
| **Graph** | NetworkX (in-process DiGraph, no Neo4j) |
| **PDF** | fpdf2 (pure Python, no system libs) + matplotlib (KPI charts) |
| **Auth** | JWT (python-jose) + bcrypt; OAuth2 password flow |
| **Frontend** | React 18, Vite 5, Tailwind CSS, Recharts, React Router v6, Axios |
| **Ticketing** | Jira REST API + console provider |

---

## Quick Start

### Prerequisites

- Python 3.11 or 3.14, Node.js 20+
- [Ollama](https://ollama.com) installed and `ollama serve` running
- NVIDIA GPU with ≥ 10 GB VRAM (RTX 3080 / 4070 Ti Super or better)

### Development instance (with seeded sample data)

```bash
# 1. From the project root
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

# 2. Environment
cp .env.example .env            # set API_KEY if needed

# 3. Pull the model (~9 GB first time)
ollama pull qwen2.5:14b

# 4. Index the RAG corpus (run once; ~5 min)
python scripts/index_rag_corpus.py

# 5. Launch everything
start.bat                       # opens Ollama · Backend :8000 · Frontend :5173
```

`start.bat` seeds a full set of demo jobs, assets, and users automatically.

### Demo instance (clean — upload your own data)

```bash
start_demo.bat                  # Backend :8001 · Frontend :5174 · fresh demo.db
```

The demo instance shares the KEV/EPSS/NVD enrichment cache and the RAG corpus with the dev instance; both can run simultaneously.

**Demo credentials (both instances):**

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin1234!` | Administrator |
| `analyst` | `Analyst1234!` | Security Analyst |
| `remediation_owner` | `RemOwner1234!` | Remediation Owner |
| `risk_owner` | `RiskOwner1234!` | Risk Owner |
| `auditor` | `Auditor1234!` | Auditor (read-only) |

---

## Demo Script (10-minute defence)

| Step | Action | What to show |
|---|---|---|
| 1 | Upload `data/input/scanner_demo1.csv` | LLM parser maps unknown "RiskTrack Enterprise v3.2" columns to VRA schema |
| 2 | Findings page | AI-triage column: confidence pills; enable FP filter → SWEET32 / POODLE / RC4 disappear |
| 3 | Open Log4Shell on `prod-api-01` | Grounded advice with `[cve_descriptions:…]` and `[vendor_advisories:…]` citations |
| 4 | Chat panel | Ask *"does this fix apply on RHEL 9?"* → RAG-grounded follow-up |
| 5 | Blast Radius tab | `prod-api-01 → prod-db-primary-01 → prod-redis-01`; click a node for details |
| 6 | Overview → 📄 Executive Report | Live PDF generation; flip through cover / summary / KPI charts / top-10 / glossary |

Demo data files:
- `data/input/assets_demo1.csv` — 25 assets, 5 business units, mixed criticality
- `data/input/scanner_demo1.csv` — 55 findings across 23 hosts (22 CRITICAL, 24 HIGH, 9 FP-targets)

---

## Frontend Pages

| Page | Route | Description |
|---|---|---|
| Overview | `/` | KPI strip, risk/status charts, recent jobs, executive report button + history |
| Remediation Jobs | `/jobs` | Filterable job list with risk badges and SLA indicators |
| Job Detail | `/jobs/:id` | Lifecycle controls, AI advice, chat panel, blast-radius tab, similar findings |
| Metrics | `/metrics` | SLA compliance, MTTR, backlog trend, KEV coverage charts |
| Tickets | `/tickets` | Jira / console ticket list and creation |
| Upload | `/upload` | Drag-and-drop scan file upload; pipeline progress stepper; diff results |
| Assets | `/assets` | Asset inventory with criticality, exposure, software, threat-alert counts |
| Findings | `/findings` | CVE-host pairs with AI triage suggestions; false-positive filter |
| Finding Detail | `/findings/:id` | Per-finding advice, blast-radius graph, similar findings, chat |
| Threat Alerts | `/alerts` | CPE/KEV-matched alerts per asset; dismiss / resolve |
| Risk Register | `/risk-register` | Risk acceptances with compensating controls and expiry |
| Enrichment | `/enrichment` | KEV / EPSS / NVD cache status; manual refresh |
| Compliance | `/compliance` | Control catalogue coverage; job-to-control mapping |
| Manual Entry | `/manual` | Direct CVE+host entry without a scanner file |
| Users | `/users` | User management (Admin only) |
| Login | `/login` | JWT authentication |

---

## API Reference

### Jobs & Lifecycle

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/jobs` | open | List jobs (filters: status, risk_level, kev_only) |
| GET | `/api/jobs/{id}` | open | Job detail |
| PATCH | `/api/jobs/{id}/status` | write | Update status |
| PATCH | `/api/jobs/{id}/triage` | write | Set triage decision |
| PATCH | `/api/jobs/{id}/sla-override` | write | Override SLA days |
| GET | `/api/jobs/{id}/events` | open | Audit trail |
| POST | `/api/jobs/{id}/risk-acceptance` | write | Record risk acceptance |
| POST | `/api/jobs/{id}/workaround` | write | Record compensating control |
| GET | `/api/jobs/{id}/workarounds` | open | List workarounds |

### Findings & Auto-Triage

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/findings/` | open | Findings list with triage join |
| POST | `/api/findings/manual` | write | Submit manual CVE+host findings |
| POST | `/api/findings/{id}/auto-triage` | analyst | Run / re-run auto-triage |
| GET | `/api/findings/{id}/auto-triage` | open | Current triage suggestion |
| GET | `/api/findings/manual/example` | open | Example payload |

### RAG / AI

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/rag/jobs/{id}/recommend` | open | AI remediation recommendation |
| POST | `/api/rag/jobs/{id}/feedback` | write | Rate a recommendation |
| GET | `/api/rag/stats` | open | ChromaDB collection stats |
| POST | `/api/findings/{id}/chat` | write | SSE chat stream |
| GET | `/api/findings/{id}/conversations` | read | List conversations |
| GET | `/api/conversations/{id}` | read | Full transcript |

### Knowledge Graph

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/findings/{id}/blast-radius` | open | BFS subgraph (depth 1–4) |
| GET | `/api/findings/{id}/similar` | open | Top-k similar findings (graph + embedding) |
| POST | `/api/graph/refresh` | admin | Rebuild in-memory graph |

### Executive Reports

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/reports/executive` | analyst | Trigger PDF generation (returns 202) |
| GET | `/api/reports/executive` | open | List past reports |
| GET | `/api/reports/executive/{id}` | open | Report metadata + summary text |
| GET | `/api/reports/executive/{id}/pdf` | open | Download PDF bytes |

### Other Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/api/metrics/*` | Overview, SLA, timeline |
| POST | `/api/uploads` | Upload scan file (multipart) |
| GET | `/api/uploads/{id}` | Upload status |
| GET/POST | `/api/tickets/*` | Jira / console tickets |
| POST | `/api/rescan/run` | Re-scan detection |
| GET | `/api/assets/*` | Asset CRUD + software inventory |
| GET | `/api/alerts/*` | Threat alerts lifecycle |
| GET | `/api/compliance/*` | Control catalogue + job mapping |
| GET | `/api/enrichment/*` | KEV/EPSS/NVD cache viewer |
| POST/GET | `/api/auth/login` | JWT token |
| GET/POST | `/api/users/*` | User management (Admin) |
| GET | `/health` | Liveness check |

Full interactive docs at **`http://localhost:8000/docs`**.

---

## Risk Formula

```
Risk Score = (CVSS / 10) × 40
           + KEV_flag      × 20
           + EPSS_score    × 15
           + criticality   × 15   (low=0.25 · medium=0.5 · high=0.75 · critical=1.0)
           + internet_exp  × 10

Thresholds:  CRITICAL ≥ 80 · HIGH ≥ 60 · MEDIUM ≥ 40 · LOW < 40
```

Weights are fully configurable in `config/policy.yaml`.

---

## SLA Policy

| Risk Level | Deadline |
|---|---|
| CRITICAL | 7 days |
| HIGH | 14 days |
| MEDIUM | 30 days |
| LOW | 90 days |

Configurable in `config/policy.yaml` under `sla_days`.

---

## AI Model

| Model | VRAM | Tok/s | Recommended for |
|---|---|---|---|
| **qwen2.5:14b** ← default | ~10 GB | ~30 tok/s | Best quality on 16 GB card |
| mistral:7b | ~4 GB | ~60 tok/s | Low-VRAM fallback |
| mistral-small:24b | ~14 GB | ~15 tok/s | Maximum quality |

Change: set `model: <name>` in `config/policy.yaml` under `rag:` and run `ollama pull <name>`.

---

## Data Privacy

All processing is local. No scan data, asset names, or finding details leave the machine.

| External call | Data sent | Purpose |
|---|---|---|
| CISA KEV feed | nothing | Download KEV catalogue |
| FIRST EPSS API | CVE IDs only | Fetch exploitation probabilities |
| NVD API v2 | CVE IDs only | Fetch CVSS scores and descriptions |

Ollama runs entirely on the local GPU. The RAG corpus is stored in `data/rag_corpus/`.

---

## Project Structure

```
vra/
├── config/
│   └── policy.yaml              ← risk weights, SLA days, RAG settings
├── data/
│   ├── input/                   ← asset CSVs, scanner files for pipeline mode
│   │   ├── assets_demo1.csv     ← 25-asset demo inventory
│   │   └── scanner_demo1.csv    ← 55-finding RiskTrack demo scan
│   ├── output/                  ← intermediate pipeline CSVs
│   ├── cache/
│   │   ├── platform.db          ← dev instance (jobs, findings, reports …)
│   │   ├── demo.db              ← demo instance (created fresh by start_demo.bat)
│   │   └── enrichment.db        ← KEV / EPSS / NVD cache (shared)
│   ├── uploads/                 ← uploaded scan files
│   ├── reports/                 ← generated executive PDFs
│   └── rag_corpus/
│       ├── chroma_db/           ← vector store (created by index_rag_corpus.py)
│       └── *.txt                ← advisory text files
├── src/
│   ├── ingestion/               ← adapters: nessus · openvas · csv_generic
│   ├── enrichment/              ← kev_ingest · epss_ingest · nvd_ingest · score_engine
│   ├── remediation/             ← build_remediation_jobs.py
│   ├── rag/                     ← indexer · retriever · recommender · reranker · multi_collection
│   └── api/
│       ├── db/                  ← migrate.py (idempotent) · connection.py
│       ├── repositories/        ← jobs_repo · events_repo
│       ├── routers/             ← 19 routers (one file per domain)
│       ├── services/
│       │   ├── graph/           ← builder · cache · queries (blast-radius, similar)
│       │   ├── reports/         ← executive.py (gather_state · LLM · fpdf2 PDF)
│       │   └── …                ← upload · rag · triage · compliance · chat …
│       └── main.py
├── frontend/
│   └── src/
│       ├── pages/               ← 16 React pages
│       ├── components/          ← shared UI components
│       └── api/client.js        ← axios client with JWT interceptor
├── scripts/
│   ├── generate_sample_data.py
│   ├── fetch_cisa_advisories.py
│   ├── index_rag_corpus.py
│   ├── build_real_data_from_nvd.py
│   └── seed_demo_graph.py       ← seeds services + asset_services + dependencies
├── docs/
│   ├── graph.md                 ← graph model + single-process limitation
│   └── executive-reports.md    ← prompt template + fallback + schedule
├── run_api.py                   ← uvicorn entry point (hot-reload in dev mode)
├── start.bat                    ← dev instance: :8000 + :5173
├── start_demo.bat               ← demo instance: :8001 + :5174 + fresh demo.db
├── requirements.txt
└── .env.example
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PLATFORM_DB_PATH` | `data/cache/platform.db` | SQLite platform database path |
| `JWT_SECRET_KEY` | (change in prod) | JWT signing key |
| `JWT_EXPIRE_HOURS` | `8` | Token lifetime |
| `API_HOST` | `0.0.0.0` | Uvicorn bind address |
| `API_PORT` | `8000` | Uvicorn port |
| `APP_ENV` | `dev` | `dev` enables hot-reload |
| `VRA_SKIP_SEED` | `false` | Set `true` to skip job/asset CSV seeding (demo instance) |
| `OLLAMA_TIMEOUT_SECONDS` | `300` | LLM call timeout |
| `GRAPH_REFRESH_INTERVAL_SECONDS` | `60` | Graph cache TTL |
| `REQUIRE_AUTH_FOR_READS` | `false` | Enforce auth on GET endpoints |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Known Limitations

- **Graph is single-process**: the in-memory NetworkX graph is local to each uvicorn worker. Multi-worker deployments need a dedicated graph service (see `docs/graph.md`).
- **SQLite concurrency**: WAL mode handles concurrent reads well; very high write throughput should migrate to PostgreSQL.
- **Ollama cold start**: first recommendation after idle takes ~10 s for model load; pre-warm with `GET /api/rag/stats` before a demo.
- **Executive PDF font**: fpdf2 built-in fonts are Latin-1; Cyrillic/CJK asset names are transliterated to `?`. Use a TTF font to lift this restriction.
