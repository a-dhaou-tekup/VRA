# VRA — Vulnerability Remediation Assistant

**Semi-Automated Vulnerability Remediation with Risk Scoring, SLA Tracking, Local AI, and Manual Upload**

> TEK-UP University · End-of-Study Project · 2025–2026
> Hardware: RTX 4070 Ti Super (16 GB VRAM) · Ryzen 7600X

---

## Overview

VRA takes vulnerability scan exports from Nessus/OpenVAS (or any CSV), enriches them with live threat intelligence (CISA KEV, FIRST EPSS, NVD), scores them using a transparent 5-factor risk formula, groups findings into actionable remediation jobs with SLA deadlines, and exposes a React dashboard with a local AI recommendation engine (Qwen2.5-14B via Ollama).

### Key differentiators vs. basic vuln tools
- **Manual upload UI** — drag-and-drop scan files directly from the browser; no CLI needed
- **Local AI (on-prem)** — Qwen2.5-14B running on your GPU; no data leaves the machine
- **RAG recommendations** — AI grounded in real advisory text (NVD + CISA KEV + vendor notes)
- **Structured JSON output** — remediation_steps, compensating_controls, verification, confidence
- **Re-scan detection** — auto-detects Fixed/Resurfaced jobs on each new scan import
- **Full audit trail** — every status change, triage decision, AI call, and ticket logged

---

## Architecture

```
Scanner files (Nessus XML / OpenVAS XML / CSV)
         │
         ▼
  M1  Ingestion ─── adapter pattern (Nessus, OpenVAS, CSV-generic)
         │
         ▼
  M2  Enrichment ── CISA KEV (7d TTL) · FIRST EPSS (30d TTL) · NVD API v2
         │           └─ auto-writes .txt files to RAG corpus
         ▼
  M3  Risk Scoring ─ CVSS×40 + KEV×20 + EPSS×15 + Criticality×15 + Exposure×10
         │
         ▼
  M4  Job Builder ── group by (asset, product) · SHA-256 fingerprint · SLA policy YAML
         │
         ├──────────────────────────────────────────────────────────┐
         ▼                                                          ▼
  M5  FastAPI ──── SQLite WAL mode                         M11 Manual Upload
         │         Repos · Migrations                              │
         │                                                   POST /api/uploads
         ├── M6  Governance ── 8-state machine                     │
         │       (TO_DO→IN_PROGRESS→DONE→                   auto-trigger pipeline
         │        CLOSED/RESURFACED/RISK_ACCEPTED…)
         │
         ├── M7  Re-scan ──── fingerprint diff → RESURFACED/DONE
         │
         ├── M8  RAG ──────── ChromaDB + MiniLM embeddings
         │                    Qwen2.5-14B via Ollama
         │                    Structured JSON output
         │
         ├── M9  Dashboard ── React 18 + Tailwind
         │                    6 pages incl. Upload page
         │
         └── M10 Ticketing ── Jira + Console providers
```

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI 0.111+, SQLite (WAL mode), raw sqlite3 |
| AI | Ollama + Qwen2.5-14B Q5_K_M (~10 GB VRAM) |
| RAG | ChromaDB, sentence-transformers (all-MiniLM-L6-v2) |
| Frontend | React 18, Vite, Tailwind CSS, Recharts, React Router v6 |
| Container | Docker + docker-compose (API + Ollama + React) |

---

## Quick Start (Local Dev)

### Prerequisites
- Python 3.11, Node.js 20+
- [Ollama](https://ollama.com) installed
- RTX 4070 Ti Super (or compatible NVIDIA GPU with 10+ GB VRAM)

```bash
# 1. Clone and navigate
cd "PFE 2/vra"

# 2. Python environment
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

# 3. Copy and configure environment
cp .env.example .env
# Edit .env — set API_KEY, adjust OLLAMA_MODEL if needed

# 4. Pull the AI model (~10 GB download)
ollama pull qwen2.5:14b

# 5. Generate sample data (no real scanner needed)
python scripts/generate_sample_data.py

# 6. Run the data pipeline
cd src/ingestion  && python build_vuln_raw.py && cd ../..
cd src/enrichment && python build_vuln_enriched.py && cd ../..
cd src/remediation && python build_remediation_jobs.py && cd ../..

# 7. Fetch CISA advisories + index RAG corpus (~5 min first time)
python scripts/fetch_cisa_advisories.py
python scripts/index_rag_corpus.py

# 8. Start the API
python run_api.py
# → http://localhost:8000
# → http://localhost:8000/docs

# 9. Start the frontend (new terminal)
cd frontend
npm install
npm run dev
# → http://localhost:5173

# 10. Start Ollama (new terminal)
ollama serve
```

---

## Docker (Demo)

```bash
cp .env.example .env  # set API_KEY
docker-compose up -d

# First run: pull the model inside the container
docker-compose exec ollama ollama pull qwen2.5:14b
```

Services:
- API: http://localhost:8000
- Frontend: http://localhost:3000
- Ollama: http://localhost:11434

---

## Modules

### M1 — Ingestion (`src/ingestion/`)
- `adapters/nessus.py` — Nessus XML (`.nessus`) parser
- `adapters/openvas.py` — OpenVAS/Greenbone XML parser
- `adapters/csv_generic.py` — Any CSV with CVE/hostname/CVSS columns
- `build_vuln_raw.py` — Auto-detects file format, merges with asset inventory → `vuln_raw.csv`

### M2 — Enrichment (`src/enrichment/`)
- `kev_ingest.py` — CISA KEV feed, 7-day cache, writes RAG corpus files
- `epss_ingest.py` — FIRST EPSS API, 30-day cache, batched requests
- `nvd_ingest.py` — NVD API v2 descriptions + CWE, writes RAG corpus files
- `build_vuln_enriched.py` — Orchestrates all enrichment → `vuln_enriched.csv`

### M3 — Risk Scoring (`src/enrichment/score_engine.py`)
```
Risk Score = (CVSS/10 × 40) + (KEV × 20) + (EPSS × 15) + (criticality_mult × 15) + (exposed × 10)
Max = 100 | CRITICAL ≥ 80 | HIGH ≥ 60 | MEDIUM ≥ 40 | LOW < 40
```

### M4 — Job Builder (`src/remediation/build_remediation_jobs.py`)
- Groups by `(asset_id, product)`, computes SHA-256 fingerprint
- Assigns SLA: Critical=7d, High=14d, Medium=30d, Low=90d
- Outputs `remediation_jobs.csv`

### M5-M10 — API Layer (`src/api/`)
- **M5** FastAPI + SQLite WAL + full repository pattern
- **M6** 8-state machine: TO_DO → IN_PROGRESS → DONE → CLOSED (+ RESURFACED, RISK_ACCEPTED, DEFERRED, FALSE_POSITIVE)
- **M7** Re-scan detection via SHA-256 job fingerprint diffing
- **M8** RAG: ChromaDB + MiniLM + Qwen2.5-14B + structured JSON output + LLM cache + feedback
- **M9** React 18 dashboard (6 pages)
- **M10** Jira + Console ticket providers

### M11 — Manual Upload (NEW) (`src/api/routers/uploads.py` + `services/upload_service.py`)
- `POST /api/uploads` — multipart file upload (supports .nessus, .xml, .csv)
- Auto-detects scanner format, validates, computes SHA-256 (dedup)
- Triggers full pipeline as background task
- Returns diff: new findings, re-detected, CVEs gone
- Full UI: drag-and-drop, progress stepper, results panel

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/jobs` | List jobs (filters: status, risk_level, kev_only) |
| GET | `/api/jobs/{id}` | Job detail |
| PATCH | `/api/jobs/{id}/status` | Update status 🔑 |
| PATCH | `/api/jobs/{id}/triage` | Triage decision 🔑 |
| GET | `/api/jobs/{id}/events` | Event history |
| GET | `/api/metrics/overview` | Dashboard summary |
| GET | `/api/metrics/sla` | SLA compliance |
| GET | `/api/metrics/timeline` | Jobs timeline |
| GET | `/api/rag/jobs/{id}/recommend` | AI recommendation |
| POST | `/api/rag/jobs/{id}/feedback` | Rate recommendation 🔑 |
| GET | `/api/rag/stats` | ChromaDB stats |
| POST | `/api/rescan/run` | Trigger re-scan detection 🔑 |
| GET | `/api/rescan/status` | Re-scan status |
| POST | `/api/uploads` | Upload scan file 🔑 |
| GET | `/api/uploads` | Upload history |
| GET | `/api/uploads/{id}` | Upload status |
| POST | `/api/tickets/jobs/{id}` | Create ticket 🔑 |
| GET | `/api/tickets` | List tickets |

🔑 = requires `X-Api-Key` header

---

## Risk Formula

| Factor | Input | Normalisation | Weight |
|---|---|---|---|
| CVSS base score | 0–10 | ÷ 10 | 40 |
| CISA KEV flag | bool | 0 or 1 | 20 |
| FIRST EPSS | 0–1 | as-is | 15 |
| Asset criticality | low/medium/high/critical | 0.25/0.5/0.75/1.0 | 15 |
| Internet exposed | bool | 0 or 1 | 10 |
| **Total maximum** | | | **100** |

---

## AI Model Selection

| Model | VRAM | Speed | Quality |
|---|---|---|---|
| **qwen2.5:14b Q5_K_M** ← recommended | ~10 GB | ~20-40 tok/s | ⭐⭐⭐⭐⭐ |
| mistral:7b | ~4 GB | ~60 tok/s | ⭐⭐⭐ |
| mistral-small:24b Q4_K_M | ~14 GB | ~15 tok/s | ⭐⭐⭐⭐⭐ |

Change model: set `OLLAMA_MODEL=qwen2.5:14b` in `.env` and run `ollama pull qwen2.5:14b`.

---

## Data Privacy

All processing is local:
- No scan data sent to external AI APIs
- Qwen2.5-14B runs on your GPU via Ollama
- Only external calls: CISA KEV feed, FIRST EPSS API, NVD API (CVE metadata only — no asset/hostname data)

---

## Project Structure

```
vra/
├── config/                  ← policy.yaml (risk weights, SLA, RAG config)
├── data/
│   ├── input/               ← scanner XML + asset_inventory.csv
│   ├── output/              ← vuln_raw, vuln_enriched, vuln_scored, remediation_jobs CSVs
│   ├── cache/               ← enrichment.db (KEV/EPSS/NVD cache), platform.db (jobs/events)
│   ├── uploads/             ← uploaded scan files
│   └── rag_corpus/          ← NVD advisory text, CISA KEV notes, vendor advisories
├── src/
│   ├── ingestion/           ← M1: adapters + build_vuln_raw.py
│   ├── enrichment/          ← M2+M3: KEV/EPSS/NVD ingest + score_engine.py
│   ├── remediation/         ← M4: build_remediation_jobs.py
│   ├── rag/                 ← M8: indexer, retriever, recommender
│   └── api/                 ← M5-M7, M9-M11: FastAPI app
├── frontend/                ← React 18 SPA
├── scripts/                 ← generate_sample_data, fetch_cisa_advisories, index_rag_corpus
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── run_api.py
└── .env.example
```
