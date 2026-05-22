# CLAUDE.md — VRA project context

This file is auto-loaded by Claude Code each session. Keep it accurate.

## What this is
VRA (Vulnerability Remediation Assistant) — TEK-UP end-of-study project. Takes vulnerability
scan exports (Nessus/OpenVAS/CSV), enriches with threat intel (CISA KEV, FIRST EPSS, NVD),
scores with a 5-factor risk model, groups findings into remediation jobs with SLA deadlines,
and serves a React dashboard with a **local** AI recommendation engine (Qwen2.5-14B via Ollama + RAG).

## Environment (important)
- **Single unrestricted machine**: RTX 4070 Ti Super (16 GB VRAM), Ryzen 7600X, Windows. This is ALSO the demo machine.
- No corporate proxy/SSL restrictions — external feeds (KEV/EPSS/NVD) fetch normally.
- Python 3.11, Node 20+, Ollama installed locally.

## Stack
- Backend: Python 3.11, FastAPI, raw sqlite3 (WAL), repository pattern. Entry: `run_api.py` → `api.main:app`.
- AI: Ollama + `qwen2.5:14b`; RAG via ChromaDB + sentence-transformers (`all-MiniLM-L6-v2`).
- Frontend: React 18 + Vite + Tailwind + Recharts, axios client (`frontend/src/api/client.js`).
- Config: `config/policy.yaml` (risk weights, SLA, RAG settings) + `.env` (from `.env.example`).

## Layout
- `src/ingestion/` — adapters (nessus/openvas/csv_generic) + `build_vuln_raw.py`
- `src/enrichment/` — `kev_ingest.py`, `epss_ingest.py`, `nvd_ingest.py`, `score_engine.py`, `build_vuln_enriched.py`
- `src/remediation/` — `build_remediation_jobs.py`
- `src/rag/` — `indexer.py`, `retriever.py`, `recommender.py`
- `src/api/` — `main.py`, `routers/`, `services/`, `repositories/`, `db/` (migrate.py creates schema on startup), `ticketing/`
- `frontend/src/pages/` — 9 pages (Overview, JobsList, JobDetail, Metrics, Tickets, Upload, Assets, ManualFindings, Enrichment)
- `scripts/` — `generate_sample_data.py`, `fetch_cisa_advisories.py`, `index_rag_corpus.py`, `build_real_data_from_nvd.py`
- `data/cache/` — `platform.db` (jobs/events/advice/tickets), `enrichment.db` (KEV/EPSS/NVD cache)
- `data/rag_corpus/` — advisory `.txt` files; `chroma_db/` is the vector store (created by indexing)

## Run commands
```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # set API_KEY
ollama pull qwen2.5:14b && ollama serve
python scripts/index_rag_corpus.py     # builds data/rag_corpus/chroma_db
python run_api.py                       # http://localhost:8000  (docs at /docs)
cd frontend && npm install && npm run dev   # http://localhost:5173
```

## Known bugs to fix (do these carefully, propose patch first)
1. `src/api/routers/rag.py::recommend` reads `result.get("model"/"prompt_tokens"/"response_tokens")`,
   but `src/rag/recommender.py::generate_recommendation` nests them under `result["_meta"]`.
   Fix the router to read from `_meta` so the `llm_advice` cache logs real model + tokens.
2. `src/rag/recommender.py::call_ollama` hardcodes `timeout=300`. Make it read from config/env.
   `policy.yaml`'s `rag:` block needs an `ollama_timeout` key; `.env` has `OLLAMA_TIMEOUT_SECONDS`.
3. `src/api/services/rag_service.py::get_chroma_stats` stub uses collection name `vra_rag` and a
   different key shape than `src/rag/indexer.py::get_collection_stats` (real name `vra_advisories`). Align them.

## Conventions
- Match the existing repository/service/router pattern; don't introduce a new ORM.
- Write endpoints require `X-Api-Key`; reads are open unless `REQUIRE_AUTH_FOR_READS=true`.
- All status changes must write a `job_events` row (audit trail).
- Keep all AI processing local; the only outbound calls are KEV/EPSS/NVD metadata fetches.

## Demo-day rules (do not violate)
- NEVER fetch live external feeds during a demo. Use the seeded `enrichment.db`.
- Pre-cache AI recommendations for demo jobs into `llm_advice` ahead of time.
- Confirm `ollama serve` + model loaded and `/api/rag/stats` > 0 before demoing.

## How I want you to work
- Read `VRA_Next_Phase_Plan.md` for the week's roadmap. Execute one Day at a time; don't jump ahead.
- For the three known bugs and any schema change, use Plan Mode / propose the diff before editing.
- After backend changes, run the relevant script or hit the endpoint to verify, and show me the output.
- Don't commit `.db` files except the intentionally seeded demo DB.
