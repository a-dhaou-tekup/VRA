# VRA — Next-Phase Operational Plan (v2 · single unrestricted GPU machine)

**Goal:** a fully operational, demo-ready, defence-ready system within one week.
**Setup:** everything runs on **one unrestricted machine** — the RTX 4070 Ti Super rig — which is also the **demo machine**. No corporate proxy/SSL restrictions. External feeds (CISA KEV, FIRST EPSS, NVD) fetch normally.
**Scope:** (A) finish + verify the LLM/RAG layer · (B) polish + light deployment hardening · (C) **two** Phase-C extensions.

Grounded in a full read of the extracted codebase (~5,200 lines Python, ~2,750 lines React across 9 pages), the README, `policy.yaml`, the DB schema, and the current data state.

---

## 0. What changed from v1 (because it's one unrestricted machine)

- **EPSS/NVD just work now.** The "corporate MITM SSL block" in the old notes was the *other* machine. No workaround needed.
- **Fresh-machine reproducibility risk is gone.** Same box builds and demos. The bootstrap script becomes *polish*, not risk mitigation. Docker fallback is **optional**.
- **~1 day freed up** → reinvested into a **second Phase-C extension** (chat-with-finding) and deeper tests.
- **The risk register collapses to one row: the GPU/Ollama path on demo day.**

> **Still non-negotiable:** do **not** fetch live external feeds during the defence, and **pre-cache AI recommendations** for the demo jobs. Not for permissions reasons — external feeds have bad days, and Ollama is your one unavoidable live dependency. Don't stack optional failure points on it.

---

## 1. Where the project actually stands

### Verified present and working (read from code + DB)
- **API**: FastAPI app factory, migrations-on-startup, 9 routers wired (`jobs, metrics, tickets, rescan, uploads, assets, findings, enrichment, rag`), `/health`, API-key auth on writes, CORS. All Python compiles.
- **Pipeline**: ingestion adapters (Nessus / OpenVAS / CSV-generic), enrichment (KEV / EPSS / NVD), 5-factor score engine, job builder with SHA-256 fingerprint + SLA policy.
- **Database** (`platform.db`): `assets`(3), `jobs`(6 seeded), `job_events`(0), `llm_advice`(0), `ticket_links`(0), `uploads`(5).
- **Enrichment cache** (`enrichment.db`): `cve_context` = **1,592 KEV CVEs cached**. No EPSS rows yet.
- **RAG code**: indexer (ChromaDB + MiniLM, CUDA-aware), retriever (top-k), recommender (Ollama JSON-mode, graceful stubs, token/latency metadata). Clean and complete.
- **Frontend**: 9 pages, axios client with API-key interceptor.
- **Enrichment management** (the old "15-min fix"): **already done** — `/api/enrichment/status|kev/refresh|epss/refresh|nvd/refresh|cve/{id}` + Enrichment page.
- **Docs**: `docs/defence.md` (21 KB), `docs/real-data-acquisition.md`.
- **Deployment**: `Dockerfile`, `docker-compose.yml`, `.env.example`.

### Present but NOT YET VERIFIED end-to-end (the real work)
- **RAG/LLM never run against a live model.** `llm_advice` = 0, `job_events` = 0.
- **No `chroma_db/`.** Corpus (~1,594 KEV note files) never indexed → retrieval empty until you index.
- **EPSS never fetched** (no `epss` table). On this machine it'll just run.
- **`data/output/` empty** — the 6 jobs were seeded directly.

### Confirmed bugs to fix (found by reading the code)
1. **RAG cache writes blank metadata.** `routers/rag.py::recommend` reads `result.get("model")`/`prompt_tokens`/`response_tokens`, but `recommender.generate_recommendation` nests those under `result["_meta"]`. → model "unknown", tokens 0.
2. **Ollama timeout not configurable.** `recommender.call_ollama` hardcodes `timeout=300`; `policy.yaml` `rag:` lacks `ollama_timeout`; `.env`'s `OLLAMA_TIMEOUT_SECONDS` isn't plumbed in.
3. **`get_chroma_stats` stub** uses `vra_rag` vs the real `vra_advisories`, with a different key shape than `get_collection_stats`.

### Not built yet
- Phase-C extensions; tests (`tests/` empty); one-command bootstrap + committed seeded dataset.

**Verdict:** ~80% done, structurally sound. The week is about proving the AI layer lives, closing three small bugs, indexing the corpus, and making the demo deterministic.

---

## 2. The week, day by day

### Day 1 — Stand it up & prove the AI path
- venv → `pip install -r requirements.txt` → `cp .env.example .env` → set `API_KEY`.
- `ollama pull qwen2.5:14b`; `ollama serve`; confirm `curl localhost:11434/api/tags`.
- **Index the corpus**: `python scripts/index_rag_corpus.py`. Verify `data/rag_corpus/chroma_db/` exists and `GET /api/rag/stats` > 0.
- Start API (`python run_api.py`) + frontend (`npm install && npm run dev`).
- **Money shot:** seeded job → AI panel → real structured JSON returns, caches, adds an `llm_advice` row. Status change writes a `job_events` row.
- **Fix bug #1**; re-test.

**Exit:** one job shows a genuine Qwen2.5 recommendation; cache + audit populate; `/api/rag/stats` > 0.

### Day 2 — Full 5-factor scoring + corpus quality
- **Fix bug #2**.
- Run **EPSS** (`POST /api/enrichment/epss/refresh` over the 1,592 cached CVEs). Confirm `epss` table populates and contributes to scores.
- Refresh NVD for a sample; confirm `/api/enrichment/cve/{id}` merged view.
- Re-run pipeline so `data/output/` CSVs exist; jobs rebuild with full 5-factor scores.
- **A6 corpus quality**: spot-check 5–10 retrievals; tune `top_k_chunks`/chunk size in `policy.yaml` if weak.

**Exit:** five-factor scores incl. EPSS; on-topic retrieval; pipeline reproducible.

### Day 3 — Latency benchmark + AI UX polish (B2/B3/B5)
- **B5 latency benchmark**: tok/s + end-to-end latency across ~10 jobs. Record it.
- **B2/B3 polish**: Upload page (drag-drop, stepper, diff); AI panel (render all schema fields + model/latency badge from fixed `_meta`); loading state.
- **Fix bug #3**.

**Exit:** AI panel finished; upload smooth; latency table captured.

### Day 4 — Determinism + polish (lighter than v1)
- **Pre-cache AI recommendations** for all demo jobs (persist in `llm_advice`). Demo-day insurance.
- **Commit seeded dataset** to `data/input/` + ship populated `enrichment.db`.
- **`bootstrap.ps1`** running README steps 1–9 in one shot (polish/professionalism).
- `git init` + `.gitignore` (exclude `.venv`, `node_modules`, `chroma_db`, `*.db` except seeded, `data/uploads/*`); first commit.
- Confirm `API_KEY` on writes, `APP_ENV=prod` disables reload, WAL on.
- *(Optional)* verify Docker path once.

**Exit:** deterministic demo from seeded data + pre-cached AI; one-command bootstrap works.

### Day 5 — Phase C #1: Multi-file upload
- Accept multiple files in `POST /api/uploads` (or `/api/uploads/batch`), run each through the existing pipeline, aggregate the new/re-detected/gone diff.
- Frontend: multi-file drop zone + combined results panel.

**Exit:** drop several scans → jobs aggregate → one combined diff.

### Day 6 — Phase C #2: Chat-with-finding + tests
- **Chat-with-finding**: reuse the RAG recommender with a free-text user turn against a job's context. `POST /api/rag/jobs/{id}/chat` + chat box on Job Detail.
- **Tests** in `tests/`: app smoke (`/health`, `/api/jobs`), score-engine unit (known input → known score), fingerprint determinism. Green.

**Exit:** grounded follow-up answers; tests pass.

### Day 7 — Test, dry-run, freeze, buffer
- Full **timed dry-run**. **Screenshots / GIF (B4)**. Tag `v1.0`. Remaining time = GPU/Ollama buffer.

---

## 3. Priority ranking (if the week compresses)

1. **Day 1 + bug #1** — AI path proven live.
2. **Day 2** — full 5-factor scoring + corpus quality.
3. **Day 4** — pre-cached recs + seeded data.
4. **Day 3** — latency + AI UX polish.
5. **Day 5** — multi-upload.
6. **Day 6** — chat-with-finding + tests.

Tiers 1–3 are non-negotiable core; 4–6 are upside.

---

## 4. Demo-day risk register (collapsed)

| Risk | Likelihood | Mitigation |
|---|---|---|
| GPU/Ollama stalls or cold-starts during demo | Medium | **Pre-cache recommendations**; confirm `ollama serve` + model loaded before the room fills; `/api/rag/stats` > 0 pre-flight; `OLLAMA_NUM_GPU=0` CPU fallback last resort |
| External feed slow/down on demo morning | Low–Med | Never fetch live; ship seeded `enrichment.db` + committed demo data |
| Empty `tests/` raised by jury | Low | Day 6 tests close this cheaply |

---

## 5. Concrete fix checklist

- [ ] `index_rag_corpus.py` run; `chroma_db/` exists; `/api/rag/stats` non-zero
- [ ] One real Qwen2.5 recommendation in UI; `llm_advice` + `job_events` populate
- [ ] **Bug 1** — `routers/rag.py` reads model/tokens from `result["_meta"]`
- [ ] **Bug 2** — Ollama timeout from config/env; `policy.yaml` `rag:` keys aligned
- [ ] **Bug 3** — `get_chroma_stats` matches `get_collection_stats` (name `vra_advisories`)
- [ ] EPSS fetched; `epss` table populated; scores now 5-factor
- [ ] NVD sampled; `/api/enrichment/cve/{id}` merged view works
- [ ] `data/output/` CSVs regenerated; jobs rebuilt with full scores
- [ ] Latency benchmark table captured (tok/s + end-to-end ms)
- [ ] Upload page + AI panel polished; loading states added
- [ ] AI recommendations **pre-cached** for all demo jobs
- [ ] Seeded demo dataset + populated `enrichment.db` committed
- [ ] `bootstrap.ps1` one-command setup
- [ ] `git init`, `.gitignore`, `v1.0` tag
- [ ] Multi-file upload live
- [ ] Chat-with-finding live
- [ ] Smoke + score-engine + fingerprint tests pass
- [ ] Screenshots / demo GIF captured
- [ ] Full timed dry-run
