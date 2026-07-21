# VRA — Claude Code Prompts (paste one block per session)

Each block is a self-contained kickoff. Start a fresh session per day (or use `/clear`
between days) so context stays focused. Always have `CLAUDE.md` + `VRA_Next_Phase_Plan.md`
in the repo root so they auto-load.

Tip: prefix risky edits with Plan Mode (press **Shift+Tab** to cycle into plan mode, or ask
"plan first, don't edit yet"). Review the diff, then let it apply.

---

## Day 1 — Stand up + prove the AI path

```
Read CLAUDE.md and VRA_Next_Phase_Plan.md. We're on Day 1.

First, help me get the stack running:
1. Confirm my venv + deps + .env are set (API_KEY filled in).
2. Confirm Ollama is up and qwen2.5:14b is pulled (curl localhost:11434/api/tags).
3. Run `python scripts/index_rag_corpus.py` and verify data/rag_corpus/chroma_db was created.
4. Start the API and tell me how to start the frontend.

Then verify the AI path end to end:
5. Hit GET /api/rag/stats — confirm total_chunks > 0.
6. Pick a seeded job, call GET /api/rag/jobs/{id}/recommend, and show me the raw JSON.
7. Confirm a new row landed in the llm_advice table and that a status change writes a job_events row.

Do NOT touch Phase C. Report what works and what doesn't before changing any code.
```

After it confirms the AI path works, then:

```
Now fix Bug #1 from CLAUDE.md (the _meta mismatch in src/api/routers/rag.py).
Plan the patch and show me the diff before editing. After applying, re-run the
recommend endpoint and prove the llm_advice row now has the real model name and
non-zero token counts.
```

---

## Day 2 — Full 5-factor scoring + corpus quality

```
Day 2 per VRA_Next_Phase_Plan.md.

1. Fix Bug #2 (Ollama timeout from config/env). Add `ollama_timeout` to the rag: block
   in policy.yaml, plumb OLLAMA_TIMEOUT_SECONDS through, propose the diff first.
2. Trigger EPSS enrichment: POST /api/enrichment/epss/refresh over the cached CVEs.
   Confirm an epss table/rows appear in enrichment.db and that EPSS now feeds the score.
3. Refresh NVD for a handful of CVEs; verify GET /api/enrichment/cve/{id} returns a
   merged KEV+EPSS+NVD view.
4. Re-run the pipeline so data/output/ CSVs exist and jobs rebuild with full 5-factor scores.
5. Corpus quality check: for 5 different jobs, show me what retrieve_for_job pulls back.
   If retrievals look off-topic, suggest tuning top_k_chunks or chunk size in policy.yaml.

Verify each step with real output before moving on.
```

---

## Day 3 — Latency benchmark + AI UX polish

```
Day 3 per the plan.

1. Write a small benchmark script (scripts/bench_llm.py) that calls the recommend
   pipeline for ~10 jobs and reports per-call latency_ms, prompt/response tokens, and
   tokens/sec. Run it and give me a markdown table of results.
2. Fix Bug #3 (get_chroma_stats name/shape mismatch). Diff first.
3. Polish the AI recommendation panel on the Job Detail page: render summary,
   exploitation_likelihood, remediation_steps, compensating_controls, verification,
   confidence, and a small badge showing model + latency. Add a loading state while
   the recommendation generates.
4. Polish the Upload page: clear drag-drop affordance, a progress stepper, and a
   results diff panel (new / re-detected / gone).

Keep changes consistent with the existing Tailwind styling. Show me the UI changes file by file.
```

---

## Day 4 — Determinism + polish

```
Day 4 per the plan. Goal: the demo runs deterministically on this machine with no live fetches.

1. Pre-cache AI recommendations for ALL demo jobs (call recommend for each so llm_advice
   is fully populated). Confirm counts.
2. Commit a known-good seeded dataset under data/input/ (sample scan + asset inventory)
   and make sure the populated enrichment.db is included.
3. Write bootstrap.ps1 that runs the full setup (venv, deps, .env from example, sample
   data, pipeline, corpus index) and prints the API/frontend URLs at the end.
4. git init with a sensible .gitignore (exclude .venv, node_modules, chroma_db, and *.db
   EXCEPT the intentionally seeded demo DBs, plus data/uploads/*). Make the first commit.
5. Sanity-check prod hardening: API_KEY required for writes, APP_ENV=prod disables reload,
   SQLite WAL is on.

Show me the .gitignore and bootstrap.ps1 before committing.
```

---

## Day 5 — Phase C #1: Multi-file upload

```
Day 5 per the plan. Build multi-file upload, reusing the existing single-upload pipeline.

1. Plan first: show me how POST /api/uploads currently flows (router → upload_service →
   pipeline) so we extend it cleanly rather than duplicating logic.
2. Add multi-file support (either accept a list in /api/uploads or add /api/uploads/batch).
   Run each file through the SAME pipeline and aggregate the diff (new / re-detected / gone)
   across all files into one combined result.
3. Frontend: multi-file drop zone + a combined results panel.
4. Test by uploading 2-3 of the sample scans and showing the aggregated diff.

Don't break the existing single-file path.
```

---

## Day 6 — Phase C #2: Chat-with-finding + tests

```
Day 6 per the plan.

Part 1 — Chat-with-finding:
1. Add POST /api/rag/jobs/{id}/chat that takes a user question, reuses the existing
   retriever + Ollama recommender against that job's context, and returns a grounded answer.
   Reuse as much of recommender.py as possible. Plan the design before coding.
2. Add a simple chat box to the Job Detail page that calls it.

Part 2 — Tests (tests/ is currently empty):
3. Add pytest tests: (a) app smoke test hitting /health and /api/jobs, (b) a score-engine
   unit test with a known input → known expected score, (c) a job-fingerprint determinism
   test (same input → same SHA-256). Run them and get them green.

Show me the test results.
```

---

## Day 7 — Dry-run + freeze

```
Day 7. Final pass.

1. Walk me through a full timed demo dry-run: clean start via bootstrap.ps1, then the
   exact click path (upload → jobs → job detail → AI recommendation → chat → metrics).
2. Flag anything that stalls or looks rough.
3. Help me capture screenshots of each key screen for the report/slides.
4. Tag v1.0 in git.

After this, bug-fixes only.
```

---

## Handy mid-session phrases
- "Plan first, don't edit yet." — forces a diff preview.
- "Run it and show me the actual output." — keeps it honest about whether things work.
- "/clear" — wipe context between days so it doesn't drift.
- "Why did you change X?" — it'll explain; good for the three subtle bug fixes.
