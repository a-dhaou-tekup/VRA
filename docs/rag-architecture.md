# RAG Architecture

## Pipeline Overview

```
job metadata
    │
    ▼
build_hybrid_query()
  ├── CVE IDs          (exact-match signal for BM25)
  ├── product name     (semantic signal)
  └── risk level
    │
    ▼
hybrid_search(query, k=50)          ← src/rag/hybrid_search.py
  ├── ChromaDB vector search  (top 50)   ← all-MiniLM-L6-v2 embeddings
  │       results: [(id, text, metadata, distance), ...]
  │
  ├── FTS5 BM25 search        (top 50)   ← src/rag/fts.py (rag_fts.db)
  │       results: [(id, text, bm25_score), ...]
  │
  └── Reciprocal Rank Fusion             ← RRF_K = 60
        score(d) = Σ 1 / (60 + rank_in_list)
        merged: up to 100 unique docs, sorted by descending RRF score
    │
    ▼
rerank(query, candidates, top_n=5)  ← src/rag/reranker.py
  model: cross-encoder/ms-marco-MiniLM-L-6-v2  (~80 MB, lazy load)
  input:  up to 50 merged docs
  output: 5 docs sorted by cross-encoder relevance score
    │
    ▼
build_prompt(job, chunks)           ← src/rag/recommender.py
  5 advisory chunks injected into LLM context window
    │
    ▼
Ollama / qwen2.5:14b
    │
    ▼
JSON recommendation
```

## Feature Flag

`config/policy.yaml` → `rag.RAG_USE_HYBRID` (default: `true`)

| Flag value | Path used |
|---|---|
| `true` | hybrid_search(50) → rerank(5) → prompt |
| `false` | original two-pass ChromaDB (CVE direct + semantic) |

Set `RAG_USE_HYBRID: false` before the A/B comparison on defence day to
compare the two retrieval paths on the same job.

## Components

### `src/rag/fts.py`
- Manages `data/cache/rag_fts.db` (SQLite FTS5, WAL mode)
- Virtual table: `rag_chunks_fts(doc_id UNINDEXED, text)` with Porter stemmer
- `write_chunks(rows)` — bulk insert/replace (called by indexer on every upsert)
- `bm25_search(query, k)` — FTS5 MATCH query returning BM25-ranked results
- FTS5 query sanitiser wraps each token in double-quotes to handle CVE hyphens

### `src/rag/hybrid_search.py`
- `RetrievedDoc` TypedDict: `{id, text, metadata, distance, rrf_score}`
- `reciprocal_rank_fusion(*ranked_lists, k=60)` — pure math, no I/O
- `hybrid_search(query, k=50)` — runs both legs, merges with RRF

### `src/rag/reranker.py`
- Loads `cross-encoder/ms-marco-MiniLM-L-6-v2` lazily on **first call** only
- Falls back gracefully (log warning, return first top_n by RRF) if model
  unavailable — never breaks the advice pipeline
- Model stays resident in memory after first load (~80 MB)

### `src/rag/indexer.py` (modified)
- `index_file()` now calls `fts.write_chunks()` after every ChromaDB upsert
- Non-fatal: FTS5 write failure logs a warning and does not abort indexing

### `src/rag/recommender.py` (modified)
- `generate_recommendation(job)` checks `RAG_USE_HYBRID` on each call
- Hybrid path logs: `finding.advise [hybrid]` with candidate / reranked counts
- Legacy path logs: `finding.advise [legacy]`

## FTS5 Population

### New databases (after this feature)
FTS5 is populated automatically via `indexer.index_file()` during corpus indexing.

### Existing databases (before this feature)
Run the one-off backfill script:
```bash
python scripts/backfill_fts.py
# Options:
#   --batch-size 500   rows per write batch (default 500)
#   --dry-run          inspect without writing
```
Expected: ~0.05 s for 1 600 chunks.

## Unit Tests

```bash
pytest tests/test_hybrid_rag.py -v
pytest tests/ -k "hybrid or rerank" -v
```

Test classes:
- `TestRRFMath` — 7 tests: exact numeric verification of the RRF formula
- `TestRerankerFallback` — 2 tests: graceful degradation when model absent
- `TestHybridSearchEndToEnd` — 3 tests: BM25 CVE rank-1 guarantee, merged
  list shape, hybrid CVE promotion (skipped if FTS5 table empty)

## Acceptance Checklist

```bash
# Re-ranker NOT loaded at startup — grep startup logs, should be absent:
grep "cross-encoder" startup.log   # expect no output

# Tests pass
pytest tests/ -k "hybrid or rerank" -v

# Hybrid path active — logs show both legs + rerank:
grep "hybrid_search\|rerank\|finding.advise" vra.log

# Legacy path toggle works:
# In policy.yaml set RAG_USE_HYBRID: false, restart, re-run advise,
# grep logs for "finding.advise [legacy]"
```
