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

---

## Multi-collection RAG

### Updated Pipeline

```
job metadata
    │
    ▼
build_hybrid_query()          (CVE IDs + product + risk level)
    │
    ▼
multi_collection_search(query, k=50)      ← src/rag/multi_collection.py
  │
  ├── _search_one_collection("cve_descriptions",  k=50)
  │     ├── ChromaDB vector search  (top 50)
  │     ├── FTS5 BM25 search        (top 50, source_class filter)
  │     └── RRF fusion              → ranked list, scores × 1.0 (weight)
  │
  ├── _search_one_collection("vendor_advisories", k=50)
  │     └── … same pattern …       → ranked list, scores × 1.2
  │
  ├── _search_one_collection("internal_runbooks", k=50)
  │     └── … same pattern …       → ranked list, scores × 1.5
  │
  └── Global merge: sort all docs by weighted RRF score (descending)
    │
    ▼
rerank(query, candidates, top_n=5)        ← src/rag/reranker.py
    │                                         (cross-encoder, lazy load)
    ▼
build_prompt(job, chunks)                 ← src/rag/recommender.py
  · Each chunk prefixed with [source_class:source_id] citation tag
  · System prompt instructs LLM to cite inline
    │
    ▼
Ollama / qwen2.5:14b
    │
    ▼
JSON recommendation  +  citations[]  +  _meta{}
```

### Three Collections

| Collection | Content | Weight | Source directories |
|---|---|---|---|
| `cve_descriptions` | NVD/MITRE CVE entries, CISA KEV notes | **1.0** | `data/rag_corpus/nvd_advisories/`, `data/rag_corpus/cisa_kev_notes/` |
| `vendor_advisories` | Red Hat, Microsoft, Debian advisories | **1.2** | `data/rag_corpus/vendor_advisories/` |
| `internal_runbooks` | Internal patch runbooks, asset-specific SOPs | **1.5** | `data/runbooks/` |

The legacy `vra_advisories` collection is preserved for A/B inspection.

### Weight Semantics

After per-collection RRF fusion, each document's score is multiplied by its
collection's weight before the global merge sort.  This means an internal
runbook at raw rank 5 (score `1/(60+5) × 1.5 ≈ 0.0231`) beats a CVE at raw
rank 1 (score `1/(60+1) × 1.0 ≈ 0.0164`).

Override weights at runtime:

```bash
RAG_WEIGHT_CVE=1.0      # default
RAG_WEIGHT_ADVISORY=1.2 # default
RAG_WEIGHT_RUNBOOK=1.5  # default
```

Or toggle the whole feature:

```yaml
# config/policy.yaml
rag:
  RAG_USE_MULTI_COLLECTION: false   # falls back to single-collection hybrid_search
```

### Citation Format

Every retrieved chunk carries `source_class` and `source_id` in its metadata.
The prompt instructs the LLM to cite inline as:

```
[cve_descriptions:CVE-2024-3400]
[vendor_advisories:RHSA-2024-1234]
[internal_runbooks:patch-management]
```

The API response always includes a `citations` array:

```json
{
  "citations": [
    {
      "source_class": "cve_descriptions",
      "source_id":    "CVE-2024-3400",
      "snippet":      "CVE: CVE-2024-3400 CWE: CWE-77 Description: …"
    },
    {
      "source_class": "internal_runbooks",
      "source_id":    "patch-management",
      "snippet":      "INTERNAL RUNBOOK: Patch Management …"
    }
  ]
}
```

### Admin Endpoint

```http
GET /api/rag/collections
Authorization: Bearer <admin-or-auditor-token>
```

Returns all four collections (including legacy) with counts and descriptions.
RBAC: `admin` and `auditor` roles only.

### FTS5 Source-Class Filtering

The `rag_chunks_lookup` table carries a `source_class` column added by
`fts.init_fts_db()` (idempotent schema migration).  `bm25_search_by_class()`
JOINs the FTS5 table with the lookup to restrict BM25 results to a single
collection — ensuring per-collection RRF fusion is meaningful.

### Migration

To migrate an existing single-collection database:

```bash
python scripts/migrate_collections.py --dry-run    # inspect classification
python scripts/migrate_collections.py --apply      # write to new collections
```

The migration also updates the FTS5 `source_class` labels for all existing
chunks.  Expected runtime: ~3 s for 1 600 chunks.

### Tests

```bash
pytest tests/test_multi_collection.py -v
pytest tests/ -k "multi_collection or provenance" -v
```

Test classes (18 tests total):
- `TestWeightedRRF` — 6 tests: weight math, env-var override, order-flip proof
- `TestProvenance` — 10 tests: source_class inference, source_id extraction, citation building
- `TestWeightedRankingE2E` — 2 tests: runbook beats CVE after weighting (mocked search); equal-weight preserves raw order

---

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
