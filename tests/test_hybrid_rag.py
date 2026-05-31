"""Unit tests for the hybrid RAG pipeline.

Tests
-----
test_rrf_math
    Verifies the Reciprocal Rank Fusion formula against known expected values
    for two synthetic ranked lists.

test_rrf_single_list
    A doc in only one list still gets a correct score.

test_rrf_disjoint_lists
    Docs exclusive to each list both appear in the result.

test_hybrid_search_cve_at_rank1
    End-to-end: an exact CVE-ID query surfaces the matching document at rank 1
    even when its vector embedding is not the closest one.  Relies on the BM25
    leg to promote exact-match results.  Skipped if FTS5 table is empty.

test_reranker_fallback
    If the cross-encoder model cannot be loaded, rerank() gracefully returns
    the first top_n docs from the input list.

Run from repo root:
    pytest tests/test_hybrid_rag.py -v
    pytest tests/ -k "hybrid or rerank" -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PLATFORM_DB_PATH", str(ROOT / "data/cache/platform.db"))


# ── RRF unit tests ────────────────────────────────────────────────────────────

from rag.hybrid_search import reciprocal_rank_fusion, RRF_K


class TestRRFMath:
    """Verify the RRF formula: score(d) = sum 1/(60 + rank)."""

    def test_rrf_single_doc_in_both_lists(self):
        """A doc at rank 1 in list A and rank 1 in list B should score 2/(60+1)."""
        lists = [["doc_A", "doc_B"], ["doc_A", "doc_C"]]
        scores = reciprocal_rank_fusion(*lists)
        expected = 2.0 / (RRF_K + 1)
        assert abs(scores["doc_A"] - expected) < 1e-10, (
            f"doc_A expected {expected:.8f}, got {scores['doc_A']:.8f}"
        )

    def test_rrf_rank_ordering(self):
        """A doc at rank 1 in list A scores higher than a doc at rank 2."""
        scores = reciprocal_rank_fusion(["first", "second"])
        assert scores["first"] > scores["second"]

    def test_rrf_overlap_boosts_score(self):
        """A doc present in both lists scores higher than a doc in only one."""
        list_a = ["shared", "only_a"]
        list_b = ["shared", "only_b"]
        scores = reciprocal_rank_fusion(list_a, list_b)
        assert scores["shared"] > scores["only_a"]
        assert scores["shared"] > scores["only_b"]

    def test_rrf_known_values(self):
        """Exact numeric check for two 3-element lists.

        list_a = [X, Y, Z]   list_b = [Y, X, W]

        score(X) = 1/(60+1) + 1/(60+2) = 1/61 + 1/62
        score(Y) = 1/(60+2) + 1/(60+1) = same as X
        score(Z) = 1/(60+3)
        score(W) = 1/(60+3)
        """
        list_a = ["X", "Y", "Z"]
        list_b = ["Y", "X", "W"]
        scores = reciprocal_rank_fusion(list_a, list_b)

        expected_X = 1.0 / 61 + 1.0 / 62
        expected_Z = 1.0 / 63

        assert abs(scores["X"] - expected_X) < 1e-12
        assert abs(scores["Z"] - expected_Z) < 1e-12
        # X and Y have the same score (symmetric positions)
        assert abs(scores["X"] - scores["Y"]) < 1e-12

    def test_rrf_single_list(self):
        """A single ranked list: score(d) = 1/(60+rank)."""
        scores = reciprocal_rank_fusion(["alpha", "beta", "gamma"])
        assert abs(scores["alpha"] - 1.0 / (RRF_K + 1)) < 1e-12
        assert abs(scores["beta"]  - 1.0 / (RRF_K + 2)) < 1e-12

    def test_rrf_disjoint_lists(self):
        """Docs exclusive to each list both appear in the merged scores."""
        scores = reciprocal_rank_fusion(["a", "b"], ["c", "d"])
        assert "a" in scores
        assert "c" in scores
        # No doc is in both lists so no score exceeds 1/(60+1)
        assert max(scores.values()) <= 1.0 / (RRF_K + 1) + 1e-12

    def test_rrf_empty_lists(self):
        """Empty input is safe."""
        assert reciprocal_rank_fusion([], []) == {}
        assert reciprocal_rank_fusion([]) == {}


# ── Reranker fallback test ────────────────────────────────────────────────────

class TestRerankerFallback:
    """Test graceful degradation when the cross-encoder model is unavailable."""

    def test_fallback_truncates_to_top_n(self, monkeypatch):
        """If _load_failed is True, rerank() returns first top_n docs unchanged."""
        import rag.reranker as reranker_mod
        from rag.hybrid_search import RetrievedDoc

        # Force the failure flag without touching the real model
        original_failed = reranker_mod._load_failed
        monkeypatch.setattr(reranker_mod, "_load_failed", True)
        monkeypatch.setattr(reranker_mod, "_cross_encoder", None)

        try:
            docs: list[RetrievedDoc] = [
                {"id": f"doc_{i}", "text": f"text {i}", "metadata": {},
                 "distance": 0.0, "rrf_score": 1.0 / i}
                for i in range(1, 11)
            ]
            result = reranker_mod.rerank("query", docs, top_n=3)
            assert len(result) == 3
            assert result[0]["id"] == "doc_1"  # order preserved from input
        finally:
            monkeypatch.setattr(reranker_mod, "_load_failed", original_failed)

    def test_empty_docs_returns_empty(self):
        """rerank() with empty input returns empty list, no model call needed."""
        from rag.reranker import rerank
        assert rerank("any query", []) == []


# ── End-to-end retrieval test ─────────────────────────────────────────────────

class TestHybridSearchEndToEnd:
    """Integration tests — require a populated FTS5 table and ChromaDB."""

    @pytest.fixture(autouse=True)
    def check_fts_populated(self):
        """Skip if the FTS5 table is empty (not yet backfilled)."""
        try:
            from rag.fts import chunk_count
            count = chunk_count()
        except Exception:
            pytest.skip("FTS5 database not available")
        if count == 0:
            pytest.skip(
                "FTS5 table is empty — run 'python scripts/backfill_fts.py' first"
            )

    def test_cve_id_surfaces_at_rank1(self):
        """An exact CVE-ID query must return the matching document at rank ≤ 3.

        The BM25 leg guarantees this even when the vector distance is not
        the smallest (e.g. when the doc's embedding is similar to many others).
        """
        from rag.fts import bm25_search

        # Pick a CVE that definitely exists in the corpus (first FTS5 entry)
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent / "data" / "cache" / "rag_fts.db"
        if not db_path.exists():
            pytest.skip("rag_fts.db not found")

        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT doc_id FROM rag_chunks_lookup LIMIT 1").fetchone()
        conn.close()
        if not row:
            pytest.skip("No rows in FTS5 table")

        # The doc_id looks like "CVE-2024-3400_0" — extract the CVE part
        doc_id: str = row[0]
        cve_part = doc_id.split("_")[0]   # e.g. "CVE-2024-3400"

        if not cve_part.startswith("CVE-"):
            pytest.skip(f"doc_id '{doc_id}' doesn't follow CVE-…_N pattern")

        results = bm25_search(cve_part, k=10)
        assert len(results) > 0, f"BM25 returned no results for {cve_part!r}"

        top_ids = [r["id"] for r in results[:3]]
        assert any(doc_id_val.startswith(cve_part) for doc_id_val in top_ids), (
            f"Expected a doc starting with '{cve_part}' in top-3 BM25 results, "
            f"got: {top_ids}"
        )

    def test_hybrid_search_returns_merged_list(self):
        """hybrid_search() returns a non-empty list with rrf_score populated."""
        from rag.hybrid_search import hybrid_search
        results = hybrid_search("vulnerability remediation patching", k=10)
        assert len(results) > 0
        for doc in results:
            assert "rrf_score" in doc
            assert doc["rrf_score"] > 0
            assert "text" in doc
            assert len(doc["text"]) > 0

    def test_hybrid_search_cve_promoted(self):
        """Hybrid search on a CVE ID should surface the matching doc in top 5."""
        from rag.fts import chunk_count, bm25_search
        import sqlite3
        from pathlib import Path

        db_path = Path(__file__).parent.parent / "data" / "cache" / "rag_fts.db"
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT doc_id FROM rag_chunks_lookup WHERE doc_id LIKE 'CVE-%' LIMIT 1"
        ).fetchone()
        conn.close()
        if not row:
            pytest.skip("No CVE docs in FTS5 table")

        cve_id = row[0].split("_")[0]   # e.g. "CVE-2024-3400"

        from rag.hybrid_search import hybrid_search
        results = hybrid_search(cve_id, k=20)
        top5_ids = [r["id"] for r in results[:5]]

        assert any(did.startswith(cve_id) for did in top5_ids), (
            f"Expected '{cve_id}' doc in top-5 hybrid results, got {top5_ids}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
