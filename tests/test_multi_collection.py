"""Tests for multi-collection RAG with weighted RRF.

Test classes
------------
TestWeightedRRF
    Unit tests for the weighting logic in multi_collection_search.
    Uses synthetic inputs — no ChromaDB or embedding model required.

TestProvenance
    End-to-end tests:
    - Confirms source_class/source_id flow through the pipeline.
    - Confirms a runbook (weight 1.5) outranks a CVE description (weight 1.0)
      even when the runbook's raw BM25/vector rank is weaker.

Run from repo root:
    pytest tests/test_multi_collection.py -v
    pytest tests/ -k "multi_collection or provenance" -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PLATFORM_DB_PATH", str(ROOT / "data/cache/platform.db"))


# ── Weighted RRF unit tests ───────────────────────────────────────────────────

from rag.hybrid_search import reciprocal_rank_fusion, RRF_K
from rag.multi_collection import _get_weights, _DEFAULT_WEIGHTS


class TestWeightedRRF:
    """Verify that collection weights change the final merged order."""

    def _make_doc(self, doc_id: str, rrf_score: float, source_class: str) -> dict:
        return {
            "id": doc_id, "text": f"text for {doc_id}",
            "metadata": {"source_class": source_class,
                         "source_id":    doc_id.rsplit("_", 1)[0]},
            "distance":     0.1,
            "rrf_score":    rrf_score,
            "source_class": source_class,
            "source_id":    doc_id.rsplit("_", 1)[0],
        }

    def test_runbook_outranks_cve_with_equal_raw_score(self):
        """A runbook with the same raw RRF score beats a CVE description.

        cve doc:     raw_score × 1.0 = 0.01
        runbook doc: raw_score × 1.5 = 0.015  → should rank first
        """
        raw = 1.0 / (RRF_K + 1)   # rank-1 score

        weights = {"cve_descriptions": 1.0, "vendor_advisories": 1.2, "internal_runbooks": 1.5}

        cve_weighted     = raw * weights["cve_descriptions"]
        runbook_weighted = raw * weights["internal_runbooks"]

        assert runbook_weighted > cve_weighted, (
            f"runbook_weighted={runbook_weighted} should exceed cve_weighted={cve_weighted}"
        )

    def test_weights_env_override(self, monkeypatch):
        """RAG_WEIGHT_CVE env var overrides the default."""
        monkeypatch.setenv("RAG_WEIGHT_CVE", "2.5")
        w = _get_weights()
        assert w["cve_descriptions"] == 2.5
        # Others unchanged
        assert w["internal_runbooks"] == _DEFAULT_WEIGHTS["internal_runbooks"]

    def test_weights_caller_override_takes_priority(self, monkeypatch):
        """Caller-supplied override beats both env var and default."""
        monkeypatch.setenv("RAG_WEIGHT_CVE", "2.5")
        w = _get_weights(override={"cve_descriptions": 0.5})
        assert w["cve_descriptions"] == 0.5

    def test_weighted_merge_changes_order(self):
        """When collection weights differ, the merged order should differ
        from the order that equal weights would produce.

        Scenario:
          - doc_A (cve_descriptions) has raw RRF rank 1 → raw score 1/(60+1)
          - doc_B (internal_runbooks) has raw RRF rank 2 → raw score 1/(60+2)

        Without weighting (both 1.0): doc_A > doc_B
        With   weighting (1.5 for runbooks): doc_B_weighted > doc_A_weighted?
          doc_A_weighted = 1/(61) × 1.0 ≈ 0.01639
          doc_B_weighted = 1/(62) × 1.5 ≈ 0.02419  → doc_B wins!
        """
        raw_a = 1.0 / (RRF_K + 1)   # rank 1 in cve_descriptions
        raw_b = 1.0 / (RRF_K + 2)   # rank 2 in internal_runbooks

        w_cve     = _DEFAULT_WEIGHTS["cve_descriptions"]
        w_runbook = _DEFAULT_WEIGHTS["internal_runbooks"]

        weighted_a = raw_a * w_cve
        weighted_b = raw_b * w_runbook

        # Confirm the weight flips the order
        assert raw_a > raw_b,     "doc_A should have the higher raw score"
        assert weighted_b > weighted_a, (
            f"After weighting, doc_B ({weighted_b:.5f}) should beat doc_A ({weighted_a:.5f})"
        )

    def test_invalid_env_var_ignored(self, monkeypatch):
        """A non-numeric env var value is silently ignored."""
        monkeypatch.setenv("RAG_WEIGHT_RUNBOOK", "not_a_number")
        w = _get_weights()
        assert w["internal_runbooks"] == _DEFAULT_WEIGHTS["internal_runbooks"]

    def test_default_weights_values(self):
        """Spot-check the documented default weights."""
        w = _get_weights()
        assert w["cve_descriptions"]  == 1.0
        assert w["vendor_advisories"] == 1.2
        assert w["internal_runbooks"] == 1.5


# ── Provenance / source_class flow tests ─────────────────────────────────────

class TestProvenance:
    """Verify source_class / source_id propagate correctly."""

    def test_infer_source_class_nvd(self):
        from rag.hybrid_search import _infer_source_class
        assert _infer_source_class("data/rag_corpus/nvd_advisories/CVE-2024-3400.txt") == "cve_descriptions"

    def test_infer_source_class_cisa(self):
        from rag.hybrid_search import _infer_source_class
        assert _infer_source_class("data/rag_corpus/cisa_kev_notes/CVE-2024-3400.txt") == "cve_descriptions"

    def test_infer_source_class_vendor(self):
        from rag.hybrid_search import _infer_source_class
        assert _infer_source_class("data/rag_corpus/vendor_advisories/RHSA-2024-1234.txt") == "vendor_advisories"

    def test_infer_source_class_runbook(self):
        from rag.hybrid_search import _infer_source_class
        assert _infer_source_class("data/runbooks/patch-management.txt") == "internal_runbooks"

    def test_infer_source_class_default(self):
        from rag.hybrid_search import _infer_source_class
        assert _infer_source_class("") == "cve_descriptions"

    def test_infer_source_id_strips_chunk_suffix(self):
        from rag.hybrid_search import _infer_source_id
        assert _infer_source_id("CVE-2024-3400_0")        == "CVE-2024-3400"
        assert _infer_source_id("patch-management_1")     == "patch-management"
        assert _infer_source_id("RHSA-2024-1234_12")      == "RHSA-2024-1234"

    def test_infer_source_id_no_suffix(self):
        from rag.hybrid_search import _infer_source_id
        assert _infer_source_id("plain-name") == "plain-name"

    def test_build_citations_deduplicates(self):
        """_build_citations() should deduplicate by (source_class, source_id)."""
        from rag.recommender import _build_citations
        chunks = [
            {"text": "text1", "metadata": {"source_class": "cve_descriptions", "source_id": "CVE-2024-0001"}},
            {"text": "text2", "metadata": {"source_class": "cve_descriptions", "source_id": "CVE-2024-0001"}},  # dup
            {"text": "text3", "metadata": {"source_class": "internal_runbooks", "source_id": "patch-management"}},
        ]
        citations = _build_citations(chunks)
        assert len(citations) == 2
        classes = {c["source_class"] for c in citations}
        assert "cve_descriptions"  in classes
        assert "internal_runbooks" in classes

    def test_build_citations_skips_missing_fields(self):
        """Chunks without source_class or source_id are excluded."""
        from rag.recommender import _build_citations
        chunks = [
            {"text": "has both",  "metadata": {"source_class": "cve_descriptions", "source_id": "CVE-X"}},
            {"text": "no class",  "metadata": {"source_id": "CVE-Y"}},
            {"text": "no id",     "metadata": {"source_class": "vendor_advisories"}},
            {"text": "no meta",   "metadata": {}},
        ]
        citations = _build_citations(chunks)
        assert len(citations) == 1
        assert citations[0]["source_id"] == "CVE-X"

    def test_build_citations_snippet_truncated(self):
        """Snippet is truncated to 200 characters."""
        from rag.recommender import _build_citations
        long_text = "x" * 500
        chunks = [{"text": long_text, "metadata": {"source_class": "cve_descriptions", "source_id": "CVE-A"}}]
        citations = _build_citations(chunks)
        assert len(citations[0]["snippet"]) <= 200


# ── End-to-end weighted ranking test ─────────────────────────────────────────

class TestWeightedRankingE2E:
    """Confirm a runbook ranks above a CVE description after weighting.

    Mocks the per-collection search so the test runs without ChromaDB/GPU.
    The runbook doc is given a weaker raw RRF score (rank 5) than the CVE
    doc (rank 1), but after the 1.5× multiplier it should finish first.
    """

    def test_runbook_beats_cve_after_weighting(self):
        from rag.multi_collection import multi_collection_search, _search_one_collection
        from rag.hybrid_search import RetrievedDoc

        # CVE doc: rank 1 in cve_descriptions → raw score 1/(60+1)
        cve_score = 1.0 / (RRF_K + 1)
        # Runbook doc: rank 5 in internal_runbooks → raw score 1/(60+5)
        runbook_raw_score = 1.0 / (RRF_K + 5)

        cve_doc = RetrievedDoc(
            id="CVE-2024-0001_0", text="CVE text",
            metadata={"source_class": "cve_descriptions", "source_id": "CVE-2024-0001"},
            distance=0.1, rrf_score=cve_score,
            source_class="cve_descriptions", source_id="CVE-2024-0001",
        )
        runbook_doc = RetrievedDoc(
            id="patch-management_0", text="Runbook text",
            metadata={"source_class": "internal_runbooks", "source_id": "patch-management"},
            distance=0.2, rrf_score=runbook_raw_score,
            source_class="internal_runbooks", source_id="patch-management",
        )

        def fake_search(query, collection_name, k):
            if collection_name == "cve_descriptions":
                return [cve_doc]
            if collection_name == "internal_runbooks":
                return [runbook_doc]
            return []

        with patch("rag.multi_collection._search_one_collection", side_effect=fake_search):
            results = multi_collection_search("patch vulnerability", k=10)

        assert len(results) >= 2, "Should have at least 2 results"

        ids_in_order = [r["id"] for r in results]
        runbook_rank = ids_in_order.index("patch-management_0")
        cve_rank     = ids_in_order.index("CVE-2024-0001_0")

        # Default weights: runbook 1.5 > cve 1.0
        # runbook_weighted = 1/(60+5) × 1.5 ≈ 0.02308
        # cve_weighted     = 1/(60+1) × 1.0 ≈ 0.01639
        assert runbook_rank < cve_rank, (
            f"Runbook (rank {runbook_rank}) should beat CVE (rank {cve_rank}) "
            f"after weighting (raw cve_score={cve_score:.5f} > runbook_raw={runbook_raw_score:.5f})"
        )

    def test_equal_weight_preserves_raw_order(self):
        """With all weights = 1.0, the doc with the higher raw score stays first."""
        from rag.multi_collection import multi_collection_search
        from rag.hybrid_search import RetrievedDoc

        high_score = 1.0 / (RRF_K + 1)
        low_score  = 1.0 / (RRF_K + 5)

        cve_doc = RetrievedDoc(
            id="CVE-2024-0001_0", text="cve text",
            metadata={"source_class": "cve_descriptions", "source_id": "CVE-2024-0001"},
            distance=0.1, rrf_score=high_score,
            source_class="cve_descriptions", source_id="CVE-2024-0001",
        )
        runbook_doc = RetrievedDoc(
            id="patch-management_0", text="runbook text",
            metadata={"source_class": "internal_runbooks", "source_id": "patch-management"},
            distance=0.2, rrf_score=low_score,
            source_class="internal_runbooks", source_id="patch-management",
        )

        def fake_search(query, collection_name, k):
            if collection_name == "cve_descriptions":
                return [cve_doc]
            if collection_name == "internal_runbooks":
                return [runbook_doc]
            return []

        all_equal = {"cve_descriptions": 1.0, "vendor_advisories": 1.0, "internal_runbooks": 1.0}

        with patch("rag.multi_collection._search_one_collection", side_effect=fake_search):
            results = multi_collection_search("query", k=10, weights=all_equal)

        ids_in_order = [r["id"] for r in results]
        assert ids_in_order.index("CVE-2024-0001_0") < ids_in_order.index("patch-management_0"), (
            "With equal weights, the higher raw-score doc should rank first"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
