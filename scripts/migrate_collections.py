"""One-off migration: split ``vra_advisories`` into three typed collections.

Reads every document from the legacy ``vra_advisories`` ChromaDB collection,
infers which new collection it belongs to, and upserts it into the correct
target collection with ``source_class`` and ``source_id`` metadata added.

The legacy collection is NOT deleted — it remains intact so you can diff
the old and new collections side-by-side after migration.

Classification heuristic
------------------------
The heuristic is applied to ``metadata["source_file"]`` (the full filesystem
path stored when the file was indexed).  If that field is absent, the doc_id
is used as a fallback.

  Path contains ``vendor_advisories``  → vendor_advisories
  Path contains ``runbooks``           → internal_runbooks
  Path contains ``nvd_advisories``     → cve_descriptions    (explicit)
  Path contains ``cisa_kev_notes``     → cve_descriptions    (explicit)
  Anything else                        → cve_descriptions    (safe default)

The same heuristic is used by:
  - ``rag.indexer.infer_collection_for_file()``
  - ``rag.hybrid_search._infer_source_class()``

Keeping a single canonical heuristic in three places is intentional: each
caller needs it at import time without depending on the others.

Usage
-----
  python scripts/migrate_collections.py --dry-run   # inspect counts only
  python scripts/migrate_collections.py --apply     # run the migration
  python scripts/migrate_collections.py --apply --batch-size 200
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PLATFORM_DB_PATH", str(ROOT / "data/cache/platform.db"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("migrate_collections")


# ── Heuristic ─────────────────────────────────────────────────────────────────

def _infer_class(source_file: str, doc_id: str) -> str:
    """Return the target collection name for a single document.

    See module docstring for the full heuristic rationale.
    """
    probe = (source_file or doc_id).replace("\\", "/").lower()
    if "vendor_advisories" in probe:
        return "vendor_advisories"
    if "runbooks" in probe:
        return "internal_runbooks"
    return "cve_descriptions"


def _infer_source_id(doc_id: str) -> str:
    """Strip the trailing ``_N`` chunk suffix from a doc_id."""
    parts = doc_id.rsplit("_", 1)
    return parts[0] if len(parts) == 2 and parts[1].isdigit() else doc_id


# ── Migration logic ───────────────────────────────────────────────────────────

def classify_documents(
    legacy_ids: list[str],
    legacy_docs: list[str],
    legacy_metas: list[dict],
) -> dict[str, list[tuple[str, str, dict]]]:
    """Group documents by inferred target collection.

    Returns a dict: collection_name → list of (id, text, enriched_metadata).
    """
    groups: dict[str, list] = {
        "cve_descriptions":  [],
        "vendor_advisories": [],
        "internal_runbooks": [],
    }

    for doc_id, text, meta in zip(legacy_ids, legacy_docs, legacy_metas):
        source_file = meta.get("source_file", "")
        col_name    = _infer_class(source_file, doc_id)
        source_id   = meta.get("source_id") or _infer_source_id(doc_id)

        enriched_meta = {
            **meta,
            "source_class": col_name,
            "source_id":    source_id,
        }
        groups[col_name].append((doc_id, text, enriched_meta))

    return groups


def migrate(batch_size: int = 500, dry_run: bool = False) -> dict:
    """Run the migration.  Returns a summary dict."""
    from rag.indexer import get_named_collection, get_embedder, COLLECTION_LEGACY
    from rag.fts import write_chunks as fts_write, _get_conn as fts_conn

    # ── Read the legacy collection ─────────────────────────────────────────────
    legacy = get_named_collection(COLLECTION_LEGACY)
    total  = legacy.count()
    logger.info("Legacy collection '%s': %d documents", COLLECTION_LEGACY, total)

    if total == 0:
        logger.warning("Legacy collection is empty — nothing to migrate.")
        return {"status": "empty", "total": 0}

    logger.info("Fetching all documents from legacy collection…")
    result = legacy.get(include=["documents", "metadatas", "embeddings"])

    ids       = result.get("ids", [])
    docs      = result.get("documents", [])
    metas     = result.get("metadatas", [])
    embeddings = result.get("embeddings", [])

    logger.info("Fetched %d documents.  Classifying…", len(ids))
    groups = classify_documents(ids, docs, metas)

    # ── Print dry-run summary ─────────────────────────────────────────────────
    for col_name, items in groups.items():
        logger.info("  %-22s → %d documents", col_name, len(items))

    if dry_run:
        logger.info("[dry-run] No changes written.")
        return {
            "status":   "dry_run",
            "total":    total,
            "groups":   {k: len(v) for k, v in groups.items()},
        }

    # ── Apply: upsert into each target collection ─────────────────────────────
    t0 = time.monotonic()
    emb_map = {doc_id: emb for doc_id, emb in zip(ids, embeddings)} if embeddings is not None and len(embeddings) > 0 else {}

    written: dict[str, int] = {}
    fts_rows_by_class: dict[str, list[tuple[str, str]]] = {}

    for col_name, items in groups.items():
        if not items:
            written[col_name] = 0
            continue

        collection = get_named_collection(col_name)
        fts_rows   = []

        for start in range(0, len(items), batch_size):
            batch = items[start : start + batch_size]
            b_ids   = [x[0] for x in batch]
            b_docs  = [x[1] for x in batch]
            b_metas = [x[2] for x in batch]

            kwargs: dict = dict(ids=b_ids, documents=b_docs, metadatas=b_metas)
            # Re-use existing embeddings when available to avoid re-computing
            if emb_map:
                b_embs = [emb_map[i] for i in b_ids if i in emb_map]
                if len(b_embs) == len(b_ids):
                    kwargs["embeddings"] = b_embs
                else:
                    # Partial match — re-embed the whole batch
                    embedder = get_embedder()
                    kwargs["embeddings"] = embedder.encode(b_docs, show_progress_bar=False).tolist()
            else:
                embedder = get_embedder()
                kwargs["embeddings"] = embedder.encode(b_docs, show_progress_bar=False).tolist()

            collection.upsert(**kwargs)
            fts_rows.extend(zip(b_ids, b_docs))
            logger.info("  %s: wrote batch %d–%d", col_name, start, start + len(batch) - 1)

        written[col_name] = len(items)
        fts_rows_by_class[col_name] = fts_rows

    # ── Update FTS5 source_class labels ──────────────────────────────────────
    logger.info("Updating FTS5 source_class labels…")
    for col_name, rows in fts_rows_by_class.items():
        try:
            fts_write(rows, source_class=col_name)
            logger.info("  FTS5[%s]: updated %d rows", col_name, len(rows))
        except Exception as exc:
            logger.warning("  FTS5[%s] update failed (non-fatal): %s", col_name, exc)

    elapsed = time.monotonic() - t0
    summary = {
        "status":    "ok",
        "total":     total,
        "groups":    {k: len(v) for k, v in groups.items()},
        "written":   written,
        "elapsed_s": round(elapsed, 2),
    }
    logger.info("Migration complete: %s", summary)
    return summary


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="Print counts and classification without writing anything")
    ap.add_argument("--apply",   action="store_true",
                    help="Actually run the migration")
    ap.add_argument("--batch-size", type=int, default=500,
                    help="ChromaDB upsert batch size (default: 500)")
    args = ap.parse_args()

    if not args.dry_run and not args.apply:
        ap.print_help()
        sys.exit(0)

    result = migrate(batch_size=args.batch_size, dry_run=args.dry_run)

    print("\nMigration summary:")
    for k, v in result.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
