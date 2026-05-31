"""One-off backfill: populate the FTS5 table from existing ChromaDB content.

Run this once on any existing database that was indexed before the hybrid
retrieval feature was added.  Safe to re-run — rows are insert-or-replaced.

Usage:
    python scripts/backfill_fts.py [--batch-size 500] [--dry-run]

The script reads every document from the ``vra_advisories`` ChromaDB
collection in batches and writes them into the SQLite FTS5 table at
``data/cache/rag_fts.db``.  It does NOT re-embed or re-index anything.

Expected runtime: ~5 s for 1 600 chunks on a laptop-class machine.
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
os.environ.setdefault("PLATFORM_DB_PATH", "data/cache/platform.db")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("backfill_fts")


def backfill(batch_size: int = 500, dry_run: bool = False) -> dict:
    """Backfill FTS5 from ChromaDB.  Returns summary stats dict."""
    from rag.indexer import get_collection
    from rag.fts import init_fts_db, write_chunks, chunk_count

    collection = get_collection()
    total_in_chroma = collection.count()
    logger.info("ChromaDB collection 'vra_advisories': %d chunks", total_in_chroma)

    if total_in_chroma == 0:
        logger.warning("ChromaDB is empty — nothing to backfill.")
        return {"status": "empty", "total": 0, "written": 0}

    init_fts_db()
    already_in_fts = chunk_count()
    logger.info("FTS5 currently holds %d chunks", already_in_fts)

    if dry_run:
        logger.info("[dry-run] would write %d chunks — exiting without changes", total_in_chroma)
        return {"status": "dry_run", "total": total_in_chroma, "written": 0}

    written = 0
    offset  = 0
    t0 = time.monotonic()

    # ChromaDB doesn't support OFFSET natively; we iterate via peek-like
    # get() with an incrementing offset simulation using IDs.
    # We fetch all at once (1 600 chunks is fine in memory) then batch-write.
    logger.info("Fetching all documents from ChromaDB…")
    result = collection.get(include=["documents"])   # ids always included

    all_ids  = result.get("ids", [])
    all_docs = result.get("documents", [])

    logger.info("Fetched %d documents; writing to FTS5 in batches of %d…",
                len(all_ids), batch_size)

    for start in range(0, len(all_ids), batch_size):
        batch = list(zip(all_ids[start:start + batch_size],
                         all_docs[start:start + batch_size]))
        n = write_chunks(batch)
        written += n
        logger.info("  Wrote batch %d–%d (%d rows)", start, start + len(batch) - 1, n)

    elapsed = time.monotonic() - t0
    final_count = chunk_count()

    summary = {
        "status":       "ok",
        "total_chroma": total_in_chroma,
        "written":      written,
        "fts_total":    final_count,
        "elapsed_s":    round(elapsed, 2),
    }
    logger.info("Backfill complete: %s", summary)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--batch-size", type=int, default=500,
                    help="Rows per write batch (default: 500)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print what would be done without writing")
    args = ap.parse_args()

    result = backfill(batch_size=args.batch_size, dry_run=args.dry_run)

    print("\nBackfill summary:")
    for k, v in result.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
