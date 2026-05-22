"""epss_ingest.py — FIRST EPSS (Exploit Prediction Scoring System) feed ingestion.

Fetches EPSS scores for a batch of CVE IDs from the FIRST API.
TTL: 30 days per CVE. Batch size limited to avoid URL length issues.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable

import requests

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/1.0/epss"
TTL_DAYS = 30
BATCH_SIZE = 100  # number of CVEs per API call

ROOT = Path(__file__).parent.parent.parent
DB_PATH = ROOT / "data" / "cache" / "enrichment.db"


def _get_conn() -> sqlite3.Connection:
    from enrichment.kev_ingest import _get_conn as base_conn
    return base_conn()


def _needs_update(conn: sqlite3.Connection, cve_id: str) -> bool:
    row = conn.execute(
        "SELECT epss_cached_at FROM cve_context WHERE cve_id=?", (cve_id,)
    ).fetchone()
    if row is None or not row["epss_cached_at"]:
        return True
    try:
        cached = datetime.fromisoformat(row["epss_cached_at"])
        return datetime.now(timezone.utc) - cached > timedelta(days=TTL_DAYS)
    except Exception:
        return True
    row = conn.execute(
        "SELECT epss_cached_at FROM cve_context WHERE cve_id=?", (cve_id,)
    ).fetchone()
    if row is None or not row["epss_cached_at"]:
        return True
    try:
        cached = datetime.fromisoformat(row["epss_cached_at"])
        return datetime.now(timezone.utc) - cached > timedelta(days=TTL_DAYS)
    except Exception:
        return True


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Returns {cve_id: (epss_score, epss_percentile)}."""
    if not cve_ids:
        return {}
    params = {"cve": ",".join(cve_ids)}
    try:
        resp = requests.get(EPSS_API, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        result = {}
        for item in data.get("data", []):
            cid = item.get("cve", "").upper()
            try:
                result[cid] = (float(item.get("epss", 0)), float(item.get("percentile", 0)))
            except (TypeError, ValueError):
                result[cid] = (0.0, 0.0)
        return result
    except Exception as e:
        logger.warning("EPSS batch request failed: %s", e)
        return {}


def enrich_epss(cve_ids: Iterable[str]) -> int:
    conn = _get_conn()
    unique = list(set(cve_ids))
    stale = [c for c in unique if _needs_update(conn, c)]

    if not stale:
        logger.info("EPSS: all %d CVEs are fresh.", len(unique))
        conn.close()
        return 0

    logger.info("EPSS: fetching scores for %d CVEs...", len(stale))
    now = datetime.now(timezone.utc).isoformat()
    updated = 0

    for i in range(0, len(stale), BATCH_SIZE):
        batch = stale[i:i + BATCH_SIZE]
        scores = fetch_epss_batch(batch)
        if not scores:
            logger.warning("EPSS: batch %d-%d returned no data; skipping write.",
                           i, i + len(batch))
            continue
        with conn:
            for cve_id in batch:
                if cve_id not in scores:
                    continue  # don't cache zeros for unknown CVEs
                score, percentile = scores[cve_id]
                conn.execute("""
                    INSERT INTO cve_context (cve_id, epss_score, epss_percentile, epss_cached_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        epss_score=excluded.epss_score,
                        epss_percentile=excluded.epss_percentile,
                        epss_cached_at=excluded.epss_cached_at
                """, (cve_id, score, percentile, now))
                updated += 1
        time.sleep(0.2)  # be polite to the FIRST API

    logger.info("EPSS: updated %d CVEs.", updated)
    conn.close()
    return updated


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    test_cves = sys.argv[1:] or ["CVE-2024-6387", "CVE-2021-44228", "CVE-2023-44487"]
    enrich_epss(test_cves)
