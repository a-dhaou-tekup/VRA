"""epss_ingest.py — FIRST EPSS (Exploit Prediction Scoring System) feed ingestion.

Primary source: Cyentia bulk CSV (https://epss.cyentia.com/epss_scores-current.csv.gz)
  - Full daily snapshot of all scored CVEs (~250 k rows, ~10 MB gzipped)
  - Cached locally for CSV_CACHE_TTL hours to avoid re-downloading on every scan

Fallback: FIRST API v1 (https://api.first.org/data/1.0/epss)
  - Per-CVE queries — used if the CSV is unavailable
  - NOTE: as of 2026 this endpoint returns 404 "permanently disabled";
    the CSV path is the only reliable option.

TTL: 30 days per CVE in the local enrichment.db cache.
"""
from __future__ import annotations

import gzip
import io
import logging
import shutil
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable

import requests

logger = logging.getLogger(__name__)

EPSS_API    = "https://api.first.org/data/1.0/epss"   # kept for reference / fallback
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

TTL_DAYS      = 30   # per-CVE cache TTL in enrichment.db
CSV_CACHE_TTL = 24   # hours before re-downloading the bulk CSV
BATCH_SIZE    = 50   # CVEs per API call (fallback path only)

ROOT            = Path(__file__).parent.parent.parent
DB_PATH         = ROOT / "data" / "cache" / "enrichment.db"
CSV_CACHE_PATH  = ROOT / "data" / "cache" / "epss_scores_cache.csv.gz"


# ── DB helpers ────────────────────────────────────────────────────────────────

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


# ── Bulk CSV (primary path) ───────────────────────────────────────────────────

def _csv_is_fresh() -> bool:
    """Return True when the local CSV cache file is younger than CSV_CACHE_TTL hours."""
    if not CSV_CACHE_PATH.exists():
        return False
    age_h = (datetime.now(timezone.utc) - datetime.fromtimestamp(
        CSV_CACHE_PATH.stat().st_mtime, tz=timezone.utc
    )).total_seconds() / 3600
    return age_h < CSV_CACHE_TTL


def _download_epss_csv() -> bool:
    """Download the Cyentia bulk CSV to CSV_CACHE_PATH.  Returns True on success."""
    CSV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CSV_CACHE_PATH.with_suffix(".tmp")
    try:
        logger.info("EPSS: downloading bulk CSV from %s …", EPSS_CSV_URL)
        resp = requests.get(EPSS_CSV_URL, timeout=120, stream=True)
        resp.raise_for_status()
        with open(tmp, "wb") as fh:
            shutil.copyfileobj(resp.raw, fh)
        tmp.replace(CSV_CACHE_PATH)
        logger.info("EPSS: bulk CSV cached at %s", CSV_CACHE_PATH)
        return True
    except Exception as exc:
        logger.warning("EPSS bulk CSV download failed: %s", exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return False


def fetch_epss_from_csv(cve_ids: Iterable[str]) -> dict[str, tuple[float, float]]:
    """Return {cve_id: (epss_score, epss_percentile)} by scanning the local CSV cache.

    Downloads the CSV first if absent or stale.
    """
    wanted = {c.upper() for c in cve_ids if c}
    if not wanted:
        return {}

    if not _csv_is_fresh():
        if not _download_epss_csv():
            return {}

    if not CSV_CACHE_PATH.exists():
        return {}

    result: dict[str, tuple[float, float]] = {}
    try:
        with gzip.open(CSV_CACHE_PATH, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("cve,"):
                    continue
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                cve_id = parts[0].upper()
                if cve_id in wanted:
                    try:
                        result[cve_id] = (float(parts[1]), float(parts[2]))
                    except (ValueError, IndexError):
                        pass
                    if len(result) == len(wanted):
                        break  # found everything we need — stop early
        logger.info("EPSS CSV: matched %d / %d CVEs", len(result), len(wanted))
        return result
    except Exception as exc:
        logger.warning("EPSS CSV parse failed: %s", exc)
        return {}


# ── Per-CVE API (fallback) ────────────────────────────────────────────────────

def fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Return {cve_id: (epss_score, epss_percentile)} via the FIRST API (fallback path).

    NOTE: The FIRST API v1 endpoint was permanently disabled circa 2025/2026.
    This function is kept for forward-compatibility but will return {} if the
    endpoint remains unavailable.  Use fetch_epss_from_csv for reliable data.
    """
    if not cve_ids:
        return {}
    # Construct URL with raw commas — requests.get(params=...) encodes them as
    # %2C which the API treats as a single invalid ID.
    url = f"{EPSS_API}?cve={','.join(cve_ids)}"
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 404:
            logger.debug("EPSS API: 404 for batch — endpoint may be disabled")
            return {}
        resp.raise_for_status()
        result: dict[str, tuple[float, float]] = {}
        for item in resp.json().get("data", []):
            cid = item.get("cve", "").upper()
            try:
                result[cid] = (float(item.get("epss", 0)), float(item.get("percentile", 0)))
            except (TypeError, ValueError):
                result[cid] = (0.0, 0.0)
        return result
    except requests.exceptions.RequestException as exc:
        logger.warning("EPSS API batch request failed: %s", exc)
        return {}


# ── Main entry point ──────────────────────────────────────────────────────────

def enrich_epss(cve_ids: Iterable[str], force: bool = False) -> int:
    """Fetch and cache EPSS scores for the supplied CVE IDs.

    Strategy:
      1. Try the Cyentia bulk CSV (fast, complete, downloaded once per day).
      2. Fall back to FIRST API per-batch for any CVEs still missing.

    Args:
        cve_ids: Iterable of CVE-YYYY-NNNNN strings.
        force:   Bypass the 30-day per-CVE TTL and always re-fetch.
    """
    conn = _get_conn()
    unique = [c for c in set(cve_ids) if c and c.startswith("CVE-")]

    if force:
        stale = unique
    else:
        stale = [c for c in unique if _needs_update(conn, c)]

    if not stale:
        logger.info("EPSS: all %d CVEs are fresh (force=%s).", len(unique), force)
        conn.close()
        return 0

    logger.info("EPSS: enriching %d CVEs …", len(stale))
    now = datetime.now(timezone.utc).isoformat()
    updated = 0

    # ── Step 1: bulk CSV (primary) ────────────────────────────────────────────
    csv_scores = fetch_epss_from_csv(stale)
    if csv_scores:
        with conn:
            for cve_id, (score, percentile) in csv_scores.items():
                conn.execute(
                    """INSERT INTO cve_context
                           (cve_id, epss_score, epss_percentile, epss_cached_at)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(cve_id) DO UPDATE SET
                           epss_score      = excluded.epss_score,
                           epss_percentile = excluded.epss_percentile,
                           epss_cached_at  = excluded.epss_cached_at""",
                    (cve_id, score, percentile, now),
                )
                updated += 1
        logger.info("EPSS: wrote %d scores from bulk CSV.", updated)

    # ── Step 2: API fallback for any CVEs still missing ───────────────────────
    still_missing = [c for c in stale if c not in csv_scores]
    if still_missing:
        logger.info("EPSS: %d CVEs not in CSV — trying API fallback …", len(still_missing))
        for i in range(0, len(still_missing), BATCH_SIZE):
            batch = still_missing[i:i + BATCH_SIZE]
            scores = fetch_epss_batch(batch)
            if not scores:
                continue
            with conn:
                for cve_id, (score, percentile) in scores.items():
                    conn.execute(
                        """INSERT INTO cve_context
                               (cve_id, epss_score, epss_percentile, epss_cached_at)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(cve_id) DO UPDATE SET
                               epss_score      = excluded.epss_score,
                               epss_percentile = excluded.epss_percentile,
                               epss_cached_at  = excluded.epss_cached_at""",
                        (cve_id, score, percentile, now),
                    )
                    updated += 1
            time.sleep(0.2)

    # ── Metadata ──────────────────────────────────────────────────────────────
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS epss_meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.execute(
            "INSERT OR REPLACE INTO epss_meta (key, value) VALUES ('last_attempted', ?)", (now,)
        )
        if updated > 0:
            conn.execute(
                "INSERT OR REPLACE INTO epss_meta (key, value) VALUES ('last_fetched', ?)", (now,)
            )
        conn.commit()
    except Exception as exc:
        logger.debug("Could not write epss_meta: %s", exc)

    logger.info("EPSS: enrichment complete — %d scores written.", updated)
    conn.close()
    return updated


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    test_cves = sys.argv[1:] or ["CVE-2024-6387", "CVE-2021-44228", "CVE-2023-44487"]
    n = enrich_epss(test_cves)
    print(f"Enriched: {n}")
