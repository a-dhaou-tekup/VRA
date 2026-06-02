"""kev_ingest.py — CISA Known Exploited Vulnerabilities feed ingestion.

Fetches the latest KEV JSON from CISA and caches it in enrichment.db.
TTL: 7 days. Also writes text files to the RAG corpus.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TTL_DAYS = 7

ROOT = Path(__file__).parent.parent.parent
DB_PATH = ROOT / "data" / "cache" / "enrichment.db"
RAG_KEV_DIR = ROOT / "data" / "rag_corpus" / "cisa_kev_notes"


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_context (
            cve_id TEXT PRIMARY KEY,
            kev_flag INTEGER DEFAULT 0,
            kev_added_date TEXT,
            kev_vendor TEXT,
            kev_product TEXT,
            kev_required_action TEXT,
            kev_short_description TEXT,
            kev_cached_at TEXT,
            epss_score REAL,
            epss_percentile REAL,
            epss_cached_at TEXT,
            nvd_description TEXT,
            nvd_cwe TEXT,
            nvd_cached_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kev_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    return conn


def _is_stale(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT value FROM kev_meta WHERE key='last_fetched'").fetchone()
    if row is None:
        return True
    try:
        last = datetime.fromisoformat(row["value"])
        return datetime.now(timezone.utc) - last > timedelta(days=TTL_DAYS)
    except Exception:
        return True


def write_kev_to_rag_corpus(cve_id: str, entry: dict) -> None:
    RAG_KEV_DIR.mkdir(parents=True, exist_ok=True)
    path = RAG_KEV_DIR / f"{cve_id}.txt"
    if path.exists():
        return
    content = (
        f"CISA KEV Entry\n"
        f"CVE: {cve_id}\n"
        f"Vendor: {entry.get('vendorProject', '')}\n"
        f"Product: {entry.get('product', '')}\n"
        f"Vulnerability Name: {entry.get('vulnerabilityName', '')}\n"
        f"Date Added: {entry.get('dateAdded', '')}\n"
        f"Required Action: {entry.get('requiredAction', '')}\n"
        f"Due Date: {entry.get('dueDate', '')}\n"
        f"Short Description: {entry.get('shortDescription', '')}\n"
        f"Status: Known Exploited\n"
    )
    path.write_text(content, encoding="utf-8")


def fetch_and_cache_kev(force: bool = False) -> int:
    conn = _get_conn()
    if not force and not _is_stale(conn):
        count = conn.execute("SELECT COUNT(*) FROM cve_context WHERE kev_flag=1").fetchone()[0]
        logger.info("KEV cache is fresh (%d entries). Skipping fetch.", count)
        conn.close()
        return count

    logger.info("Fetching KEV feed from CISA...")
    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.error("Failed to fetch KEV feed: %s", e)
        conn.close()
        return 0

    now = datetime.now(timezone.utc).isoformat()
    entries = data.get("vulnerabilities", [])
    written = 0

    with conn:
        for entry in entries:
            cve_id = entry.get("cveID", "").strip().upper()
            if not cve_id:
                continue
            conn.execute("""
                INSERT INTO cve_context (cve_id, kev_flag, kev_added_date, kev_vendor,
                    kev_product, kev_required_action, kev_short_description, kev_cached_at)
                VALUES (?, 1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    kev_flag=1, kev_added_date=excluded.kev_added_date,
                    kev_vendor=excluded.kev_vendor, kev_product=excluded.kev_product,
                    kev_required_action=excluded.kev_required_action,
                    kev_short_description=excluded.kev_short_description,
                    kev_cached_at=excluded.kev_cached_at
            """, (cve_id, entry.get("dateAdded"), entry.get("vendorProject"),
                  entry.get("product"), entry.get("requiredAction"),
                  entry.get("shortDescription"), now))
            write_kev_to_rag_corpus(cve_id, entry)
            written += 1

        conn.execute("INSERT OR REPLACE INTO kev_meta (key, value) VALUES ('last_fetched', ?)", (now,))

    logger.info("KEV: cached %d entries.", written)
    conn.close()
    return written


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    fetch_and_cache_kev()
