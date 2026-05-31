"""nvd_ingest.py — NVD API v2 CVE description and CVSS ingestion.

Fetches CVE descriptions and CWE IDs from the NVD API.
Also writes .txt files to the RAG corpus for each CVE.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable

import requests

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TTL_DAYS = 90
REQUEST_DELAY = 0.7  # NVD free tier: max ~50 req/30s without API key

ROOT = Path(__file__).parent.parent.parent
DB_PATH = ROOT / "data" / "cache" / "enrichment.db"
RAG_NVD_DIR = ROOT / "data" / "rag_corpus" / "nvd_advisories"


def _get_conn() -> sqlite3.Connection:
    from enrichment.kev_ingest import _get_conn as base_conn
    return base_conn()


def write_nvd_to_rag_corpus(cve_id: str, description: str, cwe_ids: list[str]) -> None:
    RAG_NVD_DIR.mkdir(parents=True, exist_ok=True)
    path = RAG_NVD_DIR / f"{cve_id}.txt"
    if path.exists():
        return
    content = (
        f"CVE: {cve_id}\n"
        f"CWE: {', '.join(cwe_ids) if cwe_ids else 'N/A'}\n\n"
        f"Description:\n{description}\n"
    )
    path.write_text(content, encoding="utf-8")
    logger.debug("RAG corpus: wrote %s", path.name)


def fetch_nvd_cve(cve_id: str) -> dict:
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve_data = vulns[0].get("cve", {})

        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # CWE IDs
        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe = desc.get("value", "")
                if cwe.startswith("CWE-"):
                    cwe_ids.append(cwe)

        return {"description": description, "cwe_ids": cwe_ids}
    except Exception as e:
        logger.warning("NVD fetch failed for %s: %s", cve_id, e)
        return {}


def enrich_nvd(cve_ids: Iterable[str], force: bool = False) -> int:
    """Fetch NVD descriptions and CWE IDs for the supplied CVE IDs.

    Args:
        cve_ids: Iterable of CVE-YYYY-NNNNN strings.
        force:   When True, bypass the 90-day TTL and always re-fetch from
                 the NVD API. Use this for manual refresh requests.
    """
    conn = _get_conn()
    unique = [c for c in set(cve_ids) if c and c.startswith("CVE-")]
    now_ts = datetime.now(timezone.utc)

    if force:
        stale = unique
    else:
        stale = []
        for cve_id in unique:
            row = conn.execute(
                "SELECT nvd_cached_at FROM cve_context WHERE cve_id=?", (cve_id,)
            ).fetchone()
            if row is None or not row["nvd_cached_at"]:
                stale.append(cve_id)
            else:
                try:
                    cached = datetime.fromisoformat(row["nvd_cached_at"])
                    if now_ts - cached > timedelta(days=TTL_DAYS):
                        stale.append(cve_id)
                except Exception:
                    stale.append(cve_id)

    if not stale:
        logger.info("NVD: all %d CVEs are fresh (force=%s).", len(unique), force)
        conn.close()
        return 0

    logger.info("NVD: fetching descriptions for %d CVEs...", len(stale))
    now = now_ts.isoformat()
    updated = 0

    for cve_id in stale:
        data = fetch_nvd_cve(cve_id)
        description = data.get("description", "")
        cwe_ids = data.get("cwe_ids", [])
        with conn:
            conn.execute("""
                INSERT INTO cve_context (cve_id, nvd_description, nvd_cwe, nvd_cached_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    nvd_description=excluded.nvd_description,
                    nvd_cwe=excluded.nvd_cwe,
                    nvd_cached_at=excluded.nvd_cached_at
            """, (cve_id, description, json.dumps(cwe_ids), now))
        if description:
            write_nvd_to_rag_corpus(cve_id, description, cwe_ids)
        updated += 1
        time.sleep(REQUEST_DELAY)

    logger.info("NVD: updated %d CVEs.", updated)
    conn.close()
    return updated


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    test_cves = sys.argv[1:] or ["CVE-2024-6387", "CVE-2021-44228"]
    enrich_nvd(test_cves)
