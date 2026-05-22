"""build_vuln_enriched.py — Module 2 entry point.

Joins vuln_raw.csv with enrichment data (KEV, EPSS, NVD) from enrichment.db
and writes vuln_enriched.csv. Also triggers risk scoring (Module 3) inline.
"""
from __future__ import annotations

import csv
import logging
import sqlite3
import sys
from pathlib import Path

import pandas as pd

# Allow running directly from this directory
sys.path.insert(0, str(Path(__file__).parent))

from kev_ingest import fetch_and_cache_kev, DB_PATH
from epss_ingest import enrich_epss
from nvd_ingest import enrich_nvd
from score_engine import apply_risk_scoring, _load_policy

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent
OUTPUT_DIR = ROOT / "data" / "output"

ENRICHED_OUTPUT = OUTPUT_DIR / "vuln_enriched.csv"
SCORED_OUTPUT = OUTPUT_DIR / "vuln_scored.csv"


def load_cve_context(cve_ids: list[str]) -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    placeholders = ",".join("?" * len(cve_ids))
    rows = conn.execute(
        f"SELECT * FROM cve_context WHERE cve_id IN ({placeholders})", cve_ids
    ).fetchall()
    conn.close()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame([dict(r) for r in rows])


def main() -> None:
    vuln_raw = OUTPUT_DIR / "vuln_raw.csv"
    if not vuln_raw.exists():
        logger.error("vuln_raw.csv not found. Run build_vuln_raw.py first.")
        sys.exit(1)

    df = pd.read_csv(vuln_raw, dtype=str).fillna("")
    logger.info("Loaded %d rows from vuln_raw.csv.", len(df))

    # Unique CVE IDs for enrichment
    cve_ids = df[df["cve_id"].str.startswith("CVE-", na=False)]["cve_id"].unique().tolist()
    logger.info("Unique CVEs to enrich: %d", len(cve_ids))

    # ── Step 1: KEV ──────────────────────────────────────────────────────────
    fetch_and_cache_kev()

    # ── Step 2: EPSS ─────────────────────────────────────────────────────────
    if cve_ids:
        enrich_epss(cve_ids)

    # ── Step 3: NVD ──────────────────────────────────────────────────────────
    if cve_ids:
        enrich_nvd(cve_ids)

    # ── Step 4: Join enrichment data ─────────────────────────────────────────
    if cve_ids:
        ctx = load_cve_context(cve_ids)
        if not ctx.empty:
            df = df.merge(
                ctx[["cve_id", "kev_flag", "epss_score", "epss_percentile",
                     "nvd_description", "nvd_cwe"]],
                on="cve_id", how="left",
            )
    for col in ("kev_flag", "epss_score", "epss_percentile"):
        if col not in df.columns:
            df[col] = 0
    df["kev_flag"] = pd.to_numeric(df.get("kev_flag", 0), errors="coerce").fillna(0).astype(int)
    df["epss_score"] = pd.to_numeric(df.get("epss_score", 0), errors="coerce").fillna(0.0)

    # ── Step 5: Write vuln_enriched.csv ──────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(ENRICHED_OUTPUT, index=False, quoting=csv.QUOTE_ALL)
    logger.info("vuln_enriched.csv written: %d rows", len(df))

    # ── Step 6: Risk scoring ──────────────────────────────────────────────────
    policy = _load_policy()
    df = apply_risk_scoring(df, policy)
    df.to_csv(SCORED_OUTPUT, index=False, quoting=csv.QUOTE_ALL)
    logger.info("vuln_scored.csv written: %d rows", len(df))

    cve_df = df[df["cve_id"].str.startswith("CVE-", na=False)]
    logger.info("Risk distribution:\n%s",
                cve_df["risk_level"].value_counts().to_string() if not cve_df.empty else "N/A")


if __name__ == "__main__":
    main()
