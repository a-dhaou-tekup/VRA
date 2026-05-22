"""score_engine.py — Module 3: Risk Scoring Engine.

5-factor weighted scoring formula:
  CVSS×40 + KEV×20 + EPSS×15 + Criticality×15 + Exposure×10 → 0–100

Outputs: vuln_scored.csv with risk_score, risk_level, score_breakdown columns.
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

import pandas as pd
import yaml

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent
POLICY_PATH = ROOT / "config" / "policy.yaml"
OUTPUT_DIR = ROOT / "data" / "output"


def _load_policy() -> dict:
    with open(POLICY_PATH) as f:
        return yaml.safe_load(f)


def apply_risk_scoring(df: pd.DataFrame, policy: dict) -> pd.DataFrame:
    weights = policy["risk_scoring"]["weights"]
    crit_map = policy["risk_scoring"]["criticality_map"]
    thresholds = policy["risk_scoring"]["thresholds"]

    # Only score rows that have a CVE ID
    cve_mask = df["cve_id"].str.startswith("CVE-", na=False)

    # ── Factor 1: CVSS contribution ──────────────────────────────────────────
    df["cvss_contribution"] = 0.0
    df.loc[cve_mask, "cvss_contribution"] = (
        pd.to_numeric(df.loc[cve_mask, "cvss_base_score"], errors="coerce").fillna(0.0) / 10.0
        * weights["cvss"]
    ).clip(0, weights["cvss"])

    # ── Factor 2: KEV contribution ───────────────────────────────────────────
    df["kev_contribution"] = 0.0
    if "kev_flag" in df.columns:
        df.loc[cve_mask, "kev_contribution"] = (
            pd.to_numeric(df.loc[cve_mask, "kev_flag"], errors="coerce").fillna(0).clip(0, 1)
            * weights["kev"]
        )

    # ── Factor 3: EPSS contribution ──────────────────────────────────────────
    df["epss_contribution"] = 0.0
    if "epss_score" in df.columns:
        df.loc[cve_mask, "epss_contribution"] = (
            pd.to_numeric(df.loc[cve_mask, "epss_score"], errors="coerce").fillna(0.0).clip(0, 1)
            * weights["epss"]
        )

    # ── Factor 4: Asset criticality contribution ─────────────────────────────
    df["criticality_contribution"] = 0.0
    if "criticality" in df.columns:
        crit_mult = df.loc[cve_mask, "criticality"].str.lower().map(crit_map).fillna(0.0)
        df.loc[cve_mask, "criticality_contribution"] = crit_mult * weights["criticality"]

    # ── Factor 5: Internet exposure contribution ─────────────────────────────
    df["exposure_contribution"] = 0.0
    if "internet_exposed" in df.columns:
        exposed = df.loc[cve_mask, "internet_exposed"].astype(str).str.lower().isin(
            ["true", "yes", "1", "y"]
        ).astype(float)
        df.loc[cve_mask, "exposure_contribution"] = exposed * weights["exposure"]

    # ── Total risk score ─────────────────────────────────────────────────────
    factor_cols = [
        "cvss_contribution", "kev_contribution", "epss_contribution",
        "criticality_contribution", "exposure_contribution",
    ]
    df["risk_score"] = 0.0
    df.loc[cve_mask, "risk_score"] = df.loc[cve_mask, factor_cols].sum(axis=1).clip(0, 100).round(2)

    # ── Risk level classification ─────────────────────────────────────────────
    def classify(score: float) -> str:
        if score >= thresholds["critical"]:
            return "CRITICAL"
        if score >= thresholds["high"]:
            return "HIGH"
        if score >= thresholds["medium"]:
            return "MEDIUM"
        return "LOW"

    df["risk_level"] = df["risk_score"].apply(classify)
    df.loc[~cve_mask, "risk_level"] = "INFO"

    # ── Score breakdown JSON (CVE rows only) ──────────────────────────────────
    def make_breakdown(row) -> str | None:
        if not str(row.get("cve_id", "")).startswith("CVE-"):
            return None
        return json.dumps({
            "cvss_contribution": round(row["cvss_contribution"], 2),
            "kev_contribution": round(row["kev_contribution"], 2),
            "epss_contribution": round(row["epss_contribution"], 2),
            "criticality_contribution": round(row["criticality_contribution"], 2),
            "exposure_contribution": round(row["exposure_contribution"], 2),
            "total": round(row["risk_score"], 2),
            "risk_level": row["risk_level"],
        })

    df["score_breakdown"] = df.apply(make_breakdown, axis=1)
    return df


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    vuln_enriched = OUTPUT_DIR / "vuln_enriched.csv"
    vuln_scored = OUTPUT_DIR / "vuln_scored.csv"

    if not vuln_enriched.exists():
        logger.error("vuln_enriched.csv not found. Run build_vuln_enriched.py first.")
        return

    df = pd.read_csv(vuln_enriched, dtype=str)
    policy = _load_policy()

    for col in ("cvss_base_score", "kev_flag", "epss_score"):
        if col not in df.columns:
            df[col] = 0

    df = apply_risk_scoring(df, policy)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(vuln_scored, index=False, quoting=csv.QUOTE_ALL)
    logger.info("vuln_scored.csv written: %d rows → %s", len(df), vuln_scored)

    # Summary
    if "risk_level" in df.columns:
        summary = df[df["cve_id"].str.startswith("CVE-", na=False)]["risk_level"].value_counts()
        logger.info("Risk level distribution:\n%s", summary.to_string())


if __name__ == "__main__":
    main()
