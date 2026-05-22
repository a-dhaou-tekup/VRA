"""build_remediation_jobs.py — Module 4: Job Builder & SLA Engine.

Groups vuln_scored findings into actionable remediation jobs.
Each job covers one (asset, product/package) combination.
Assigns SLA deadlines, SHA-256 fingerprints, and carries score_breakdown JSON.
"""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent
POLICY_PATH = ROOT / "config" / "policy.yaml"
OUTPUT_DIR = ROOT / "data" / "output"

SCORED_INPUT = OUTPUT_DIR / "vuln_scored.csv"
JOBS_OUTPUT = OUTPUT_DIR / "remediation_jobs.csv"

FINAL_OUTPUT_COLUMNS = [
    "job_id", "job_fingerprint", "asset_ids", "cve_list",
    "main_product", "plugin_family",
    "max_risk_level", "risk_score_max",
    "business_owner", "business_unit", "environment",
    "kev_present", "kev_cves",
    "affected_asset_count", "cve_count",
    "score_breakdown",
    "sla_days", "created_at", "due_date",
    "status",
]

RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _load_policy() -> dict:
    with open(POLICY_PATH) as f:
        return yaml.safe_load(f)


def compute_job_fingerprint(asset_ids: list[str], cve_list: list[str]) -> str:
    payload = ",".join(sorted(asset_ids)) + "|" + ",".join(sorted(cve_list))
    return hashlib.sha256(payload.encode()).hexdigest()


def _best_risk_level(levels: pd.Series) -> str:
    if levels.empty:
        return "LOW"
    mapped = levels.map(RISK_ORDER).fillna(0)
    best_label = mapped.idxmax()
    return levels.loc[best_label]


def _derive_product(row: pd.Series) -> str:
    """Extract a meaningful product/package name for job grouping."""
    plugin_name = str(row.get("plugin_name", ""))
    vuln_title = str(row.get("vuln_title", ""))

    # Common product keywords
    for candidate in (plugin_name, vuln_title):
        for keyword in ("Apache", "nginx", "OpenSSL", "OpenSSH", "Django", "Spring",
                        "Log4j", "Windows", "Linux", "Ubuntu", "Debian", "CentOS",
                        "Python", "Node.js", "PHP", "MySQL", "PostgreSQL", "MongoDB",
                        "Cisco", "Fortinet", "Palo Alto", "VMware", "Kubernetes"):
            if keyword.lower() in candidate.lower():
                return keyword
    if plugin_name:
        return plugin_name[:60]
    if vuln_title:
        return vuln_title[:60]
    return str(row.get("plugin_family", "Unknown"))


def build_remediation_jobs(df: pd.DataFrame, policy: dict) -> pd.DataFrame:
    sla_map = policy.get("sla_days", {
        "CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90
    })
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    df["_product"] = df.apply(_derive_product, axis=1)

    # Only group CVE rows; non-CVE findings are included separately
    cve_df = df[df["cve_id"].str.startswith("CVE-", na=False)].copy()

    job_rows: list[dict] = []
    group_keys = ["asset_id", "_product"]

    for (asset_id, product), group in cve_df.groupby(group_keys, dropna=False):
        cve_list = group["cve_id"].dropna().unique().tolist()
        asset_ids = group["asset_id"].dropna().unique().tolist()

        max_risk = _best_risk_level(group["risk_level"])
        risk_score_max = float(pd.to_numeric(group["risk_score"], errors="coerce").max() or 0)

        if "kev_flag" in group.columns:
            kev_cves = group[group["kev_flag"].astype(str).isin(["1", "True", "true"])]["cve_id"].tolist()
        else:
            kev_cves = []
        kev_present = len(kev_cves) > 0

        business_owner = group["business_owner"].iloc[0] if "business_owner" in group.columns else ""
        business_unit = group["business_unit"].iloc[0] if "business_unit" in group.columns else ""
        environment = group["environment"].iloc[0] if "environment" in group.columns else ""
        plugin_family = group["plugin_family"].iloc[0] if "plugin_family" in group.columns else ""

        # Take the worst score_breakdown among the group
        best_breakdown = None
        if "score_breakdown" in group.columns:
            for bd in group["score_breakdown"].dropna():
                try:
                    parsed = json.loads(bd)
                    if best_breakdown is None or parsed.get("total", 0) > json.loads(best_breakdown).get("total", 0):
                        best_breakdown = bd
                except (json.JSONDecodeError, TypeError):
                    pass

        sla_days = sla_map.get(max_risk, 30)
        due_date = (now + timedelta(days=sla_days)).isoformat()
        fingerprint = compute_job_fingerprint(asset_ids, cve_list)

        # Deterministic job ID based on fingerprint
        job_id = f"job-{fingerprint[:8]}"

        job_rows.append({
            "job_id": job_id,
            "job_fingerprint": fingerprint,
            "asset_ids": json.dumps(sorted(asset_ids)),
            "cve_list": json.dumps(sorted(cve_list)),
            "main_product": product,
            "plugin_family": plugin_family,
            "max_risk_level": max_risk,
            "risk_score_max": round(risk_score_max, 2),
            "business_owner": business_owner,
            "business_unit": business_unit,
            "environment": environment,
            "kev_present": kev_present,
            "kev_cves": json.dumps(kev_cves),
            "affected_asset_count": len(asset_ids),
            "cve_count": len(cve_list),
            "score_breakdown": best_breakdown,
            "sla_days": sla_days,
            "created_at": now_iso,
            "due_date": due_date,
            "status": "TO_DO",
        })

    if not job_rows:
        logger.warning("No remediation jobs produced.")
        return pd.DataFrame(columns=FINAL_OUTPUT_COLUMNS)

    jobs_df = pd.DataFrame(job_rows)

    # Deduplicate by fingerprint — keep highest risk
    jobs_df["_risk_order"] = jobs_df["max_risk_level"].map(RISK_ORDER).fillna(0)
    jobs_df = jobs_df.sort_values("_risk_order", ascending=False)
    jobs_df = jobs_df.drop_duplicates(subset="job_fingerprint", keep="first")
    jobs_df = jobs_df.drop(columns=["_risk_order"])

    logger.info("Built %d remediation jobs.", len(jobs_df))
    return jobs_df[FINAL_OUTPUT_COLUMNS]


def main() -> None:
    if not SCORED_INPUT.exists():
        logger.error("vuln_scored.csv not found. Run build_vuln_enriched.py first.")
        sys.exit(1)

    df = pd.read_csv(SCORED_INPUT, dtype=str).fillna("")
    logger.info("Loaded %d rows from vuln_scored.csv.", len(df))

    policy = _load_policy()
    jobs_df = build_remediation_jobs(df, policy)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    jobs_df.to_csv(JOBS_OUTPUT, index=False, quoting=csv.QUOTE_ALL)
    logger.info("remediation_jobs.csv written: %d jobs → %s", len(jobs_df), JOBS_OUTPUT)

    if not jobs_df.empty:
        summary = jobs_df["max_risk_level"].value_counts()
        logger.info("Jobs by risk level:\n%s", summary.to_string())


if __name__ == "__main__":
    main()
