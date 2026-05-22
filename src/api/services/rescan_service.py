"""Re-scan detection service.

Compares a fresh scan's output against the current job database to:
  - RESURFACE jobs that were DONE/CLOSED but appear in the new scan
  - Auto-DONE jobs whose CVEs are no longer present in the new scan
"""

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent.parent


def safe_json_loads(v, default=None):
    if default is None:
        default = []
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


# ── Data loaders ──────────────────────────────────────────────────────────────

def load_new_scan_cves(csv_path: str) -> set[str]:
    """Read vuln_enriched.csv and return all unique CVE IDs present in the new scan."""
    path = Path(csv_path) if not Path(csv_path).is_absolute() else Path(csv_path)
    if not path.is_absolute():
        path = ROOT / csv_path

    cves: set[str] = set()
    if not path.exists():
        logger.warning("rescan: enriched CSV not found at %s", path)
        return cves

    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                cve_id = (row.get("cve_id") or "").strip().upper()
                if cve_id.startswith("CVE-"):
                    cves.add(cve_id)
    except Exception as exc:
        logger.error("rescan: failed reading %s — %s", path, exc)

    logger.info("rescan: found %d unique CVEs in new scan", len(cves))
    return cves


def load_new_job_fingerprints(csv_path: str) -> dict[str, str]:
    """Read remediation_jobs.csv → {job_fingerprint: job_id}."""
    path = Path(csv_path) if not Path(csv_path).is_absolute() else Path(csv_path)
    if not path.is_absolute():
        path = ROOT / csv_path

    mapping: dict[str, str] = {}
    if not path.exists():
        logger.warning("rescan: jobs CSV not found at %s", path)
        return mapping

    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                fp  = (row.get("job_fingerprint") or "").strip()
                jid = (row.get("job_id") or "").strip()
                if fp and jid:
                    mapping[fp] = jid
    except Exception as exc:
        logger.error("rescan: failed reading jobs CSV %s — %s", path, exc)

    logger.info("rescan: %d job fingerprints loaded from new scan", len(mapping))
    return mapping


# ── Detection logic ───────────────────────────────────────────────────────────

def detect_resurfaced(
    conn: sqlite3.Connection,
    new_fingerprints: dict[str, str],
) -> list[str]:
    """Find DONE/CLOSED jobs whose fingerprint appears in the new scan → RESURFACED."""
    if not new_fingerprints:
        return []

    fps = list(new_fingerprints.keys())
    placeholders = ", ".join("?" * len(fps))
    cursor = conn.execute(
        f"""SELECT job_id, job_fingerprint FROM jobs
            WHERE status IN ('DONE','CLOSED')
              AND job_fingerprint IN ({placeholders})""",
        fps,
    )
    job_ids = [row["job_id"] for row in cursor.fetchall()]
    logger.info("rescan: %d resurfaced jobs detected", len(job_ids))
    return job_ids


def detect_newly_fixed(
    conn: sqlite3.Connection,
    new_scan_cves: set[str],
) -> list[str]:
    """Find TO_DO/IN_PROGRESS jobs where NONE of their CVEs appear in the new scan → DONE."""
    cursor = conn.execute(
        "SELECT job_id, cve_list FROM jobs WHERE status IN ('TO_DO','IN_PROGRESS')"
    )
    rows = cursor.fetchall()

    fixed_ids: list[str] = []
    for row in rows:
        cves = safe_json_loads(row["cve_list"], [])
        if not cves:
            continue
        # Fixed if no overlap with current scan
        if not any(c.strip().upper() in new_scan_cves for c in cves):
            fixed_ids.append(row["job_id"])

    logger.info("rescan: %d newly-fixed jobs detected", len(fixed_ids))
    return fixed_ids


# ── Apply & orchestrate ───────────────────────────────────────────────────────

def apply_rescan_results(
    conn: sqlite3.Connection,
    resurfaced: list[str],
    fixed: list[str],
    changed_by: str,
) -> dict:
    """Write status transitions and events for resurfaced/fixed jobs."""
    from api.repositories.jobs_repo import update_job_status

    for job_id in resurfaced:
        update_job_status(
            conn, job_id, "RESURFACED", changed_by,
            comment="Auto-resurfaced: vulnerability re-detected in new scan",
        )

    for job_id in fixed:
        update_job_status(
            conn, job_id, "DONE", changed_by,
            comment="Auto-closed: CVEs no longer present in new scan",
        )

    return {"resurfaced": len(resurfaced), "fixed": len(fixed)}


def run_rescan(
    conn: sqlite3.Connection,
    enriched_csv: str,
    jobs_csv: str,
    changed_by: str = "pipeline",
) -> dict:
    """Orchestrate full re-scan detection. Returns summary dict."""
    new_cves         = load_new_scan_cves(enriched_csv)
    new_fingerprints = load_new_job_fingerprints(jobs_csv)

    resurfaced = detect_resurfaced(conn, new_fingerprints)
    fixed      = detect_newly_fixed(conn, new_cves)

    summary = apply_rescan_results(conn, resurfaced, fixed, changed_by)
    summary["scan_timestamp"] = datetime.now(timezone.utc).isoformat()
    return summary
