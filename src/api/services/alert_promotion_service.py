"""alert_promotion_service.py — promote threat alerts to remediation jobs.

Grouping strategies
-------------------
by_cve      (default)
    One job per unique CVE.  All assets affected by the same CVE are
    consolidated into a single job.  Best for wide-spread vulnerabilities
    like Log4Shell where 10+ servers all need the same patch.

by_asset_product
    One job per (asset, product) pair — mirrors the regular scan-pipeline
    grouping.  More granular; useful when assets need different patch schedules.

by_product
    One job per unique product name.  All CVEs and all assets that share the
    same product are merged.  Useful for "patch everything Apache" batches.

Scoring
-------
Uses the same 5-factor formula as score_engine.py:
    CVSS×40 + KEV×20 + EPSS×15 + Criticality×15 + InternetExposed×10

CVSS is approximated from the alert's severity text (CRITICAL→9.5, HIGH→7.5,
MEDIUM→5.5, LOW→3.5) since enrichment.db does not store a numeric CVSS column.
The remaining factors come directly from the threat_alerts and assets rows.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

SLA_DAYS = {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90}

CRITICALITY_MAP = {
    "low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.00,
}

# Severity text → approximate CVSS base score proxy.
# Used when a numeric CVSS is not available from enrichment.db.
_SEVERITY_CVSS: dict[str, float] = {
    "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5,
}


def _severity_to_cvss(severity: str | None) -> float:
    return _SEVERITY_CVSS.get((severity or "").upper(), 5.0)

VALID_STRATEGIES = {"by_cve", "by_asset_product", "by_product"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _score(cvss: float, is_kev: bool, epss: float,
           criticality: str, internet_exposed: bool) -> tuple[float, str]:
    """Return (risk_score, risk_level) using the VRA 5-factor formula."""
    crit_mult = CRITICALITY_MAP.get((criticality or "medium").lower(), 0.5)
    score = (
        (cvss / 10.0) * 40
        + (1 if is_kev else 0) * 20
        + epss * 15
        + crit_mult * 15
        + (1 if internet_exposed else 0) * 10
    )
    score = round(min(100.0, score), 1)
    if score >= 80:   level = "CRITICAL"
    elif score >= 60: level = "HIGH"
    elif score >= 40: level = "MEDIUM"
    else:             level = "LOW"
    return score, level


def _fingerprint(*parts: str) -> str:
    key = "|".join(sorted(str(p) for p in parts if p))
    return hashlib.sha256(key.encode()).hexdigest()[:24]


# ── Main function ─────────────────────────────────────────────────────────────

def promote_alerts_to_jobs(
    conn: sqlite3.Connection,
    alert_ids: Optional[list[int]] = None,
    grouping: str = "by_cve",
    actor: str = "system",
) -> dict:
    """Create remediation jobs from threat alerts and record the links.

    Parameters
    ----------
    conn       : platform.db connection
    alert_ids  : specific alert IDs to promote; None = all open alerts
    grouping   : "by_cve" | "by_asset_product" | "by_product"
    actor      : username logged in job_events

    Returns
    -------
    dict with jobs_created, jobs_skipped (already existed), alert_ids_promoted
    """
    if grouping not in VALID_STRATEGIES:
        raise ValueError(f"grouping must be one of {VALID_STRATEGIES}")

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # ── 1. Fetch alerts ───────────────────────────────────────────────────────
    if alert_ids:
        placeholders = ",".join("?" * len(alert_ids))
        alerts = conn.execute(
            f"""SELECT ta.*, a.hostname, a.ip_address, a.business_unit,
                       a.business_owner, a.environment, a.criticality,
                       a.internet_exposed
                FROM threat_alerts ta
                JOIN assets a ON a.asset_id = ta.asset_id
                WHERE ta.id IN ({placeholders}) AND ta.status = 'open'""",
            alert_ids,
        ).fetchall()
    else:
        alerts = conn.execute(
            """SELECT ta.*, a.hostname, a.ip_address, a.business_unit,
                      a.business_owner, a.environment, a.criticality,
                      a.internet_exposed
               FROM threat_alerts ta
               JOIN assets a ON a.asset_id = ta.asset_id
               WHERE ta.status = 'open'""",
        ).fetchall()

    if not alerts:
        return {"jobs_created": 0, "jobs_skipped": 0, "alert_ids_promoted": []}

    # ── 2. Group alerts by strategy ───────────────────────────────────────────
    groups: dict[str, list] = {}

    for a in alerts:
        cve_id  = a["cve_id"]  or ""
        product = a["matched_product"] or ""
        asset   = a["asset_id"]

        if grouping == "by_cve":
            key = cve_id
        elif grouping == "by_asset_product":
            key = f"{asset}::{product}"
        else:  # by_product
            key = product or cve_id

        groups.setdefault(key, []).append(dict(a))

    # ── 4. Create one job per group ───────────────────────────────────────────
    jobs_created = 0
    jobs_skipped = 0
    promoted_alert_ids: list[int] = []

    for group_key, group_alerts in groups.items():
        # Aggregate CVEs and assets
        cve_set: set[str]  = set()
        asset_set: set[str] = set()
        is_kev_any = False
        max_epss   = 0.0

        for a in group_alerts:
            if a["cve_id"]:  cve_set.add(a["cve_id"])
            if a["asset_id"]: asset_set.add(a["asset_id"])
            if a["is_kev"]:   is_kev_any = True
            max_epss = max(max_epss, float(a["epss_score"] or 0.0))

        cve_list   = sorted(cve_set)
        asset_ids  = sorted(asset_set)

        # Representative asset (worst criticality)
        CRIT_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        rep_alert = max(
            group_alerts,
            key=lambda a: CRIT_ORDER.get((a["criticality"] or "medium").lower(), 2),
        )
        criticality      = rep_alert["criticality"] or "medium"
        internet_exposed = bool(rep_alert["internet_exposed"])
        business_unit    = rep_alert["business_unit"] or ""
        business_owner   = rep_alert["business_owner"] or ""
        environment      = rep_alert["environment"] or "production"
        main_product     = rep_alert["matched_product"] or (cve_list[0] if cve_list else "Unknown")

        # Score: worst-case severity across the group (approximated via CVSS proxy)
        max_cvss = max(
            (_severity_to_cvss(a["severity"]) for a in group_alerts), default=0.0
        )
        risk_score, risk_level = _score(
            max_cvss, is_kev_any, max_epss, criticality, internet_exposed
        )

        # Fingerprint (idempotent — same group = same fingerprint)
        fp = _fingerprint(*cve_list, *asset_ids, main_product)

        # Check for existing job with this fingerprint
        existing = conn.execute(
            "SELECT job_id FROM jobs WHERE job_fingerprint = ?", (fp,)
        ).fetchone()

        if existing:
            job_id = existing["job_id"]
            jobs_skipped += 1
        else:
            sla = SLA_DAYS.get(risk_level, 30)
            due = (now + timedelta(days=sla)).isoformat()
            job_id = str(uuid.uuid4())

            kev_cves = [c for c in cve_list if any(
                a["cve_id"] == c and a["is_kev"] for a in group_alerts
            )]

            score_breakdown = json.dumps({
                "cvss":        round(max_cvss / 10.0 * 40, 2),
                "kev":         20 if is_kev_any else 0,
                "epss":        round(max_epss * 15, 2),
                "criticality": round(CRITICALITY_MAP.get(criticality.lower(), 0.5) * 15, 2),
                "exposure":    10 if internet_exposed else 0,
            })

            conn.execute(
                """INSERT INTO jobs
                   (job_id, job_fingerprint, asset_ids, cve_list, main_product,
                    plugin_family, max_risk_level, risk_score_max, business_owner,
                    business_unit, environment, kev_present, kev_cves,
                    affected_asset_count, cve_count, score_breakdown,
                    sla_days, created_at, due_date, status, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'TO_DO',?)""",
                (
                    job_id, fp,
                    json.dumps(asset_ids),
                    json.dumps(cve_list),
                    main_product,
                    "Threat Alert",
                    risk_level,
                    risk_score,
                    business_owner,
                    business_unit,
                    environment,
                    int(is_kev_any),
                    json.dumps(kev_cves),
                    len(asset_ids),
                    len(cve_list),
                    score_breakdown,
                    sla,
                    now_iso,
                    due,
                    now_iso,
                ),
            )

            # Audit event
            conn.execute(
                """INSERT INTO job_events
                   (job_id, event_type, old_status, new_status, changed_by, comment, created_at)
                   VALUES (?, 'created', NULL, 'TO_DO', ?, ?, ?)""",
                (
                    job_id, actor,
                    f"Auto-created from threat alert promotion "
                    f"(grouping={grouping}, CVEs={','.join(cve_list[:3])}{'…' if len(cve_list)>3 else ''})",
                    now_iso,
                ),
            )
            jobs_created += 1

        # ── 5. Link alerts → job ──────────────────────────────────────────────
        for a in group_alerts:
            conn.execute(
                "INSERT OR IGNORE INTO alert_jobs (alert_id, job_id, created_at) VALUES (?,?,?)",
                (a["id"], job_id, now_iso),
            )
            promoted_alert_ids.append(a["id"])

    conn.commit()
    logger.info(
        "promote_alerts: created=%d skipped=%d alerts=%d (grouping=%s)",
        jobs_created, jobs_skipped, len(promoted_alert_ids), grouping,
    )
    return {
        "jobs_created":       jobs_created,
        "jobs_skipped":       jobs_skipped,
        "alert_ids_promoted": promoted_alert_ids,
        "grouping":           grouping,
    }
