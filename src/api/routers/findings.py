"""Manual findings router — direct entry of CVE+host findings without a scanner file.

For users who:
  - Have CVE intelligence from a feed or threat report (but no scanner)
  - Want to add findings discovered manually (e.g., during a code review)
  - Are testing the platform with a small set of real CVEs

The submitted findings are written to a temporary CSV and routed through the
same upload pipeline as Nessus / OpenVAS files, so the result is identical:
enriched with KEV/EPSS/NVD, scored, and grouped into remediation jobs.
"""

import csv
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from api.auth import get_current_user, require_role
from api.db.connection import get_db, DB_PATH
from api.services.upload_service import (
    UPLOAD_DIR, create_upload_record, run_upload_pipeline,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Findings"])

_WRITERS = ("analyst", "remediation_owner", "admin")


# ── Schemas ────────────────────────────────────────────────────────────────────

class ManualFinding(BaseModel):
    cve_id:           str  = Field(..., description="e.g. CVE-2024-3400")
    hostname:         str  = Field(..., description="Asset hostname")
    ip_address:       str  = Field("", description="Asset IP (optional if hostname matches inventory)")
    cvss_base_score:  float = Field(0.0, ge=0.0, le=10.0)
    severity:         str  = Field("medium", description="critical|high|medium|low")
    vuln_title:       str  = ""
    plugin_family:    str  = ""
    plugin_name:      str  = ""
    plugin_id:        str  = ""

    @field_validator("cve_id")
    @classmethod
    def _validate_cve(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.startswith("CVE-"):
            raise ValueError(f"cve_id must start with 'CVE-', got '{v}'")
        return v

    @field_validator("severity")
    @classmethod
    def _normalise_severity(cls, v: str) -> str:
        v = v.lower()
        if v not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError(f"severity must be one of critical/high/medium/low/info, got '{v}'")
        return v


class ManualBatch(BaseModel):
    findings:    list[ManualFinding] = Field(..., min_length=1, max_length=500)
    uploaded_by: str = "manual-entry"


# ── Routes ─────────────────────────────────────────────────────────────────────

_WRITERS = ("analyst", "remediation_owner", "admin")


@router.post("/api/findings/manual", status_code=status.HTTP_201_CREATED)
def submit_manual_findings(
    payload:          ManualBatch,
    background_tasks: BackgroundTasks,
    conn:             sqlite3.Connection = Depends(get_db),
    user:             dict = Depends(require_role(*_WRITERS)),
):
    """Accept a batch of manually entered findings and route through the standard pipeline.

    Returns the upload record (which the client can poll via GET /api/uploads/{id}).
    """
    if not payload.findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one finding is required.",
        )

    upload_id = str(uuid.uuid4())
    dest_dir  = UPLOAD_DIR / upload_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Write findings to a CSV the csv_generic adapter can consume
    csv_path = dest_dir / "manual_findings.csv"
    fieldnames = [
        "cve_id", "hostname", "ip_address", "cvss_base_score", "severity",
        "vuln_title", "plugin_family", "plugin_name", "plugin_id", "scanner_source",
    ]
    file_size = 0
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for finding in payload.findings:
            writer.writerow({
                "cve_id":          finding.cve_id,
                "hostname":        finding.hostname,
                "ip_address":      finding.ip_address or finding.hostname,
                "cvss_base_score": finding.cvss_base_score,
                "severity":        finding.severity,
                "vuln_title":      finding.vuln_title or finding.cve_id,
                "plugin_family":   finding.plugin_family or "Manual Entry",
                "plugin_name":     finding.plugin_name or finding.cve_id,
                "plugin_id":       finding.plugin_id or "",
                "scanner_source":  "manual",
            })
        file_size = f.tell()

    # Compute a SHA-256 for dedup parity with file uploads
    import hashlib
    hasher = hashlib.sha256()
    with open(csv_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    sha256 = hasher.hexdigest()

    record = create_upload_record(
        conn,
        upload_id=upload_id,
        filename=csv_path.name,
        original_filename="manual_findings.csv",
        sha256=sha256,
        scanner_type="csv_generic",
        file_size=file_size,
        uploaded_by=payload.uploaded_by,
    )

    background_tasks.add_task(
        run_upload_pipeline,
        upload_id=upload_id,
        file_path=str(csv_path),
        scanner_type="csv_generic",
        db_path=str(DB_PATH),
    )

    conn.execute(
        "UPDATE uploads SET pipeline_triggered = 1 WHERE id = ?", (upload_id,)
    )
    conn.commit()
    record["pipeline_triggered"] = 1
    record["finding_count"] = len(payload.findings)

    return {"data": record}


# ── Findings list (with auto_triage join) ─────────────────────────────────────

@router.get("/api/findings/")
def list_findings(
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0,  ge=0),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    """Return findings with their auto_triage suggestion (LEFT JOIN).

    Falls back gracefully when the auto_triage table does not yet exist
    (e.g. before the server has been restarted after a schema migration).
    """
    import sqlite3 as _sq
    try:
        rows = conn.execute(
            """SELECT
                   f.id, f.upload_id, f.cve_id, f.hostname, f.component,
                   f.severity, f.ingest_method,
                   COALESCE(f.state, 'NEW') AS state,
                   f.created_at,
                   atr.triage_class, atr.confidence, atr.justification,
                   atr.model_version, atr.created_at AS triage_at
               FROM findings f
               LEFT JOIN auto_triage atr ON atr.finding_id = f.id
               ORDER BY f.created_at DESC
               LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    except _sq.OperationalError as exc:
        err = str(exc).lower()
        if "no such table" in err or "no such column" in err:
            # Tables created by migration — restart the API server to apply them.
            logger.warning("list_findings: schema not ready (%s). Returning empty list.", exc)
            return {"data": [], "total": 0,
                    "warning": "Run migrations by restarting the server, then retry."}
        raise

    return {"data": [dict(r) for r in rows], "total": total}


# ── Auto-triage endpoints ──────────────────────────────────────────────────────

@router.post("/api/findings/{finding_id}/auto-triage", status_code=status.HTTP_200_OK)
def trigger_auto_triage(
    finding_id: str,
    force: bool = Query(False, description="Overwrite even if analyst has acted"),
    conn:  sqlite3.Connection = Depends(get_db),
    user:  dict               = Depends(require_role("analyst", "admin")),
):
    """Run (or re-run) auto-triage for a finding.

    Idempotent — calling multiple times overwrites the previous result.
    Skips silently if findings.state is not NEW/TRIAGED unless force=true.
    """
    from api.services.triage_agent import run_auto_triage

    try:
        result = run_auto_triage(
            finding_id, conn,
            force=force,
            actor=user["username"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("auto-triage failed for %s: %s", finding_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Triage agent error: {exc}")

    return {"data": result}


@router.get("/api/findings/{finding_id}/auto-triage")
def get_auto_triage(
    finding_id: str,
    conn:       sqlite3.Connection = Depends(get_db),
    user:       dict               = Depends(get_current_user),
):
    """Return the current auto-triage suggestion for a finding."""
    row = conn.execute(
        "SELECT * FROM auto_triage WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No auto-triage result for finding '{finding_id}'. "
                   "Run POST /findings/{id}/auto-triage first.",
        )
    return {"data": dict(row)}


@router.post("/api/findings/backfill-from-jobs", status_code=200)
def backfill_findings_from_jobs(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(require_role(*_WRITERS)),
):
    """Create findings rows for every (CVE, asset) pair in existing jobs that
    has no corresponding finding yet.

    Safe to call multiple times — uses INSERT OR IGNORE so it never duplicates.
    Returns how many new rows were inserted.
    """
    from datetime import datetime, timezone
    import json as _json

    now = datetime.now(timezone.utc).isoformat()
    jobs = conn.execute(
        "SELECT job_id, cve_list, asset_ids, max_risk_level, main_product FROM jobs"
    ).fetchall()

    inserted = 0
    for job in jobs:
        cve_list  = _json.loads(job["cve_list"]  or "[]") if job["cve_list"]  else []
        asset_ids = _json.loads(job["asset_ids"] or "[]") if job["asset_ids"] else []
        if not cve_list or not asset_ids:
            continue

        for aid in asset_ids:
            row = conn.execute(
                "SELECT hostname FROM assets WHERE asset_id = ?", (aid,)
            ).fetchone()
            hostname = row["hostname"] if row else aid

            for cve in cve_list:
                if not cve or not cve.startswith("CVE-"):
                    continue
                existing = conn.execute(
                    "SELECT id FROM findings WHERE cve_id = ? AND hostname = ?",
                    (cve, hostname),
                ).fetchone()
                if existing:
                    continue
                conn.execute(
                    """INSERT OR IGNORE INTO findings
                       (id, upload_id, cve_id, hostname, component, severity,
                        ingest_method, state, created_at)
                       VALUES (?, NULL, ?, ?, ?, ?, 'backfill', 'NEW', ?)""",
                    (
                        str(uuid.uuid4()), cve, hostname,
                        job["main_product"] or "",
                        (job["max_risk_level"] or "MEDIUM").upper(),
                        now,
                    ),
                )
                inserted += 1

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    logger.info("backfill_findings_from_jobs: inserted %d rows, total=%d", inserted, total)
    return {"data": {"inserted": inserted, "total_findings": total}}


@router.post("/api/uploads/{upload_id}/reprocess", status_code=200)
def reprocess_upload(
    upload_id: str,
    background_tasks: BackgroundTasks,
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(require_role(*_WRITERS)),
):
    """Re-run the pipeline for a previously failed or partial upload.

    Resets status to 'queued' and re-triggers the background processing task.
    Useful after fixing a parser bug (e.g. adding Tenable SC column mappings).
    """
    row = conn.execute(
        "SELECT id, filename, scanner_type FROM uploads WHERE id = ?", (upload_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Upload '{upload_id}' not found.")

    # Find the file on disk
    from pathlib import Path as _Path
    from api.services.upload_service import UPLOAD_DIR, run_upload_pipeline, update_upload_status

    upload_dir = UPLOAD_DIR / upload_id
    candidates = list(upload_dir.glob("*")) if upload_dir.exists() else []
    if not candidates:
        raise HTTPException(status_code=404, detail=f"No files found for upload '{upload_id}'.")

    file_path = str(candidates[0])
    scanner_type = row["scanner_type"] or "auto"

    update_upload_status(conn, upload_id, "queued")
    background_tasks.add_task(
        run_upload_pipeline,
        upload_id=upload_id,
        file_path=file_path,
        scanner_type=scanner_type,
        db_path=str(DB_PATH),
    )
    conn.execute("UPDATE uploads SET pipeline_triggered = 1 WHERE id = ?", (upload_id,))
    conn.commit()

    logger.info("reprocess_upload: triggered re-processing for upload %s", upload_id)
    return {"data": {"upload_id": upload_id, "status": "queued", "file": candidates[0].name}}


@router.get("/api/findings/manual/example")
def get_example_payload():
    """Return the ODDO BHF demo manual-entry scenario.

    Narrative: Three CVEs flagged by the FS-ISAC morning threat feed that the
    Q2 scanner missed — two CISA KEV entries and one freshly published advisory.
    The analyst enters them directly without waiting for the next scan cycle.
    """
    return {
        "data": {
            "uploaded_by": "soc-analyst",
            "findings": [
                {
                    # CISA KEV — OpenSSH race-condition RCE, affects all Linux servers
                    # running OpenSSH 8.5p1–9.7p1. Scored 8.1 but HIGH exploitation
                    # probability given widespread PoC availability.
                    "cve_id":          "CVE-2024-6387",
                    "hostname":        "prod-db-primary-01",
                    "ip_address":      "10.10.3.10",
                    "cvss_base_score": 8.1,
                    "severity":        "high",
                    "vuln_title":      "OpenSSH regreSSHion — Unauthenticated RCE (race condition in signal handler)",
                    "plugin_family":   "OS / Remote Services",
                },
                {
                    # CISA KEV — Zero-click Outlook NTLM hash theft, no user interaction.
                    # Critical for ODDO BHF: finance workstations authenticate to Exchange.
                    "cve_id":          "CVE-2023-23397",
                    "hostname":        "workstation-fin-01",
                    "ip_address":      "10.10.50.10",
                    "cvss_base_score": 9.8,
                    "severity":        "critical",
                    "vuln_title":      "Microsoft Outlook Zero-Click NTLM Hash Theft (CVE-2023-23397)",
                    "plugin_family":   "Desktop Productivity",
                },
                {
                    # New Fortinet advisory published today — same firewall as existing
                    # CVE-2024-21762 finding, different attack surface (adjacent-network RCE).
                    "cve_id":          "CVE-2025-58413",
                    "hostname":        "fortigate-fw-01",
                    "ip_address":      "10.10.0.1",
                    "cvss_base_score": 7.5,
                    "severity":        "high",
                    "vuln_title":      "FortiOS / FortiSASE Stack-Based Buffer Overflow — Adjacent RCE",
                    "plugin_family":   "Network Appliances / Firewall",
                },
            ],
        }
    }
