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

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from api.auth import require_role
from api.db.connection import get_db, DB_PATH
from api.services.upload_service import (
    UPLOAD_DIR, create_upload_record, run_upload_pipeline,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


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


@router.post("/manual", status_code=status.HTTP_201_CREATED)
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


@router.get("/manual/example")
def get_example_payload():
    """Return a real-CVE example payload showing the correct shape.

    All CVE IDs and CVSS scores below are real (sourced from CISA KEV + NVD).
    Replace the hostnames with your actual assets.
    """
    return {
        "data": {
            "uploaded_by": "your-name",
            "findings": [
                {
                    "cve_id":          "CVE-2024-3400",
                    "hostname":        "vpn-gw-prod-01",
                    "ip_address":      "10.0.0.5",
                    "cvss_base_score": 10.0,
                    "severity":        "critical",
                    "vuln_title":      "PAN-OS Command Injection in GlobalProtect",
                    "plugin_family":   "Firewalls",
                },
                {
                    "cve_id":          "CVE-2021-44228",
                    "hostname":        "app-srv-prod-01",
                    "ip_address":      "10.0.1.20",
                    "cvss_base_score": 10.0,
                    "severity":        "critical",
                    "vuln_title":      "Apache Log4j2 RCE (Log4Shell)",
                    "plugin_family":   "Java",
                },
                {
                    "cve_id":          "CVE-2024-21762",
                    "hostname":        "fortigate-fw-01",
                    "ip_address":      "10.0.0.1",
                    "cvss_base_score": 9.6,
                    "severity":        "critical",
                    "vuln_title":      "Fortinet FortiOS SSL-VPN OOB Write",
                    "plugin_family":   "Firewalls",
                },
            ],
        }
    }
