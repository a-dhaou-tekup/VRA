"""Compliance control-mapping service.

Loads control_mapping.yaml into control_catalog on startup and provides
live evidence resolution against existing VRA tables.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_YAML_PATH = Path(__file__).parent.parent.parent.parent / "config" / "control_mapping.yaml"


# ── Raw evidence queries ──────────────────────────────────────────────────────
# Each key maps to a scalar COUNT(*) (or aggregate) query.

EVIDENCE_QUERIES: dict[str, str] = {
    "assets_total":             "SELECT COUNT(*) FROM assets",
    "assets_classified":        (
        "SELECT COUNT(*) FROM assets "
        "WHERE criticality IS NOT NULL AND criticality != ''"
    ),
    "uploads_count":            "SELECT COUNT(*) FROM uploads WHERE status = 'done'",
    "audit_events_count":       "SELECT COUNT(*) FROM job_events",
    "ticket_links_count":       "SELECT COUNT(*) FROM ticket_links",
    "jobs_total":               "SELECT COUNT(*) FROM jobs",
    "software_records_count":   "SELECT COUNT(*) FROM asset_software",
    "risk_acceptances_count":   "SELECT COUNT(*) FROM risk_acceptances WHERE status = 'active'",
    "ai_advice_count":          (
        "SELECT COUNT(DISTINCT job_id) FROM llm_advice "
        "WHERE model_name != 'unavailable'"
    ),
    "workaround_records_count": "SELECT COUNT(*) FROM workaround_records",
    "kev_jobs_count":           "SELECT COUNT(*) FROM jobs WHERE kev_present = 1",
    "threat_alerts_count":      "SELECT COUNT(*) FROM threat_alerts",
    "users_count":              "SELECT COUNT(*) FROM users WHERE active = 1",
    "done_jobs_count":          "SELECT COUNT(*) FROM jobs WHERE status IN ('DONE','CLOSED')",
    "internet_exposed_count":   "SELECT COUNT(*) FROM assets WHERE internet_exposed = 1",
    "overdue_jobs_count":       (
        "SELECT COUNT(*) FROM jobs "
        "WHERE due_date < datetime('now') "
        "AND status NOT IN ('DONE','CLOSED','FALSE_POSITIVE')"
    ),
    "sla_jobs_count":           "SELECT COUNT(*) FROM jobs WHERE sla_days IS NOT NULL",
}


# ── Derived metric helpers ────────────────────────────────────────────────────

def _pct(numerator: int, denominator: int) -> float:
    return round(numerator / denominator * 100, 1) if denominator else 0.0


def _derive(data: dict) -> dict:
    """Compute percentage-based derived metrics from raw counts."""
    out = dict(data)
    if "assets_classified" in out and "assets_total" in out:
        out["assets_classified_pct"] = _pct(out["assets_classified"], out["assets_total"])
    if "ticket_links_count" in out and "jobs_total" in out:
        out["ticket_coverage_pct"] = _pct(out["ticket_links_count"], out["jobs_total"])
    if "software_records_count" in out and "assets_total" in out:
        out["software_coverage_pct"] = _pct(out["software_records_count"], out["assets_total"])
    if "ai_advice_count" in out and "jobs_total" in out:
        out["ai_advice_coverage_pct"] = _pct(out["ai_advice_count"], out["jobs_total"])
    if "done_jobs_count" in out and "jobs_total" in out:
        out["remediation_rate_pct"] = _pct(out["done_jobs_count"], out["jobs_total"])
    if "sla_jobs_count" in out and "jobs_total" in out:
        out["sla_configured_pct"] = _pct(out["sla_jobs_count"], out["jobs_total"])
    return out


# ── Status evaluators (one per control ID) ────────────────────────────────────

def _fop(full: bool, partial: bool) -> str:
    """Return 'full', 'partial', or 'not_applicable'."""
    if full:
        return "full"
    if partial:
        return "partial"
    return "not_applicable"


STATUS_EVALUATORS: dict[str, callable] = {
    # ── ISO 27001:2022 ────────────────────────────────────────────────────────
    "ISO-A.8.1": lambda e: _fop(
        e.get("assets_total", 0) >= 1 and e.get("assets_classified_pct", 0) >= 90,
        e.get("assets_total", 0) >= 1,
    ),
    "ISO-A.8.8": lambda e: _fop(
        e.get("uploads_count", 0) >= 1,
        e.get("jobs_total", 0) >= 1,
    ),
    "ISO-A.5.26": lambda e: _fop(
        e.get("audit_events_count", 0) >= 10,
        e.get("audit_events_count", 0) >= 1,
    ),
    "ISO-A.5.24": lambda e: _fop(
        e.get("ticket_coverage_pct", 0) >= 50,
        e.get("ticket_links_count", 0) >= 1,
    ),
    "ISO-A.8.9": lambda e: _fop(
        e.get("software_coverage_pct", 0) >= 20,
        e.get("software_records_count", 0) >= 1,
    ),
    "ISO-A.5.10": lambda e: _fop(
        e.get("risk_acceptances_count", 0) >= 1
        and e.get("ticket_coverage_pct", 0) >= 50,
        e.get("risk_acceptances_count", 0) >= 1,
    ),
    "ISO-A.5.35": lambda e: _fop(
        e.get("ai_advice_coverage_pct", 0) >= 100,
        e.get("ai_advice_coverage_pct", 0) >= 30,
    ),
    # ── CIS Controls v8 ───────────────────────────────────────────────────────
    "CIS-1": lambda e: _fop(
        e.get("assets_total", 0) >= 1,
        e.get("assets_total", 0) >= 1,
    ),
    "CIS-7": lambda e: _fop(
        e.get("kev_jobs_count", 0) >= 1 and e.get("threat_alerts_count", 0) >= 100,
        e.get("threat_alerts_count", 0) >= 1,
    ),
    "CIS-17": lambda e: _fop(
        e.get("audit_events_count", 0) >= 10,
        e.get("audit_events_count", 0) >= 1,
    ),
    "CIS-2": lambda e: _fop(
        e.get("software_coverage_pct", 0) >= 20,
        e.get("software_records_count", 0) >= 1,
    ),
    "CIS-5": lambda e: _fop(
        e.get("users_count", 0) >= 5 and e.get("audit_events_count", 0) >= 100,
        e.get("users_count", 0) >= 1,
    ),
    "CIS-6": lambda e: _fop(
        e.get("ticket_coverage_pct", 0) >= 50,
        e.get("users_count", 0) >= 1,
    ),
    "CIS-13": lambda e: _fop(
        e.get("threat_alerts_count", 0) >= 100
        and e.get("remediation_rate_pct", 0) >= 80,
        e.get("threat_alerts_count", 0) >= 100,
    ),
    # ── NIST CSF 2.0 ──────────────────────────────────────────────────────────
    "CSF-ID.AM": lambda e: _fop(
        e.get("assets_total", 0) >= 1 and e.get("assets_classified_pct", 0) >= 90,
        e.get("assets_total", 0) >= 1,
    ),
    "CSF-PR.IP": lambda e: _fop(
        e.get("sla_configured_pct", 0) >= 100,
        e.get("sla_jobs_count", 0) >= 1,
    ),
    "CSF-DE.CM": lambda e: _fop(
        e.get("threat_alerts_count", 0) >= 100
        and e.get("remediation_rate_pct", 0) >= 80,
        e.get("threat_alerts_count", 0) >= 100,
    ),
    "CSF-RS.MI": lambda e: _fop(
        e.get("remediation_rate_pct", 0) >= 80,
        e.get("done_jobs_count", 0) >= 1,
    ),
    "CSF-RC.RP": lambda e: _fop(
        e.get("workaround_records_count", 0) >= 5
        and e.get("remediation_rate_pct", 0) >= 80,
        e.get("workaround_records_count", 0) >= 1,
    ),
}


# ── Core functions ────────────────────────────────────────────────────────────

def gather_evidence(conn: sqlite3.Connection, features: list[str]) -> dict:
    """Run SQL queries for each named feature; return raw + derived metrics."""
    raw: dict[str, int] = {}
    for key in features:
        if key in EVIDENCE_QUERIES:
            val = conn.execute(EVIDENCE_QUERIES[key]).fetchone()[0]
            raw[key] = int(val) if val is not None else 0
    return _derive(raw)


def compute_status(control_id: str, is_supporting: bool, evidence: dict) -> str:
    if is_supporting:
        return "supporting"
    evaluator = STATUS_EVALUATORS.get(control_id)
    if evaluator is None:
        return "partial"
    try:
        return evaluator(evidence)
    except Exception:
        return "partial"


def enrich_control(conn: sqlite3.Connection, row: dict) -> dict:
    """Add live evidence snapshot and computed status to a control_catalog row."""
    features   = json.loads(row.get("vra_features") or "[]")
    deep_links = json.loads(row.get("deep_links")   or "[]")
    evidence   = gather_evidence(conn, features)
    st         = compute_status(row["control_id"], bool(row.get("is_supporting")), evidence)
    return {
        **row,
        "vra_features": features,
        "deep_links":   deep_links,
        "evidence":     evidence,
        "status":       st,
    }


# ── Catalog loader ────────────────────────────────────────────────────────────

def load_control_catalog(conn: sqlite3.Connection) -> int:
    """Load (or reload) control_mapping.yaml into control_catalog. Returns row count."""
    with open(_YAML_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    controls = data.get("controls", [])
    now = datetime.now(timezone.utc).isoformat()

    conn.execute("DELETE FROM control_catalog")
    for ctrl in controls:
        conn.execute(
            """INSERT INTO control_catalog
                   (control_id, framework, name, description, objective,
                    vra_features, deep_links, is_supporting, loaded_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                ctrl["id"],
                ctrl["framework"],
                ctrl["name"],
                ctrl.get("description", ""),
                ctrl.get("objective", ""),
                json.dumps(ctrl.get("vra_features", [])),
                json.dumps(ctrl.get("deep_links",   [])),
                1 if ctrl.get("is_supporting", False) else 0,
                now,
            ),
        )
    conn.commit()
    logger.info("compliance: loaded %d controls from control_mapping.yaml", len(controls))
    return len(controls)
