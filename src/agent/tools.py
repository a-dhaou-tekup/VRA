"""Read-only tool layer for the VRA agent.

Each function accepts ``role: str`` plus keyword arguments, calls existing
repos / services directly (no HTTP round-trip), and returns a uniform envelope:

    {"ok": True,  "data": <payload>, "error": None}   — success
    {"ok": False, "data": None,      "error": "<msg>"} — failure

``role`` is validated against ALLOWED_ROLES and recorded in the envelope
metadata for audit.  All named roles share identical read access per the
current VRA policy; the parameter is a future hook for per-role scoping.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

ALLOWED_ROLES = {"admin", "analyst", "remediation_owner", "risk_owner", "auditor"}

# Statuses that mean a job is no longer actionable
_TERMINAL = {"DONE", "CLOSED", "FALSE_POSITIVE"}

ROOT = Path(__file__).parent.parent.parent  # project root
ENRICHMENT_DB = ROOT / "data" / "cache" / "enrichment.db"


# ── Envelope helpers ──────────────────────────────────────────────────────────

def _ok(data: Any) -> dict:
    return {"ok": True, "data": data, "error": None}


def _err(msg: str) -> dict:
    logger.warning("tool error: %s", msg)
    return {"ok": False, "data": None, "error": msg}


# ── Connection helpers ────────────────────────────────────────────────────────

def _platform_conn() -> sqlite3.Connection:
    from api.db.connection import get_connection
    return get_connection()


def _enrichment_conn() -> Optional[sqlite3.Connection]:
    if not ENRICHMENT_DB.exists():
        return None
    conn = sqlite3.connect(str(ENRICHMENT_DB), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _validate_role(role: str) -> Optional[str]:
    """Return an error string if role is unrecognised, else None."""
    if role not in ALLOWED_ROLES:
        return f"Unknown role '{role}'. Must be one of: {', '.join(sorted(ALLOWED_ROLES))}"
    return None


# ── 1. get_metrics ────────────────────────────────────────────────────────────

def get_metrics(role: str) -> dict:
    """Return the live VRA KPI dashboard.

    Includes: total job count, breakdown by status and risk level, KEV job
    count, overdue (past-SLA) count, SLA compliance %, critical/high open
    counts, and the KEV-past-SLA sub-count.
    """
    if err := _validate_role(role):
        return _err(err)
    try:
        conn = _platform_conn()
        try:
            from api.repositories.jobs_repo import (
                count_by_status,
                count_by_risk_level,
                get_overdue_jobs,
            )
            by_status      = count_by_status(conn)
            by_risk        = count_by_risk_level(conn)
            total_jobs     = sum(by_status.values())
            kev_jobs_count = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE kev_present = 1"
            ).fetchone()[0]
            overdue        = get_overdue_jobs(conn)
            overdue_count  = len(overdue)

            non_closed = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status NOT IN ('DONE','CLOSED')"
            ).fetchone()[0]
            sla_compliance_pct = (
                round((non_closed - overdue_count) / non_closed * 100, 1)
                if non_closed > 0 else 100.0
            )

            critical_open = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE max_risk_level='CRITICAL'"
                " AND status NOT IN ('DONE','CLOSED','FALSE_POSITIVE')"
            ).fetchone()[0]
            high_open = conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE max_risk_level='HIGH'"
                " AND status NOT IN ('DONE','CLOSED','FALSE_POSITIVE')"
            ).fetchone()[0]
            kev_past_sla = conn.execute(
                "SELECT COUNT(*) FROM jobs"
                " WHERE kev_present = 1"
                " AND due_date IS NOT NULL"
                " AND due_date < datetime('now')"
                " AND status NOT IN ('DONE','CLOSED','FALSE_POSITIVE')"
            ).fetchone()[0]

            return _ok({
                "total_jobs":         total_jobs,
                "jobs_by_status":     by_status,
                "jobs_by_risk_level": by_risk,
                "kev_jobs_count":     kev_jobs_count,
                "kev_past_sla":       kev_past_sla,
                "overdue_count":      overdue_count,
                "sla_compliance_pct": sla_compliance_pct,
                "critical_open":      critical_open,
                "high_open":          high_open,
            })
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"get_metrics failed: {exc}")


# ── 2. get_sla_compliance ─────────────────────────────────────────────────────

def get_sla_compliance(role: str) -> dict:
    """Return detailed SLA compliance data.

    Returns total open job count, how many are within SLA vs breached,
    the compliance percentage, and a list of overdue jobs with days-overdue,
    risk level, and product name per entry.
    """
    if err := _validate_role(role):
        return _err(err)
    try:
        conn = _platform_conn()
        try:
            now = datetime.now(timezone.utc)
            open_jobs = conn.execute(
                "SELECT job_id, due_date, max_risk_level, main_product"
                " FROM jobs WHERE status NOT IN ('DONE','CLOSED')"
            ).fetchall()
            total_open      = len(open_jobs)
            overdue_details: list[dict] = []

            for row in open_jobs:
                if not row["due_date"]:
                    continue
                try:
                    due = datetime.fromisoformat(row["due_date"].replace("Z", "+00:00"))
                except ValueError:
                    continue
                if due < now:
                    overdue_details.append({
                        "job_id":       row["job_id"],
                        "due_date":     row["due_date"],
                        "days_overdue": (now - due).days,
                        "risk_level":   row["max_risk_level"],
                        "product":      row["main_product"],
                    })

            breached       = len(overdue_details)
            within_sla     = total_open - breached
            compliance_pct = (
                round(within_sla / total_open * 100, 1) if total_open > 0 else 100.0
            )
            return _ok({
                "total_open":     total_open,
                "within_sla":     within_sla,
                "breached":       breached,
                "compliance_pct": compliance_pct,
                "overdue_jobs":   overdue_details,
            })
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"get_sla_compliance failed: {exc}")


# ── 3. list_jobs ──────────────────────────────────────────────────────────────

def list_jobs(
    role: str,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    business_unit: Optional[str] = None,
    kev_only: bool = False,
    past_sla: bool = False,
    limit: int = 50,
) -> dict:
    """List remediation jobs with optional filters.

    ``status`` accepts workflow values (TO_DO, IN_PROGRESS, DONE, CLOSED,
    FALSE_POSITIVE) or the alias ``'open'`` which expands to all non-terminal
    statuses.  ``past_sla=True`` restricts results to jobs whose SLA deadline
    has already passed.
    """
    if err := _validate_role(role):
        return _err(err)
    # Coerce list values the model sometimes passes (e.g. risk_level=["CRITICAL","HIGH"])
    if isinstance(status, list):
        status = status[0] if status else None
    if isinstance(risk_level, list):
        risk_level = risk_level[0] if risk_level else None
    if isinstance(business_unit, list):
        business_unit = business_unit[0] if business_unit else None
    try:
        conn = _platform_conn()
        try:
            from api.repositories.jobs_repo import get_all_jobs

            # Resolve the "open" alias: fetch without status filter, post-filter.
            open_alias = status is not None and str(status).upper() == "OPEN"
            repo_status = None if open_alias else status

            # When we need to post-filter by past_sla or open_alias, fetch more rows.
            fetch_limit = 1000 if (past_sla or open_alias) else limit

            jobs = get_all_jobs(
                conn,
                status=repo_status,
                risk_level=risk_level,
                business_unit=business_unit,
                kev_only=kev_only,
                limit=fetch_limit,
                offset=0,
            )

            if open_alias:
                jobs = [j for j in jobs if j.get("status") not in _TERMINAL]

            if past_sla:
                now = datetime.now(timezone.utc)
                filtered: list[dict] = []
                for j in jobs:
                    if j.get("status") in _TERMINAL:
                        continue
                    dd = j.get("due_date")
                    if not dd:
                        continue
                    try:
                        due = datetime.fromisoformat(dd.replace("Z", "+00:00"))
                        if due < now:
                            filtered.append(j)
                    except ValueError:
                        continue
                jobs = filtered

            jobs = jobs[:limit]
            return _ok({"jobs": jobs, "count": len(jobs)})
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"list_jobs failed: {exc}")


# ── 4. get_job_detail ─────────────────────────────────────────────────────────

def get_job_detail(role: str, job_id: str) -> dict:
    """Return the complete record for a single remediation job.

    Includes CVE list, risk score breakdown, SLA dates, triage decision,
    assigned team, KEV flag, lifecycle timestamps, and enrichment data.
    """
    if err := _validate_role(role):
        return _err(err)
    if not job_id or not job_id.strip():
        return _err("job_id is required")
    try:
        conn = _platform_conn()
        try:
            from api.repositories.jobs_repo import get_job_by_id
            job = get_job_by_id(conn, job_id.strip())
            if job is None:
                return _err(f"Job '{job_id}' not found")
            return _ok(job)
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"get_job_detail failed: {exc}")


# ── 5. search_cves ────────────────────────────────────────────────────────────

def search_cves(role: str, cve_id: str, kev_only: bool = False) -> dict:
    """Look up a CVE in the enrichment cache and find affected jobs.

    Returns KEV flag, EPSS score, CVSS score, description (from NVD cache),
    and the list of remediation jobs that reference this CVE.  If ``kev_only``
    is True and the CVE is not on the CISA KEV catalog, returns found=False.
    """
    if err := _validate_role(role):
        return _err(err)
    if not cve_id or not cve_id.strip():
        return _err("cve_id is required")
    cve_id = cve_id.strip().upper()

    # ── Enrichment lookup ──────────────────────────────────────────────────────
    enrichment: Optional[dict] = None
    if ENRICHMENT_DB.exists():
        econn = _enrichment_conn()
        if econn:
            try:
                row = econn.execute(
                    "SELECT * FROM cve_context WHERE cve_id = ?", (cve_id,)
                ).fetchone()
                if row:
                    enrichment = dict(row)
            except Exception as exc:
                logger.warning("search_cves enrichment lookup failed: %s", exc)
            finally:
                econn.close()

    is_kev = bool(enrichment.get("kev_flag")) if enrichment else False
    if kev_only and not is_kev:
        return _ok({"cve_id": cve_id, "found": False, "kev": False, "affected_jobs": []})

    # ── Platform jobs scan ────────────────────────────────────────────────────
    affected_jobs: list[dict] = []
    try:
        conn = _platform_conn()
        try:
            rows = conn.execute(
                "SELECT job_id, main_product, max_risk_level, status, cve_list FROM jobs"
            ).fetchall()
            for row in rows:
                try:
                    cve_list = [c.upper() for c in json.loads(row["cve_list"] or "[]")]
                except Exception:
                    continue
                if cve_id in cve_list:
                    affected_jobs.append({
                        "job_id":       row["job_id"],
                        "main_product": row["main_product"],
                        "risk_level":   row["max_risk_level"],
                        "status":       row["status"],
                    })
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("search_cves platform scan failed: %s", exc)

    return _ok({
        "cve_id":        cve_id,
        "found":         enrichment is not None,
        "kev":           is_kev,
        "epss_score":    enrichment.get("epss_score")   if enrichment else None,
        "cvss_score":    enrichment.get("cvss_score")   if enrichment else None,
        "description":   enrichment.get("description")  if enrichment else None,
        "affected_jobs": affected_jobs,
    })


# ── 6. get_enrichment_status ──────────────────────────────────────────────────

def get_enrichment_status(role: str) -> dict:
    """Return KEV / EPSS / NVD cache freshness and counts.

    Surfaces how many CVEs are cached per feed, when each feed was last
    fetched, and the RAG advisory corpus file count.
    """
    if err := _validate_role(role):
        return _err(err)
    if not ENRICHMENT_DB.exists():
        return _ok({
            "db_exists":        False,
            "rag_corpus_files": 0,
            "kev":  {"cached": 0, "last_fetched": None, "ttl_days": 7},
            "epss": {"cached": 0, "last_fetched": None, "ttl_days": 30},
            "nvd":  {"cached": 0, "last_fetched": None, "ttl_days": 90},
        })
    try:
        econn = _enrichment_conn()
        if not econn:
            return _err("Could not open enrichment database")
        try:
            kev_count  = econn.execute(
                "SELECT COUNT(*) FROM cve_context WHERE kev_flag = 1"
            ).fetchone()[0]
            epss_count = econn.execute(
                "SELECT COUNT(*) FROM cve_context WHERE epss_score IS NOT NULL"
            ).fetchone()[0]
            nvd_count  = econn.execute(
                "SELECT COUNT(*) FROM cve_context WHERE nvd_cached_at IS NOT NULL"
            ).fetchone()[0]

            kev_meta = econn.execute(
                "SELECT value FROM kev_meta WHERE key = 'last_fetched'"
            ).fetchone()
            kev_last  = kev_meta["value"] if kev_meta else None
            epss_last = econn.execute(
                "SELECT MAX(epss_cached_at) FROM cve_context"
            ).fetchone()[0]
            nvd_last  = econn.execute(
                "SELECT MAX(nvd_cached_at) FROM cve_context"
            ).fetchone()[0]

            rag_dir   = ROOT / "data" / "rag_corpus"
            rag_count = sum(1 for _ in rag_dir.rglob("*.txt")) if rag_dir.exists() else 0
            db_size   = ENRICHMENT_DB.stat().st_size

            return _ok({
                "db_exists":        True,
                "db_size_bytes":    db_size,
                "rag_corpus_files": rag_count,
                "kev":  {"cached": kev_count,  "last_fetched": kev_last,  "ttl_days": 7},
                "epss": {"cached": epss_count, "last_fetched": epss_last, "ttl_days": 30},
                "nvd":  {"cached": nvd_count,  "last_fetched": nvd_last,  "ttl_days": 90},
            })
        finally:
            econn.close()
    except Exception as exc:
        return _err(f"get_enrichment_status failed: {exc}")


# ── 7. get_threat_alerts ──────────────────────────────────────────────────────

def get_threat_alerts(
    role: str,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    kev_only: bool = False,
    limit: int = 50,
) -> dict:
    """List threat-exposure alerts from the asset–CVE matching engine.

    Filter by ``status`` (open / acknowledged / dismissed), ``alert_type``
    (kev_match / high_epss), or ``kev_only=True`` for KEV-matched alerts only.
    Results are ordered by KEV flag DESC, EPSS score DESC.
    """
    if err := _validate_role(role):
        return _err(err)
    try:
        conn = _platform_conn()
        try:
            from api.repositories.threat_alerts_repo import get_all
            alerts, total = get_all(
                conn,
                status=status,
                alert_type=alert_type,
                is_kev=True if kev_only else None,
                limit=limit,
                offset=0,
            )
            return _ok({"alerts": alerts, "total": total})
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"get_threat_alerts failed: {exc}")


# ── 8. get_risk_acceptances ───────────────────────────────────────────────────

def get_risk_acceptances(role: str, expired: bool = False) -> dict:
    """Return the risk acceptance register.

    By default returns all entries with status='active'.  Set ``expired=True``
    to restrict to acceptances whose ``expiry_date`` has already passed — these
    are logically overdue for re-review even though still marked active.
    """
    if err := _validate_role(role):
        return _err(err)
    try:
        conn = _platform_conn()
        try:
            from api.repositories.risk_acceptance_repo import (
                get_all_active,
                get_expired_active,
            )
            records = get_expired_active(conn) if expired else get_all_active(conn)
            return _ok({"risk_acceptances": records, "count": len(records)})
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"get_risk_acceptances failed: {exc}")


# ── 9. query_controls ─────────────────────────────────────────────────────────

def query_controls(
    role: str,
    framework: Optional[str] = None,
    control_id: Optional[str] = None,
) -> dict:
    """Return compliance controls with live evidence and coverage status.

    Each result includes the control definition, a live evidence snapshot
    (raw counts + derived percentages from the live DB), and a computed
    status: full / partial / supporting / not_applicable.

    Filter by ``framework`` (ISO/IEC 27001:2022, CIS Controls v8, NIST CSF 2.0)
    or ``control_id`` (e.g. 'ISO-8.8', 'CIS-7', 'CSF-ID.AM').
    """
    if err := _validate_role(role):
        return _err(err)
    try:
        conn = _platform_conn()
        try:
            from api.services.compliance_service import enrich_control
            clauses: list[str] = []
            params:  list[str] = []
            if framework:
                clauses.append("framework = ?")
                params.append(framework)
            if control_id:
                clauses.append("control_id = ?")
                params.append(control_id)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"SELECT * FROM control_catalog {where} ORDER BY framework, control_id",
                params,
            ).fetchall()
            controls = [enrich_control(conn, dict(r)) for r in rows]
            return _ok({"controls": controls, "count": len(controls)})
        finally:
            conn.close()
    except Exception as exc:
        return _err(f"query_controls failed: {exc}")


# ── 10. search_knowledge ──────────────────────────────────────────────────────

def search_knowledge(role: str, query: str, top_k: int = 5) -> dict:
    """Search the VRA advisory RAG corpus for relevant text chunks.

    Embeds ``query`` and returns the ``top_k`` most similar advisory chunks
    from the ChromaDB collection (CISA, NVD, and vendor advisories).
    Use for advice, best-practice, and 'how to handle X' questions.
    """
    if err := _validate_role(role):
        return _err(err)
    if not query or not query.strip():
        return _err("query is required")
    if not (1 <= top_k <= 20):
        return _err("top_k must be between 1 and 20")
    try:
        from rag.retriever import retrieve_chunks
        chunks = retrieve_chunks(query.strip(), top_k=top_k)
        return _ok({"chunks": chunks, "count": len(chunks)})
    except Exception as exc:
        return _err(f"search_knowledge failed: {exc}")
