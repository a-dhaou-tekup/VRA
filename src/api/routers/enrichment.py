"""Enrichment management — surface KEV / EPSS / NVD cache status and trigger refreshes."""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.auth import get_current_user, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/enrichment", tags=["Enrichment"])

ROOT = Path(__file__).parent.parent.parent.parent
ENRICHMENT_DB = ROOT / "data" / "cache" / "enrichment.db"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _enrichment_conn() -> Optional[sqlite3.Connection]:
    if not ENRICHMENT_DB.exists():
        return None
    conn = sqlite3.connect(ENRICHMENT_DB, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _format_age(iso_ts: Optional[str]) -> Optional[str]:
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts)
        delta = datetime.now(timezone.utc) - dt
        if delta < timedelta(minutes=1):
            return "just now"
        if delta < timedelta(hours=1):
            return f"{int(delta.total_seconds() // 60)} min ago"
        if delta < timedelta(days=1):
            return f"{int(delta.total_seconds() // 3600)} h ago"
        return f"{delta.days} d ago"
    except Exception:
        return None


# ── Pydantic ──────────────────────────────────────────────────────────────────

class RefreshRequest(BaseModel):
    cve_ids: Optional[list[str]] = Field(
        default=None,
        description="Specific CVE IDs to refresh. If empty, refreshes everything known.",
    )
    limit: Optional[int] = Field(
        default=None,
        ge=1, le=5000,
        description="Cap on number of CVEs to refresh (useful for NVD rate-limit budget).",
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/status")
def enrichment_status(user: dict = Depends(get_current_user)):
    """Return cache freshness counts and last-fetched timestamps for KEV, EPSS, NVD."""
    if not ENRICHMENT_DB.exists():
        return {
            "data": {
                "kev":  {"cached": 0, "last_fetched": None, "age": None, "ttl_days": 7},
                "epss": {"cached": 0, "last_fetched": None, "age": None, "ttl_days": 30},
                "nvd":  {"cached": 0, "last_fetched": None, "age": None, "ttl_days": 90},
                "rag_corpus_files": 0,
                "db_size_bytes": 0,
                "db_path": str(ENRICHMENT_DB),
                "db_exists": False,
            }
        }

    conn = _enrichment_conn()
    try:
        kev_count = conn.execute(
            "SELECT COUNT(*) AS n FROM cve_context WHERE kev_flag=1"
        ).fetchone()["n"]
        epss_count = conn.execute(
            "SELECT COUNT(*) AS n FROM cve_context WHERE epss_score IS NOT NULL"
        ).fetchone()["n"]
        nvd_count = conn.execute(
            "SELECT COUNT(*) AS n FROM cve_context WHERE nvd_cached_at IS NOT NULL"
        ).fetchone()["n"]

        kev_meta = conn.execute(
            "SELECT value FROM kev_meta WHERE key='last_fetched'"
        ).fetchone()
        kev_last = kev_meta["value"] if kev_meta else None

        epss_last_row = conn.execute(
            "SELECT MAX(epss_cached_at) AS m FROM cve_context"
        ).fetchone()
        epss_last = epss_last_row["m"] if epss_last_row else None
        # Fall back to last_attempted so the UI shows a date after any refresh attempt
        if not epss_last:
            try:
                meta_row = conn.execute(
                    "SELECT value FROM epss_meta WHERE key IN ('last_fetched','last_attempted') "
                    "ORDER BY value DESC LIMIT 1"
                ).fetchone()
                if meta_row:
                    epss_last = meta_row["value"]
            except Exception:
                pass

        nvd_last_row = conn.execute(
            "SELECT MAX(nvd_cached_at) AS m FROM cve_context"
        ).fetchone()
        nvd_last = nvd_last_row["m"] if nvd_last_row else None

        rag_dir = ROOT / "data" / "rag_corpus"
        rag_count = sum(1 for _ in rag_dir.rglob("*.txt")) if rag_dir.exists() else 0

        db_size = ENRICHMENT_DB.stat().st_size

        return {
            "data": {
                "kev": {
                    "cached":       kev_count,
                    "last_fetched": kev_last,
                    "age":          _format_age(kev_last),
                    "ttl_days":     7,
                },
                "epss": {
                    "cached":       epss_count,
                    "last_fetched": epss_last,
                    "age":          _format_age(epss_last),
                    "ttl_days":     30,
                },
                "nvd": {
                    "cached":       nvd_count,
                    "last_fetched": nvd_last,
                    "age":          _format_age(nvd_last),
                    "ttl_days":     90,
                },
                "rag_corpus_files": rag_count,
                "db_size_bytes":    db_size,
                "db_path":          str(ENRICHMENT_DB),
                "db_exists":        True,
            }
        }
    finally:
        conn.close()


@router.post("/kev/refresh", status_code=status.HTTP_202_ACCEPTED)
def refresh_kev(
    background_tasks: BackgroundTasks,
    user:             dict = Depends(require_role("admin")),
):
    """Trigger a CISA KEV catalogue refresh in the background."""

    def _run():
        try:
            from enrichment.kev_ingest import fetch_and_cache_kev
            count = fetch_and_cache_kev(force=True)   # always fetch when triggered from UI
            logger.info("KEV refresh complete: %d entries.", count)
        except Exception as exc:
            logger.error("KEV refresh failed: %s", exc, exc_info=True)

    background_tasks.add_task(_run)
    return {"data": {"queued": True, "source": "CISA KEV"}}


@router.post("/epss/refresh", status_code=status.HTTP_202_ACCEPTED)
def refresh_epss(
    payload:          RefreshRequest,
    background_tasks: BackgroundTasks,
    user:             dict = Depends(require_role("admin")),
):
    """Refresh EPSS scores for given CVE list (or all CVEs we already know about).

    Always bypasses the 30-day TTL when called from this endpoint — the analyst
    explicitly requested a refresh.
    """
    cve_ids = payload.cve_ids or _all_known_cve_ids(limit=payload.limit)

    if not cve_ids:
        # Nothing to refresh yet — succeed silently rather than erroring
        return {"data": {"queued": False, "source": "FIRST EPSS", "cve_count": 0,
                         "message": "No CVEs known yet; upload a scan first."}}

    def _run():
        try:
            from enrichment.epss_ingest import enrich_epss
            n = enrich_epss(cve_ids, force=True)
            logger.info("EPSS refresh complete: %d CVEs updated.", n)
        except Exception as exc:
            logger.error("EPSS refresh failed: %s", exc, exc_info=True)

    background_tasks.add_task(_run)
    return {"data": {"queued": True, "source": "FIRST EPSS", "cve_count": len(cve_ids)}}


@router.post("/nvd/refresh", status_code=status.HTTP_202_ACCEPTED)
def refresh_nvd(
    payload:          RefreshRequest,
    background_tasks: BackgroundTasks,
    user:             dict = Depends(require_role("admin")),
):
    """Refresh NVD descriptions / CWEs. Rate-limited; cap with `limit` (default 50).

    Always bypasses the 90-day TTL when called from this endpoint.
    """
    limit   = payload.limit or 50
    cve_ids = payload.cve_ids or _all_known_cve_ids(limit=limit)

    if not cve_ids:
        return {"data": {"queued": False, "source": "NVD API v2", "cve_count": 0,
                         "message": "No CVEs known yet; upload a scan first."}}

    cve_ids = cve_ids[:limit]

    def _run():
        try:
            from enrichment.nvd_ingest import enrich_nvd
            n = enrich_nvd(cve_ids, force=True)
            logger.info("NVD refresh complete: %d CVEs updated.", n)
        except Exception as exc:
            logger.error("NVD refresh failed: %s", exc, exc_info=True)

    background_tasks.add_task(_run)
    return {"data": {"queued": True, "source": "NVD API v2", "cve_count": len(cve_ids)}}


@router.get("/catalog")
def browse_catalog(
    search:   Optional[str] = None,
    vendor:   Optional[str] = None,
    kev_only: bool          = True,
    sort_by:  str           = "kev_added_date",
    order:    str           = "desc",
    limit:    int           = 50,
    offset:   int           = 0,
    user:     dict          = Depends(get_current_user),
):
    """Browse the enrichment catalog with search + filters."""
    if not ENRICHMENT_DB.exists():
        return {"data": [], "total": 0}

    VALID_SORT  = {"kev_added_date", "epss_score", "epss_percentile", "cve_id", "kev_vendor"}
    VALID_ORDER = {"asc", "desc"}
    sort_col = sort_by if sort_by in VALID_SORT else "kev_added_date"
    direction = "DESC" if order.lower() == "desc" else "ASC"

    conn = _enrichment_conn()
    try:
        clauses = []
        params: list = []

        if kev_only:
            clauses.append("kev_flag = 1")

        if vendor:
            clauses.append("LOWER(kev_vendor) = LOWER(?)")
            params.append(vendor)

        if search:
            s = f"%{search}%"
            clauses.append(
                "(cve_id LIKE ? OR LOWER(kev_vendor) LIKE LOWER(?) "
                "OR LOWER(kev_product) LIKE LOWER(?) "
                "OR LOWER(kev_short_description) LIKE LOWER(?))"
            )
            params.extend([s, s, s, s])

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM cve_context {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT cve_id, kev_flag, kev_added_date, kev_vendor, kev_product,
                       kev_required_action, kev_short_description,
                       epss_score, epss_percentile, nvd_cwe, nvd_description
                FROM cve_context {where}
                ORDER BY
                  CASE WHEN {sort_col} IS NULL THEN 1 ELSE 0 END,
                  {sort_col} {direction}
                LIMIT ? OFFSET ?""",
            [*params, limit, offset],
        ).fetchall()

        return {"data": [dict(r) for r in rows], "total": total}
    finally:
        conn.close()


@router.get("/vendors")
def list_vendors(user: dict = Depends(get_current_user)):
    """Return distinct KEV vendors (for filter dropdown)."""
    if not ENRICHMENT_DB.exists():
        return {"data": []}
    conn = _enrichment_conn()
    try:
        rows = conn.execute(
            """SELECT kev_vendor, COUNT(*) AS cnt
               FROM cve_context
               WHERE kev_flag=1 AND kev_vendor IS NOT NULL AND kev_vendor != ''
               GROUP BY kev_vendor ORDER BY cnt DESC"""
        ).fetchall()
        return {"data": [{"vendor": r["kev_vendor"], "count": r["cnt"]} for r in rows]}
    finally:
        conn.close()


@router.get("/cve/{cve_id}")
def cve_detail(cve_id: str, user: dict = Depends(get_current_user)):
    """Inspect the cached enrichment for a single CVE — useful for the UI and the demo."""
    cve_id = cve_id.strip().upper()
    if not ENRICHMENT_DB.exists():
        raise HTTPException(status_code=404, detail="Enrichment cache is empty.")
    conn = _enrichment_conn()
    try:
        row = conn.execute(
            "SELECT * FROM cve_context WHERE cve_id=?", (cve_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"No cached data for {cve_id}.")
        d = dict(row)
        d["kev_age"]  = _format_age(d.get("kev_cached_at"))
        d["epss_age"] = _format_age(d.get("epss_cached_at"))
        d["nvd_age"]  = _format_age(d.get("nvd_cached_at"))
        return {"data": d}
    finally:
        conn.close()


# ── Internal helpers ──────────────────────────────────────────────────────────

def _all_known_cve_ids(limit: Optional[int] = None) -> list[str]:
    """Get every CVE we've seen in jobs (most useful set) + KEV catalog."""
    out: set[str] = set()

    # From the main DB: jobs.cve_list (JSON arrays)
    try:
        from api.db.connection import get_connection
        import json
        conn = get_connection()
        try:
            rows = conn.execute("SELECT cve_list FROM jobs").fetchall()
            for r in rows:
                try:
                    cves = json.loads(r["cve_list"] or "[]")
                    for c in cves:
                        if isinstance(c, str) and c.startswith("CVE-"):
                            out.add(c.upper())
                except Exception:
                    pass
        finally:
            conn.close()
    except Exception as exc:
        logger.debug("Could not pull CVEs from jobs: %s", exc)

    # From KEV catalog
    if ENRICHMENT_DB.exists():
        conn = _enrichment_conn()
        try:
            for r in conn.execute("SELECT cve_id FROM cve_context WHERE kev_flag=1"):
                out.add(r["cve_id"])
        finally:
            conn.close()

    result = sorted(out)
    if limit:
        result = result[:limit]
    return result
