"""Jobs repository — full CRUD for the jobs table."""

import csv
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_json_loads(v, default=None):
    if default is None:
        default = []
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


# ── Read operations ───────────────────────────────────────────────────────────

# Whitelisted sort expressions for jobs — no user input reaches SQL
_JOB_SORT_EXPRS: dict[str, str] = {
    "created_at":           "created_at",
    "due_date":             "due_date",
    "risk_score_max":       "risk_score_max",
    "max_risk_level": (
        "CASE max_risk_level "
        "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
        "WHEN 'MEDIUM'   THEN 2 WHEN 'LOW'  THEN 1 ELSE 0 END"
    ),
    "status":               "status",
    "main_product":         "main_product",
    "sla_days":             "sla_days",
    "kev_present":          "kev_present",
    "affected_asset_count": "affected_asset_count",
    "cve_count":            "cve_count",
}
_JOB_DEFAULT_ORDER = "created_at DESC"


def get_all_jobs(
    conn: sqlite3.Connection,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    business_unit: Optional[str] = None,
    kev_only: bool = False,
    sort_by:  str = "created_at",
    sort_dir: str = "desc",
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Return (rows, total_count).  sort_by / sort_dir use the whitelist above."""
    clauses: list[str] = []
    params: list = []

    if status:        clauses.append("status = ?");        params.append(status)
    if risk_level:    clauses.append("max_risk_level = ?"); params.append(risk_level)
    if business_unit: clauses.append("business_unit = ?"); params.append(business_unit)
    if kev_only:      clauses.append("kev_present = 1")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    sort_expr = _JOB_SORT_EXPRS.get(sort_by, "")
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
    order_by  = f"{sort_expr} {direction}, {_JOB_DEFAULT_ORDER}" if sort_expr else _JOB_DEFAULT_ORDER

    total = conn.execute(f"SELECT COUNT(*) FROM jobs {where}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM jobs {where} ORDER BY {order_by} LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return [dict(r) for r in rows], total


def get_job_by_id(conn: sqlite3.Connection, job_id: str) -> dict | None:
    cursor = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_job_by_fingerprint(conn: sqlite3.Connection, fingerprint: str) -> dict | None:
    cursor = conn.execute("SELECT * FROM jobs WHERE job_fingerprint = ?", (fingerprint,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_jobs_by_status(conn: sqlite3.Connection, statuses: list[str]) -> list[dict]:
    placeholders = ", ".join("?" * len(statuses))
    cursor = conn.execute(
        f"SELECT * FROM jobs WHERE status IN ({placeholders}) ORDER BY created_at DESC",
        statuses,
    )
    return [dict(row) for row in cursor.fetchall()]


def get_overdue_jobs(conn: sqlite3.Connection) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT * FROM jobs
           WHERE due_date IS NOT NULL
             AND due_date < ?
             AND status NOT IN ('DONE', 'CLOSED')
           ORDER BY due_date ASC""",
        (now,),
    )
    return [dict(row) for row in cursor.fetchall()]


def count_by_status(conn: sqlite3.Connection) -> dict:
    cursor = conn.execute("SELECT status, COUNT(*) AS cnt FROM jobs GROUP BY status")
    return {row["status"]: row["cnt"] for row in cursor.fetchall()}


def count_by_risk_level(conn: sqlite3.Connection) -> dict:
    cursor = conn.execute(
        "SELECT max_risk_level, COUNT(*) AS cnt FROM jobs GROUP BY max_risk_level"
    )
    return {row["max_risk_level"]: row["cnt"] for row in cursor.fetchall()}


# ── Write operations ──────────────────────────────────────────────────────────

def upsert_job(conn: sqlite3.Connection, job_data: dict) -> str:
    """Insert or update a job by job_fingerprint. Returns job_id."""
    now = datetime.now(timezone.utc).isoformat()
    fingerprint = job_data.get("job_fingerprint")

    # If we have a fingerprint, try to update existing record
    if fingerprint:
        existing = get_job_by_fingerprint(conn, fingerprint)
        if existing:
            job_id = existing["job_id"]
            update = {k: v for k, v in job_data.items() if k not in ("job_id", "created_at")}
            update["updated_at"] = now
            set_clause = ", ".join(f"{k} = ?" for k in update)
            conn.execute(
                f"UPDATE jobs SET {set_clause} WHERE job_id = ?",
                [*update.values(), job_id],
            )
            conn.commit()
            return job_id

    job_id = job_data.get("job_id") or str(uuid.uuid4())

    fields = {
        "job_id":               job_id,
        "job_fingerprint":      fingerprint,
        "asset_ids":            job_data.get("asset_ids"),
        "cve_list":             job_data.get("cve_list"),
        "main_product":         job_data.get("main_product"),
        "plugin_family":        job_data.get("plugin_family"),
        "max_risk_level":       job_data.get("max_risk_level"),
        "risk_score_max":       job_data.get("risk_score_max"),
        "business_owner":       job_data.get("business_owner"),
        "business_unit":        job_data.get("business_unit"),
        "environment":          job_data.get("environment"),
        "kev_present":          int(bool(job_data.get("kev_present", 0))),
        "kev_cves":             job_data.get("kev_cves"),
        "affected_asset_count": job_data.get("affected_asset_count"),
        "cve_count":            job_data.get("cve_count"),
        "score_breakdown":      job_data.get("score_breakdown"),
        "sla_days":             job_data.get("sla_days"),
        "created_at":           job_data.get("created_at", now),
        "due_date":             job_data.get("due_date"),
        "status":               job_data.get("status", "TO_DO"),
        "triage_decision":      job_data.get("triage_decision"),
        "assigned_team":        job_data.get("assigned_team"),
        "closed_at":            job_data.get("closed_at"),
        "fixed_at":             job_data.get("fixed_at"),
        "updated_at":           now,
        # P2 columns (may be absent in older CSV seeds)
        "sla_paused_at":        job_data.get("sla_paused_at"),
        "sla_paused_days":      job_data.get("sla_paused_days", 0),
        "lifecycle_note":       job_data.get("lifecycle_note"),
    }

    col_list    = ", ".join(fields.keys())
    placeholders = ", ".join("?" * len(fields))
    conn.execute(
        f"INSERT OR REPLACE INTO jobs ({col_list}) VALUES ({placeholders})",
        list(fields.values()),
    )
    conn.commit()
    return job_id


def update_job_status(
    conn: sqlite3.Connection,
    job_id: str,
    new_status: str,
    changed_by: str,
    comment: Optional[str] = None,
) -> bool:
    existing = get_job_by_id(conn, job_id)
    if not existing:
        return False

    old_status = existing["status"]
    now = datetime.now(timezone.utc).isoformat()

    set_parts = ["status = ?", "updated_at = ?"]
    params: list = [new_status, now]

    if new_status in ("DONE", "CLOSED"):
        set_parts.append("fixed_at = ?")
        params.append(now)
    if new_status == "CLOSED":
        set_parts.append("closed_at = ?")
        params.append(now)

    params.append(job_id)
    conn.execute(f"UPDATE jobs SET {', '.join(set_parts)} WHERE job_id = ?", params)

    from api.repositories.events_repo import write_event
    write_event(conn, job_id, "STATUS_CHANGE", old_status, new_status, changed_by, comment)

    conn.commit()
    return True


def update_triage(
    conn: sqlite3.Connection,
    job_id: str,
    triage_decision: str,
    assigned_team: Optional[str],
    changed_by: str,
    comment: Optional[str] = None,
) -> bool:
    existing = get_job_by_id(conn, job_id)
    if not existing:
        return False

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE jobs SET triage_decision = ?, assigned_team = ?, updated_at = ? WHERE job_id = ?",
        (triage_decision, assigned_team, now, job_id),
    )

    from api.repositories.events_repo import write_event
    write_event(conn, job_id, "TRIAGE", None, triage_decision, changed_by, comment)

    conn.commit()
    return True


# ── CSV seeding ───────────────────────────────────────────────────────────────

def seed_from_csv(conn: sqlite3.Connection, csv_path: Path) -> int:
    """Read remediation_jobs.csv and upsert all rows. Returns number of rows processed."""
    count = 0
    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                job: dict = {k: (v if v != "" else None) for k, v in row.items()}

                for f in ("sla_days", "affected_asset_count", "cve_count"):
                    if job.get(f) is not None:
                        try:
                            job[f] = int(float(job[f]))
                        except (ValueError, TypeError):
                            job[f] = None

                if job.get("risk_score_max") is not None:
                    try:
                        job["risk_score_max"] = float(job["risk_score_max"])
                    except (ValueError, TypeError):
                        job["risk_score_max"] = None

                if job.get("kev_present") is not None:
                    try:
                        job["kev_present"] = int(float(job["kev_present"]))
                    except (ValueError, TypeError):
                        job["kev_present"] = 0

                upsert_job(conn, job)
                count += 1
    except Exception as exc:
        logger.error("seed_from_csv: error reading %s — %s", csv_path, exc)
    return count
