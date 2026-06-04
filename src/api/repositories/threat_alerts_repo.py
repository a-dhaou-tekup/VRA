"""Repository for the threat_alerts table (P4b threat-exposure matching)."""

import sqlite3
from datetime import datetime, timezone
from typing import Optional


def upsert_alert(
    conn: sqlite3.Connection,
    asset_id: str,
    cve_id: str,
    source: str,
    severity: Optional[str],
    epss_score: float,
    is_kev: bool,
    matched_cpe: Optional[str],
    matched_product: Optional[str],
    matched_version: Optional[str],
    alert_type: str,
) -> dict:
    """Insert or update a threat alert (unique on asset_id+cve_id).

    On conflict: refresh severity, epss_score, is_kev, alert_type and updated_at.
    Status is not overwritten (an already-dismissed alert keeps its status).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO threat_alerts
               (asset_id, cve_id, source, severity, epss_score, is_kev,
                matched_cpe, matched_product, matched_version,
                alert_type, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
           ON CONFLICT(asset_id, cve_id) DO UPDATE SET
               severity        = excluded.severity,
               epss_score      = excluded.epss_score,
               is_kev          = excluded.is_kev,
               matched_cpe     = excluded.matched_cpe,
               matched_product = excluded.matched_product,
               matched_version = excluded.matched_version,
               alert_type      = excluded.alert_type,
               updated_at      = excluded.updated_at,
               status = CASE
                   WHEN excluded.is_kev = 1 AND threat_alerts.status != 'open' THEN 'open'
                   ELSE threat_alerts.status
               END""",
        (
            asset_id, cve_id, source, severity, epss_score,
            int(is_kev), matched_cpe, matched_product, matched_version,
            alert_type, now, now,
        ),
    )
    # Caller is responsible for committing — no per-row commit here.
    row = conn.execute(
        "SELECT * FROM threat_alerts WHERE asset_id=? AND cve_id=?",
        (asset_id, cve_id),
    ).fetchone()
    return dict(row)


# Whitelisted sort expressions.  Keys are the column names the frontend may
# request; values are the raw SQL ORDER BY fragment (no user input injected).
_SORT_EXPRS: dict[str, str] = {
    "cve_id":          "ta.cve_id",
    "asset_id":        "a.hostname",          # sort by hostname for readability
    "hostname":        "a.hostname",
    "alert_type":      "ta.alert_type",
    "severity": (
        "CASE ta.severity "
        "WHEN 'CRITICAL' THEN 4 "
        "WHEN 'HIGH'     THEN 3 "
        "WHEN 'MEDIUM'   THEN 2 "
        "WHEN 'LOW'      THEN 1 "
        "ELSE 0 END"
    ),
    "epss_score":      "ta.epss_score",
    "is_kev":          "ta.is_kev",
    "matched_product": "ta.matched_product",
    "status":          "ta.status",
    "created_at":      "ta.created_at",
    "updated_at":      "ta.updated_at",
}
_DEFAULT_ORDER = "ta.is_kev DESC, ta.epss_score DESC, ta.created_at DESC"


def get_all(
    conn: sqlite3.Connection,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    asset_id: Optional[str] = None,
    is_kev: Optional[bool] = None,
    sort_by:  str = "is_kev",
    sort_dir: str = "desc",
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Return (rows, total_count) with optional filters and server-side sort.

    sort_by  — one of the keys in _SORT_EXPRS (unknown values fall back to default)
    sort_dir — 'asc' | 'desc'  (anything else treated as 'desc')
    """
    clauses = ["1=1"]
    params: list = []
    if status:
        clauses.append("ta.status = ?");    params.append(status)
    if alert_type:
        clauses.append("ta.alert_type = ?"); params.append(alert_type)
    if asset_id:
        clauses.append("ta.asset_id = ?");  params.append(asset_id)
    if is_kev is not None:
        clauses.append("ta.is_kev = ?");    params.append(int(is_kev))

    where = " AND ".join(clauses)

    # Build ORDER BY — always falls back to a safe default for unknown columns
    sort_expr = _SORT_EXPRS.get(sort_by, "")
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
    order_by  = f"{sort_expr} {direction}, {_DEFAULT_ORDER}" if sort_expr else _DEFAULT_ORDER

    count = conn.execute(
        f"SELECT COUNT(*) FROM threat_alerts ta WHERE {where}", params
    ).fetchone()[0]

    rows = conn.execute(
        f"""SELECT ta.*, a.hostname, a.ip_address, a.business_unit, a.environment
            FROM threat_alerts ta
            JOIN assets a ON a.asset_id = ta.asset_id
            WHERE {where}
            ORDER BY {order_by}
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    ).fetchall()
    return [dict(r) for r in rows], count


def get_by_asset(conn: sqlite3.Connection, asset_id: str) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM threat_alerts
           WHERE asset_id = ? AND status = 'open'
           ORDER BY is_kev DESC, epss_score DESC""",
        (asset_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def update_status(conn: sqlite3.Connection, alert_id: int, new_status: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE threat_alerts SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now, alert_id),
    )
    conn.commit()
    return conn.execute("SELECT changes()").fetchone()[0] > 0


def summary_counts(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        """SELECT
               COUNT(*)                                         AS total_open,
               SUM(CASE WHEN is_kev   = 1 THEN 1 ELSE 0 END)  AS kev_alerts,
               SUM(CASE WHEN alert_type='high_epss' THEN 1 ELSE 0 END) AS high_epss_alerts,
               COUNT(DISTINCT asset_id)                         AS impacted_assets
           FROM threat_alerts WHERE status = 'open'"""
    ).fetchone()
    return dict(rows) if rows else {}
