"""Repository for the asset_software table (P4a software inventory)."""

import sqlite3
from datetime import datetime, timezone
from typing import Optional


def upsert(
    conn: sqlite3.Connection,
    asset_id: str,
    product: str,
    version: Optional[str] = None,
    vendor: Optional[str] = None,
    cpe: Optional[str] = None,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO asset_software (asset_id, product, version, vendor, cpe, created_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(asset_id, product, version) DO UPDATE SET
               vendor = excluded.vendor,
               cpe    = excluded.cpe""",
        (asset_id, product, version or "", vendor, cpe, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM asset_software WHERE asset_id=? AND product=? AND version=?",
        (asset_id, product, version or ""),
    ).fetchone()
    return dict(row)


def bulk_replace(
    conn: sqlite3.Connection,
    asset_id: str,
    items: list[dict],
) -> list[dict]:
    """Delete all software for an asset and re-insert from items list."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("DELETE FROM asset_software WHERE asset_id = ?", (asset_id,))
    inserted = []
    for item in items:
        product = item.get("product", "").strip()
        if not product:
            continue
        conn.execute(
            """INSERT OR IGNORE INTO asset_software
               (asset_id, product, version, vendor, cpe, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                asset_id,
                product,
                item.get("version", "") or "",
                item.get("vendor"),
                item.get("cpe"),
                now,
            ),
        )
    conn.commit()
    rows = conn.execute(
        "SELECT * FROM asset_software WHERE asset_id = ? ORDER BY product",
        (asset_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_by_asset(conn: sqlite3.Connection, asset_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM asset_software WHERE asset_id = ? ORDER BY product, version",
        (asset_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all(conn: sqlite3.Connection) -> list[dict]:
    """All software rows joined with hostname for threat-matching purposes."""
    rows = conn.execute(
        """SELECT sw.*, a.hostname, a.ip_address, a.business_unit, a.environment
           FROM asset_software sw
           JOIN assets a ON a.asset_id = sw.asset_id
           ORDER BY sw.asset_id, sw.product""",
    ).fetchall()
    return [dict(r) for r in rows]


def delete_one(conn: sqlite3.Connection, sw_id: int, asset_id: str) -> bool:
    conn.execute(
        "DELETE FROM asset_software WHERE id = ? AND asset_id = ?",
        (sw_id, asset_id),
    )
    conn.commit()
    return conn.execute("SELECT changes()").fetchone()[0] > 0


def get_unique_cpes(conn: sqlite3.Connection) -> list[str]:
    """Return all distinct non-null CPE strings across all assets."""
    rows = conn.execute(
        "SELECT DISTINCT cpe FROM asset_software WHERE cpe IS NOT NULL AND cpe != ''"
    ).fetchall()
    return [r["cpe"] for r in rows]
