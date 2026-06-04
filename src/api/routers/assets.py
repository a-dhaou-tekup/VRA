"""Assets router — Manual CRUD for asset inventory + P4a fleet + software endpoints.

P4a additions:
  - AssetIn/AssetUpdate gain os_version, site, owning_team
  - Fleet filters: environment, site, owning_team, business_unit
  - GET  /api/fleet/summary          — counts grouped by environment+BU
  - GET  /api/assets/{id}/software   — list installed software
  - POST /api/assets/{id}/software   — add one software entry
  - PUT  /api/assets/{id}/software   — replace full software list (bulk)
  - DELETE /api/assets/{id}/software/{sw_id}
  - BulkImport now accepts optional 'software' list per row
"""

import csv
import io
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.repositories import asset_software_repo
from api.utils.asset_classify import infer as classify_asset

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Assets"])

_WRITERS = ("analyst", "remediation_owner", "admin")

VALID_CRITICALITY  = {"low", "medium", "high", "critical"}
VALID_ENVIRONMENTS = {"production", "staging", "dev", "test"}


# ── Schemas ────────────────────────────────────────────────────────────────────

class SoftwareItem(BaseModel):
    product: str
    version: Optional[str] = None
    vendor:  Optional[str] = None
    cpe:     Optional[str] = None


class AssetIn(BaseModel):
    hostname:         str
    ip_address:       str
    business_unit:    str = "IT"
    business_owner:   str = ""
    criticality:      str = Field("medium", description="low|medium|high|critical")
    internet_exposed: bool = False
    environment:      str = Field("production", description="production|staging|dev|test")
    # P4a fleet fields
    os_version:   Optional[str] = None
    site:         Optional[str] = None
    owning_team:  Optional[str] = None
    # cascade dropdown classification
    asset_type:   Optional[str] = None
    platform:     Optional[str] = None


class AssetUpdate(BaseModel):
    hostname:         Optional[str]  = None
    ip_address:       Optional[str]  = None
    business_unit:    Optional[str]  = None
    business_owner:   Optional[str]  = None
    criticality:      Optional[str]  = None
    internet_exposed: Optional[bool] = None
    environment:      Optional[str]  = None
    # P4a
    os_version:   Optional[str] = None
    site:         Optional[str] = None
    owning_team:  Optional[str] = None
    # cascade dropdown classification
    asset_type:   Optional[str] = None
    platform:     Optional[str] = None


def _validate_asset(data: dict) -> None:
    if "criticality" in data and data["criticality"]:
        if data["criticality"].lower() not in VALID_CRITICALITY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"criticality must be one of {sorted(VALID_CRITICALITY)}",
            )
    if "environment" in data and data["environment"]:
        if data["environment"].lower() not in VALID_ENVIRONMENTS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"environment must be one of {sorted(VALID_ENVIRONMENTS)}",
            )


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["internet_exposed"] = bool(d.get("internet_exposed", 0))
    return d


# ── Fleet summary ──────────────────────────────────────────────────────────────

@router.get("/fleet/summary")
def fleet_summary(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Return asset counts grouped by environment and business_unit."""
    by_env = conn.execute(
        "SELECT environment, COUNT(*) AS cnt FROM assets GROUP BY environment ORDER BY environment"
    ).fetchall()
    by_bu = conn.execute(
        "SELECT business_unit, COUNT(*) AS cnt FROM assets GROUP BY business_unit ORDER BY business_unit"
    ).fetchall()
    by_site = conn.execute(
        "SELECT site, COUNT(*) AS cnt FROM assets WHERE site IS NOT NULL GROUP BY site ORDER BY site"
    ).fetchall()
    by_team = conn.execute(
        "SELECT owning_team, COUNT(*) AS cnt FROM assets WHERE owning_team IS NOT NULL GROUP BY owning_team ORDER BY owning_team"
    ).fetchall()
    by_asset_type = conn.execute(
        "SELECT asset_type, COUNT(*) AS cnt FROM assets WHERE asset_type IS NOT NULL GROUP BY asset_type ORDER BY asset_type"
    ).fetchall()
    by_platform = conn.execute(
        "SELECT platform, COUNT(*) AS cnt FROM assets WHERE platform IS NOT NULL GROUP BY platform ORDER BY platform"
    ).fetchall()
    exposed_count = conn.execute(
        "SELECT COUNT(*) AS cnt FROM assets WHERE internet_exposed = 1"
    ).fetchone()["cnt"]
    total = conn.execute("SELECT COUNT(*) AS cnt FROM assets").fetchone()["cnt"]

    return {
        "data": {
            "total": total,
            "internet_exposed": exposed_count,
            "by_environment": [dict(r) for r in by_env],
            "by_business_unit": [dict(r) for r in by_bu],
            "by_site": [dict(r) for r in by_site],
            "by_owning_team": [dict(r) for r in by_team],
            "by_asset_type": [dict(r) for r in by_asset_type],
            "by_platform": [dict(r) for r in by_platform],
        }
    }


# ── Asset list ─────────────────────────────────────────────────────────────────

@router.get("/assets")
def list_assets(
    business_unit:    Optional[str]  = Query(None),
    criticality:      Optional[str]  = Query(None),
    internet_exposed: Optional[bool] = Query(None),
    environment:      Optional[str]  = Query(None),
    site:             Optional[str]  = Query(None),
    owning_team:      Optional[str]  = Query(None),
    search:           Optional[str]  = Query(None, description="Substring match on hostname or IP"),
    limit:  int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict = Depends(get_current_user),
):
    sql    = "SELECT * FROM assets WHERE 1=1"
    params: list = []

    if business_unit:
        sql += " AND business_unit = ?"; params.append(business_unit)
    if criticality:
        sql += " AND criticality = ?";   params.append(criticality)
    if internet_exposed is not None:
        sql += " AND internet_exposed = ?"; params.append(int(internet_exposed))
    if environment:
        sql += " AND environment = ?";   params.append(environment)
    if site:
        sql += " AND site = ?";          params.append(site)
    if owning_team:
        sql += " AND owning_team = ?";   params.append(owning_team)
    if search:
        sql += " AND (hostname LIKE ? OR ip_address LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    sql += " ORDER BY hostname LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(sql, params).fetchall()
    return {"data": [_row_to_dict(r) for r in rows], "total": len(rows)}


# ── Get one ────────────────────────────────────────────────────────────────────

@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(get_current_user),
):
    row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    d = _row_to_dict(row)
    d["software"] = asset_software_repo.get_by_asset(conn, asset_id)
    return {"data": d}


# ── Create ─────────────────────────────────────────────────────────────────────

@router.post("/assets", status_code=status.HTTP_201_CREATED)
def create_asset(
    asset: AssetIn,
    conn:  sqlite3.Connection = Depends(get_db),
    user:  dict = Depends(require_role(*_WRITERS)),
):
    _validate_asset(asset.model_dump())

    existing = conn.execute(
        "SELECT asset_id FROM assets WHERE hostname = ? OR ip_address = ?",
        (asset.hostname, asset.ip_address),
    ).fetchone()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Asset already exists (id={existing['asset_id']}).",
        )

    asset_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO assets
           (asset_id, hostname, ip_address, business_owner, business_unit,
            criticality, environment, internet_exposed,
            os_version, site, owning_team, asset_type, platform,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            asset_id,
            asset.hostname, asset.ip_address,
            asset.business_owner, asset.business_unit,
            asset.criticality.lower(), asset.environment.lower(),
            int(asset.internet_exposed),
            asset.os_version, asset.site, asset.owning_team,
            asset.asset_type, asset.platform,
            now, now,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    return {"data": _row_to_dict(row)}


# ── Update ─────────────────────────────────────────────────────────────────────

@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: str,
    patch:    AssetUpdate,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role(*_WRITERS)),
):
    existing = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    updates = patch.model_dump(exclude_none=True)
    if not updates:
        return {"data": _row_to_dict(existing)}
    _validate_asset(updates)

    set_parts: list = []
    params: list = []
    for key, value in updates.items():
        if key == "internet_exposed":
            set_parts.append("internet_exposed = ?")
            params.append(int(bool(value)))
        elif key in {"criticality", "environment"} and isinstance(value, str):
            set_parts.append(f"{key} = ?")
            params.append(value.lower())
        else:
            set_parts.append(f"{key} = ?")
            params.append(value)

    set_parts.append("updated_at = ?")
    params.append(datetime.now(timezone.utc).isoformat())
    params.append(asset_id)

    conn.execute(f"UPDATE assets SET {', '.join(set_parts)} WHERE asset_id = ?", params)
    conn.commit()
    row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    return {"data": _row_to_dict(row)}


# ── Delete ─────────────────────────────────────────────────────────────────────

@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role("admin")),
):
    row = conn.execute("SELECT asset_id FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    job_ref = conn.execute(
        "SELECT job_id FROM jobs WHERE asset_ids LIKE ? LIMIT 1", (f"%{asset_id}%",)
    ).fetchone()
    if job_ref:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete: referenced by job '{job_ref['job_id']}'.",
        )
    conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
    conn.commit()


# ── Software sub-endpoints ─────────────────────────────────────────────────────

@router.get("/assets/{asset_id}/software")
def list_software(
    asset_id: str,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(get_current_user),
):
    _require_asset(conn, asset_id)
    return {"data": asset_software_repo.get_by_asset(conn, asset_id)}


@router.post("/assets/{asset_id}/software", status_code=status.HTTP_201_CREATED)
def add_software(
    asset_id: str,
    item:     SoftwareItem,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role(*_WRITERS)),
):
    _require_asset(conn, asset_id)
    row = asset_software_repo.upsert(
        conn, asset_id,
        product=item.product, version=item.version,
        vendor=item.vendor, cpe=item.cpe,
    )
    return {"data": row}


@router.put("/assets/{asset_id}/software")
def replace_software(
    asset_id: str,
    items:    List[SoftwareItem],
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role(*_WRITERS)),
):
    """Replace the full software inventory for an asset."""
    _require_asset(conn, asset_id)
    rows = asset_software_repo.bulk_replace(
        conn, asset_id,
        [i.model_dump() for i in items],
    )
    return {"data": rows}


@router.delete("/assets/{asset_id}/software/{sw_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_software(
    asset_id: str,
    sw_id:    int,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role(*_WRITERS)),
):
    _require_asset(conn, asset_id)
    ok = asset_software_repo.delete_one(conn, sw_id, asset_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Software entry {sw_id} not found.")


def _require_asset(conn: sqlite3.Connection, asset_id: str) -> None:
    row = conn.execute("SELECT asset_id FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")


# ── Global software list ───────────────────────────────────────────────────────

@router.get("/software")
def list_all_software(
    limit:  int = Query(500, ge=1, le=5000),
    offset: int = Query(0,   ge=0),
    search: Optional[str] = Query(None, description="Substring on product/vendor/hostname"),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict = Depends(get_current_user),
):
    """List all installed-software entries joined with asset hostname."""
    sql    = """SELECT sw.*, a.hostname, a.ip_address
                FROM asset_software sw
                JOIN assets a ON a.asset_id = sw.asset_id
                WHERE 1=1"""
    params: list = []
    if search:
        sql += " AND (sw.product LIKE ? OR sw.vendor LIKE ? OR a.hostname LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    count = conn.execute(
        sql.replace("sw.*, a.hostname, a.ip_address", "COUNT(*)"), params
    ).fetchone()[0]
    sql += " ORDER BY a.hostname, sw.product LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return {"data": [dict(r) for r in rows], "total": count}


@router.post("/software/csv", status_code=201)
def bulk_software_csv(
    file: UploadFile = File(..., description="CSV with columns: hostname, product, version, vendor, cpe"),
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(require_role(*_WRITERS)),
):
    """Upload a CSV to bulk-upsert installed software across any number of assets.

    Required column:  hostname  (matched to assets.hostname) OR asset_id
    Required column:  product
    Optional columns: version, vendor, cpe

    Example CSV
    -----------
    hostname,product,version,vendor,cpe
    prod-api-01,log4j-core,2.14.1,Apache,cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
    prod-web-01,nginx,1.24.0,nginx Inc,
    """
    now = datetime.now(timezone.utc).isoformat()
    content = file.file.read()
    text    = content.decode("utf-8-sig", errors="replace")
    reader  = csv.DictReader(io.StringIO(text))

    # Normalise header names to lowercase-stripped
    reader.fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]

    inserted = 0; skipped = 0
    errors: list[str] = []

    # Build hostname → asset_id lookup cache
    host_cache: dict[str, str] = {}

    def _resolve(row: dict) -> Optional[str]:
        aid = (row.get("asset_id") or "").strip()
        if aid:
            return aid
        hostname = (row.get("hostname") or "").strip()
        if not hostname:
            return None
        if hostname not in host_cache:
            r = conn.execute(
                "SELECT asset_id FROM assets WHERE hostname = ?", (hostname,)
            ).fetchone()
            host_cache[hostname] = r["asset_id"] if r else ""
        return host_cache[hostname] or None

    for line_no, row in enumerate(reader, start=2):
        product = (row.get("product") or "").strip()
        if not product:
            skipped += 1
            continue
        asset_id_resolved = _resolve(row)
        if not asset_id_resolved:
            errors.append(f"Line {line_no}: hostname/asset_id not found — {row}")
            continue
        version = (row.get("version") or "").strip() or None
        vendor  = (row.get("vendor")  or "").strip() or None
        cpe     = (row.get("cpe")     or "").strip() or None
        try:
            conn.execute(
                """INSERT INTO asset_software
                       (asset_id, product, version, vendor, cpe, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(asset_id, product, version) DO UPDATE SET
                       vendor = excluded.vendor,
                       cpe    = excluded.cpe""",
                (asset_id_resolved, product, version or "", vendor, cpe, now),
            )
            inserted += 1
        except Exception as exc:
            errors.append(f"Line {line_no}: {exc}")

    conn.commit()
    total_sw = conn.execute("SELECT COUNT(*) FROM asset_software").fetchone()[0]
    return {
        "data": {
            "inserted": inserted,
            "skipped":  skipped,
            "errors":   errors[:20],
            "total_software_entries": total_sw,
        }
    }


# ── Bulk CSV import (extended with fleet columns + optional software list) ─────

class BulkImportRow(BaseModel):
    hostname:         str
    ip_address:       str
    business_unit:    str = "IT"
    business_owner:   str = ""
    criticality:      str = "medium"
    internet_exposed: bool = False
    environment:      str = "production"
    # P4a fleet
    os_version:   Optional[str] = None
    site:         Optional[str] = None
    owning_team:  Optional[str] = None
    # cascade dropdown classification
    asset_type:   Optional[str] = None
    platform:     Optional[str] = None
    # P4a software — optional inline list
    software: Optional[List[SoftwareItem]] = None


class BulkImport(BaseModel):
    assets: list[BulkImportRow]
    upsert: bool = Field(True, description="Update existing assets matched by hostname")


# ── Backfill asset_type / platform for unclassified assets ────────────────────

@router.post("/assets/classify", status_code=status.HTTP_200_OK)
def backfill_classification(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(require_role(*_WRITERS)),
):
    """Infer and write asset_type / platform for all assets missing those fields."""
    rows = conn.execute(
        "SELECT asset_id, hostname, os_version FROM assets WHERE asset_type IS NULL OR platform IS NULL"
    ).fetchall()

    updated = 0
    now = datetime.now(timezone.utc).isoformat()
    for r in rows:
        a_type, a_plat = classify_asset(r["hostname"], r["os_version"] or "")
        if a_type or a_plat:
            conn.execute(
                """UPDATE assets SET
                       asset_type = COALESCE(asset_type, ?),
                       platform   = COALESCE(platform, ?),
                       updated_at = ?
                   WHERE asset_id = ?""",
                (a_type, a_plat, now, r["asset_id"]),
            )
            updated += 1

    conn.commit()
    return {"data": {"total_unclassified": len(rows), "updated": updated}}


@router.post("/assets/bulk", status_code=status.HTTP_200_OK)
def bulk_import(
    payload: BulkImport,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict = Depends(require_role(*_WRITERS)),
):
    inserted = 0; updated = 0; skipped = 0; sw_upserted = 0
    errors: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    for row in payload.assets:
        try:
            _validate_asset(row.model_dump())
        except HTTPException as exc:
            errors.append(f"{row.hostname}: {exc.detail}"); continue

        # Auto-infer asset_type / platform from hostname + os_version if not supplied
        a_type = row.asset_type
        a_plat = row.platform
        if not a_type or not a_plat:
            inferred_type, inferred_plat = classify_asset(row.hostname, row.os_version or "")
            a_type = a_type or inferred_type
            a_plat = a_plat or inferred_plat

        existing = conn.execute(
            "SELECT asset_id FROM assets WHERE hostname = ?", (row.hostname,)
        ).fetchone()

        if existing is not None:
            if not payload.upsert:
                skipped += 1; continue
            aid = existing["asset_id"]
            conn.execute(
                """UPDATE assets
                   SET ip_address=?, business_unit=?, business_owner=?,
                       criticality=?, environment=?, internet_exposed=?,
                       os_version=?, site=?, owning_team=?,
                       asset_type=?, platform=?, updated_at=?
                   WHERE asset_id=?""",
                (
                    row.ip_address, row.business_unit, row.business_owner,
                    row.criticality.lower(), row.environment.lower(),
                    int(row.internet_exposed),
                    row.os_version, row.site, row.owning_team,
                    a_type, a_plat,
                    now, aid,
                ),
            )
            updated += 1
        else:
            aid = str(uuid.uuid4())
            conn.execute(
                """INSERT INTO assets
                   (asset_id, hostname, ip_address, business_owner, business_unit,
                    criticality, environment, internet_exposed,
                    os_version, site, owning_team, asset_type, platform,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    aid, row.hostname, row.ip_address,
                    row.business_owner, row.business_unit,
                    row.criticality.lower(), row.environment.lower(),
                    int(row.internet_exposed),
                    row.os_version, row.site, row.owning_team,
                    a_type, a_plat,
                    now, now,
                ),
            )
            inserted += 1

        # Software sub-list
        if row.software:
            result = asset_software_repo.bulk_replace(
                conn, aid,
                [s.model_dump() for s in row.software],
            )
            sw_upserted += len(result)

    conn.commit()
    return {
        "data": {
            "inserted":     inserted,
            "updated":      updated,
            "skipped":      skipped,
            "sw_upserted":  sw_upserted,
            "errors":       errors,
        }
    }
