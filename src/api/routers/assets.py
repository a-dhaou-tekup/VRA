"""Assets router — Manual CRUD for asset inventory.

Lets users build / edit their real asset inventory directly via the UI,
without needing to edit CSV files. Source of ground truth for risk scoring.
"""

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.auth import get_current_user, require_role
from api.db.connection import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/assets", tags=["Assets"])

_WRITERS = ("analyst", "remediation_owner", "admin")

VALID_CRITICALITY = {"low", "medium", "high", "critical"}
VALID_ENVIRONMENTS = {"production", "staging", "dev", "test"}


# ── Schemas ────────────────────────────────────────────────────────────────────

class AssetIn(BaseModel):
    hostname:         str
    ip_address:       str
    business_unit:    str = "IT"
    business_owner:   str = ""
    criticality:      str = Field("medium", description="low|medium|high|critical")
    internet_exposed: bool = False
    environment:      str = Field("production", description="production|staging|dev|test")


class AssetUpdate(BaseModel):
    hostname:         Optional[str]  = None
    ip_address:       Optional[str]  = None
    business_unit:    Optional[str]  = None
    business_owner:   Optional[str]  = None
    criticality:      Optional[str]  = None
    internet_exposed: Optional[bool] = None
    environment:      Optional[str]  = None


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


# ── List ───────────────────────────────────────────────────────────────────────

@router.get("")
def list_assets(
    business_unit: Optional[str] = Query(None),
    criticality:   Optional[str] = Query(None),
    internet_exposed: Optional[bool] = Query(None),
    search:        Optional[str] = Query(None, description="Substring match on hostname or IP"),
    limit:  int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict = Depends(get_current_user),
):
    sql = "SELECT * FROM assets WHERE 1=1"
    params: list = []
    if business_unit:
        sql += " AND business_unit = ?"
        params.append(business_unit)
    if criticality:
        sql += " AND criticality = ?"
        params.append(criticality)
    if internet_exposed is not None:
        sql += " AND internet_exposed = ?"
        params.append(int(internet_exposed))
    if search:
        sql += " AND (hostname LIKE ? OR ip_address LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY hostname LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(sql, params).fetchall()
    return {"data": [_row_to_dict(r) for r in rows], "total": len(rows)}


# ── Get one ────────────────────────────────────────────────────────────────────

@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(get_current_user),
):
    row = conn.execute(
        "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found.",
        )
    return {"data": _row_to_dict(row)}


# ── Create ─────────────────────────────────────────────────────────────────────

@router.post("", status_code=status.HTTP_201_CREATED)
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
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Asset with hostname '{asset.hostname}' or IP '{asset.ip_address}' already exists (id={existing['asset_id']}).",
        )

    asset_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO assets
           (asset_id, hostname, ip_address, business_owner, business_unit,
            criticality, environment, internet_exposed, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            asset_id,
            asset.hostname,
            asset.ip_address,
            asset.business_owner,
            asset.business_unit,
            asset.criticality.lower(),
            asset.environment.lower(),
            int(asset.internet_exposed),
            now,
            now,
        ),
    )
    conn.commit()

    row = conn.execute(
        "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
    ).fetchone()
    return {"data": _row_to_dict(row)}


# ── Update ─────────────────────────────────────────────────────────────────────

@router.patch("/{asset_id}")
def update_asset(
    asset_id: str,
    patch:    AssetUpdate,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role(*_WRITERS)),
):
    existing = conn.execute(
        "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
    ).fetchone()
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found.",
        )

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

    conn.execute(
        f"UPDATE assets SET {', '.join(set_parts)} WHERE asset_id = ?",
        params,
    )
    conn.commit()

    row = conn.execute(
        "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
    ).fetchone()
    return {"data": _row_to_dict(row)}


# ── Delete ─────────────────────────────────────────────────────────────────────

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role("admin")),
):
    row = conn.execute(
        "SELECT asset_id FROM assets WHERE asset_id = ?", (asset_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found.",
        )

    # Refuse delete if any jobs reference this asset
    job_ref = conn.execute(
        "SELECT job_id FROM jobs WHERE asset_ids LIKE ? LIMIT 1",
        (f"%{asset_id}%",),
    ).fetchone()
    if job_ref is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete asset: it is referenced by job '{job_ref['job_id']}'.",
        )

    conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
    conn.commit()


# ── Bulk CSV import ────────────────────────────────────────────────────────────

class BulkImportRow(BaseModel):
    hostname:         str
    ip_address:       str
    business_unit:    str = "IT"
    business_owner:   str = ""
    criticality:      str = "medium"
    internet_exposed: bool = False
    environment:      str = "production"


class BulkImport(BaseModel):
    assets: list[BulkImportRow]
    upsert: bool = Field(True, description="If true, update existing assets matched by hostname")


@router.post("/bulk", status_code=status.HTTP_200_OK)
def bulk_import(
    payload: BulkImport,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict = Depends(require_role(*_WRITERS)),
):
    inserted = 0
    updated = 0
    skipped = 0
    errors: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    for row in payload.assets:
        try:
            _validate_asset(row.model_dump())
        except HTTPException as exc:
            errors.append(f"{row.hostname}: {exc.detail}")
            continue

        existing = conn.execute(
            "SELECT asset_id FROM assets WHERE hostname = ?", (row.hostname,)
        ).fetchone()

        if existing is not None:
            if not payload.upsert:
                skipped += 1
                continue
            conn.execute(
                """UPDATE assets
                   SET ip_address = ?, business_unit = ?, business_owner = ?,
                       criticality = ?, environment = ?, internet_exposed = ?, updated_at = ?
                   WHERE asset_id = ?""",
                (
                    row.ip_address, row.business_unit, row.business_owner,
                    row.criticality.lower(), row.environment.lower(),
                    int(row.internet_exposed), now, existing["asset_id"],
                ),
            )
            updated += 1
        else:
            conn.execute(
                """INSERT INTO assets
                   (asset_id, hostname, ip_address, business_owner, business_unit,
                    criticality, environment, internet_exposed, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), row.hostname, row.ip_address,
                    row.business_owner, row.business_unit,
                    row.criticality.lower(), row.environment.lower(),
                    int(row.internet_exposed), now, now,
                ),
            )
            inserted += 1

    conn.commit()
    return {
        "data": {
            "inserted": inserted,
            "updated":  updated,
            "skipped":  skipped,
            "errors":   errors,
        }
    }
