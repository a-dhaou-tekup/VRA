"""Uploads router — Module 11: Manual File Upload."""

import logging
import os
import sqlite3
import uuid
from typing import Optional

from fastapi import (
    APIRouter, BackgroundTasks, Depends, File, Form, HTTPException,
    UploadFile, status,
)

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.services.upload_service import (
    create_upload_record,
    save_upload_file,
    run_upload_pipeline,
    safe_json_loads,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/uploads", tags=["Uploads"])

MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
VALID_SCANNER_TYPES = {"nessus", "openvas", "csv_generic", "auto"}

_WRITERS = ("analyst", "remediation_owner", "admin")


# ── Upload a file ─────────────────────────────────────────────────────────────

@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_file(
    background_tasks: BackgroundTasks,
    file:             UploadFile = File(...),
    scanner_type:     str        = Form("auto"),
    uploaded_by:      str        = Form("user"),
    conn:             sqlite3.Connection = Depends(get_db),
    user:             dict       = Depends(require_role(*_WRITERS)),
):
    if scanner_type not in VALID_SCANNER_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scanner_type '{scanner_type}'. Valid: {sorted(VALID_SCANNER_TYPES)}",
        )

    # Pre-check content length if available
    content_length = file.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {MAX_UPLOAD_SIZE_MB} MB",
        )

    upload_id = str(uuid.uuid4())

    # Save file to disk and compute SHA-256
    try:
        saved_path, sha256, file_size = await save_upload_file(file, upload_id)
    except Exception as exc:
        logger.error("Failed to save uploaded file: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File storage error: {exc}",
        ) from exc

    # Enforce size limit after saving (handles chunked uploads without Content-Length)
    if file_size > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        saved_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {MAX_UPLOAD_SIZE_MB} MB",
        )

    original_filename = file.filename or "unknown"
    record = create_upload_record(
        conn,
        upload_id=upload_id,
        filename=saved_path.name,
        original_filename=original_filename,
        sha256=sha256,
        scanner_type=scanner_type,
        file_size=file_size,
        uploaded_by=uploaded_by,
    )

    # Trigger background pipeline
    from api.db.connection import DB_PATH

    background_tasks.add_task(
        run_upload_pipeline,
        upload_id=upload_id,
        file_path=str(saved_path),
        scanner_type=scanner_type,
        db_path=str(DB_PATH),
    )

    # Mark pipeline as triggered
    conn.execute(
        "UPDATE uploads SET pipeline_triggered = 1 WHERE id = ?", (upload_id,)
    )
    conn.commit()
    record["pipeline_triggered"] = 1

    return {"data": record}


# ── List uploads ──────────────────────────────────────────────────────────────

@router.get("")
def list_uploads(
    limit:  int = 50,
    offset: int = 0,
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    cursor = conn.execute(
        "SELECT * FROM uploads ORDER BY uploaded_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    for row in rows:
        row["stats_json"] = safe_json_loads(row.get("stats_json"), {})
    return {"data": rows, "total": len(rows)}


# ── Get upload status ─────────────────────────────────────────────────────────

@router.get("/{upload_id}")
def get_upload(
    upload_id: str,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(get_current_user),
):
    row = conn.execute(
        "SELECT * FROM uploads WHERE id = ?", (upload_id,)
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upload '{upload_id}' not found.",
        )

    record = dict(row)
    record["stats_json"] = safe_json_loads(record.get("stats_json"), {})
    return {"data": record}


# ── Delete upload ─────────────────────────────────────────────────────────────

@router.delete("/{upload_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_upload(
    upload_id: str,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(require_role("admin")),
):
    row = conn.execute(
        "SELECT filename FROM uploads WHERE id = ?", (upload_id,)
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upload '{upload_id}' not found.",
        )

    # Remove file from disk
    try:
        from api.services.upload_service import UPLOAD_DIR
        upload_dir = UPLOAD_DIR / upload_id
        if upload_dir.exists():
            import shutil
            shutil.rmtree(upload_dir, ignore_errors=True)
    except Exception as exc:
        logger.warning("Could not remove upload directory %s: %s", upload_id, exc)

    conn.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
    conn.commit()
