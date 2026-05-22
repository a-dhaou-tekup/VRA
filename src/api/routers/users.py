"""Users router — admin-only user management.

All endpoints require role=admin.
"""

import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.auth import hash_password, require_role
from api.db.connection import get_db
from api.repositories import users_repo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["Users"])

VALID_ROLES = {"admin", "analyst", "remediation_owner", "risk_owner", "auditor"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    role:     str = Field(..., description="admin|analyst|remediation_owner|risk_owner|auditor")


class UserUpdate(BaseModel):
    role:     Optional[str]  = None
    active:   Optional[bool] = None
    password: Optional[str]  = Field(None, min_length=8)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
def list_users(
    conn: sqlite3.Connection = Depends(get_db),
    _admin: dict = Depends(require_role("admin")),
):
    """List all users (no password hashes)."""
    return {"data": users_repo.get_all(conn)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    conn: sqlite3.Connection = Depends(get_db),
    _admin: dict = Depends(require_role("admin")),
):
    if payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{payload.role}'. Valid: {sorted(VALID_ROLES)}",
        )
    existing = users_repo.get_by_username(conn, payload.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already taken.",
        )
    user = users_repo.create_user(
        conn,
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    logger.info("users: created user=%r role=%r", payload.username, payload.role)
    return {"data": user}


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    conn: sqlite3.Connection = Depends(get_db),
    _admin: dict = Depends(require_role("admin")),
):
    if payload.role and payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{payload.role}'. Valid: {sorted(VALID_ROLES)}",
        )
    ph = hash_password(payload.password) if payload.password else None
    updated = users_repo.update_user(
        conn,
        user_id,
        role=payload.role,
        active=payload.active,
        password_hash=ph,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    logger.info("users: updated user_id=%d", user_id)
    return {"data": updated}


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    conn: sqlite3.Connection = Depends(get_db),
    admin: dict = Depends(require_role("admin")),
):
    # Prevent self-deletion
    me = users_repo.get_by_username(conn, admin["username"])
    if me and me.get("id") == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account.",
        )
    deleted = users_repo.delete_user(conn, user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    logger.info("users: deleted user_id=%d by admin=%r", user_id, admin["username"])
