"""Auth router — login + current-user endpoint.

POST /api/auth/login   → returns {access_token, token_type, username, role}
GET  /api/auth/me      → returns {username, role} for the current token
"""

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from api.auth import create_access_token, get_current_user, verify_password
from api.db.connection import get_db
from api.repositories import users_repo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Auth"])


@router.post("/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    conn: sqlite3.Connection = Depends(get_db),
):
    """Exchange username + password for a Bearer token.

    The response is intentionally vague on failure (no "user not found" vs
    "wrong password" distinction) to prevent user-enumeration.
    """
    user = users_repo.get_by_username(conn, form.username)
    if (
        user is None
        or not user.get("active")
        or not verify_password(form.password, user["password_hash"])
    ):
        logger.warning("auth: failed login attempt for username=%r", form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user["username"], user["role"])
    logger.info("auth: login success username=%r role=%r", user["username"], user["role"])
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     user["username"],
        "role":         user["role"],
    }


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    """Return the username and role of the currently authenticated user."""
    return {"username": user["username"], "role": user["role"]}
