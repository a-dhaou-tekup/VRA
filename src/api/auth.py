"""JWT auth helpers: token creation, current-user dependency, require_role factory.

Usage in a router:
    from api.auth import require_role

    @router.patch("/{job_id}/status")
    def update_status(
        job_id: str,
        payload: JobStatusUpdate,
        conn: sqlite3.Connection = Depends(get_db),
        user: dict = Depends(require_role("analyst", "remediation_owner", "admin")),
    ):
        ...

The `user` dict contains {"username": str, "role": str}.
"""

import os
from datetime import datetime, timedelta, timezone

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# ── Config ────────────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "CHANGE-ME-in-prod-use-32-plus-random-bytes",
)
ALGORITHM = "HS256"
EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "8"))

VALID_ROLES = frozenset(
    {"admin", "analyst", "remediation_owner", "risk_owner", "auditor"}
)

# ── Crypto — use bcrypt directly (avoids passlib/bcrypt-4.x version mismatch) ─

# tokenUrl points at the login endpoint so FastAPI /docs shows a working
# "Authorize" button.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── Token ─────────────────────────────────────────────────────────────────────

def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=EXPIRE_HOURS)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependencies ──────────────────────────────────────────────────────────────

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Validate token and return {"username": ..., "role": ...}."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        if username is None or role not in VALID_ROLES:
            raise credentials_exc
    except JWTError:
        raise credentials_exc
    return {"username": username, "role": role}


def require_role(*roles: str):
    """Dependency factory that enforces role membership.

    Usage:
        user: dict = Depends(require_role("admin", "analyst"))
    Raises 403 if the authenticated user's role is not in *roles.
    """
    async def _checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{user['role']}' is not allowed to perform this action. "
                    f"Required: {sorted(roles)}."
                ),
            )
        return user

    return _checker
