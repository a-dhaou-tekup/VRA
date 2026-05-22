"""Repository for the `users` table (RBAC).

All functions take a sqlite3.Connection and return plain dicts or None.
Password hashes are NEVER returned by public-facing functions (get_all,
get_by_id) — only get_by_username returns the hash for login verification.
"""

import sqlite3
from datetime import datetime, timezone
from typing import Optional


# ── Internal helper ───────────────────────────────────────────────────────────

def _safe_row(row: Optional[sqlite3.Row], include_hash: bool = False) -> Optional[dict]:
    if row is None:
        return None
    d = dict(row)
    if not include_hash:
        d.pop("password_hash", None)
    return d


# ── Queries ───────────────────────────────────────────────────────────────────

def get_by_username(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    """Return the full user row including password_hash (for login only)."""
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return _safe_row(row, include_hash=True)


def get_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[dict]:
    """Return user without password_hash."""
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return _safe_row(row)


def get_all(conn: sqlite3.Connection) -> list[dict]:
    """Return all users without password hashes."""
    rows = conn.execute(
        "SELECT * FROM users ORDER BY role, username"
    ).fetchall()
    return [_safe_row(r) for r in rows]


# ── Mutations ─────────────────────────────────────────────────────────────────

def create_user(
    conn: sqlite3.Connection,
    username: str,
    password_hash: str,
    role: str,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO users (username, password_hash, role, active, created_at)
           VALUES (?, ?, ?, 1, ?)""",
        (username, password_hash, role, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return _safe_row(row)


def update_user(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    role: Optional[str] = None,
    active: Optional[bool] = None,
    password_hash: Optional[str] = None,
) -> Optional[dict]:
    parts: list[str] = []
    params: list = []

    if role is not None:
        parts.append("role = ?")
        params.append(role)
    if active is not None:
        parts.append("active = ?")
        params.append(int(active))
    if password_hash is not None:
        parts.append("password_hash = ?")
        params.append(password_hash)

    if not parts:
        return get_by_id(conn, user_id)

    params.append(user_id)
    conn.execute(
        f"UPDATE users SET {', '.join(parts)} WHERE id = ?", params
    )
    conn.commit()
    return get_by_id(conn, user_id)


def delete_user(conn: sqlite3.Connection, user_id: int) -> bool:
    result = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return result.rowcount > 0
