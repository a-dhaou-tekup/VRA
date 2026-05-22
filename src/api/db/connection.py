"""SQLite connection factory with WAL mode and thread safety."""

import sqlite3
import os
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent.parent
DB_PATH = ROOT / os.getenv("PLATFORM_DB_PATH", "data/cache/platform.db")


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def get_db():
    """FastAPI dependency that yields a connection and closes it after."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()
