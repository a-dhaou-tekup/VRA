#!/usr/bin/env python3
"""Seed the demo graph tables (services, asset_services, service_dependencies).

Run:  python scripts/seed_demo_graph.py

Populates 8 services, links them to the existing assets, and adds 5 dependency
edges — enough to make blast-radius queries visually interesting.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT    = Path(__file__).parent.parent
DB_PATH = ROOT / "data" / "cache" / "platform.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    if not DB_PATH.exists():
        print(f"[ERROR] {DB_PATH} not found — start the API first to run migrations.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")

    # ── Load existing assets ─────────────────────────────────────────────────
    assets = [dict(r) for r in conn.execute(
        "SELECT asset_id, hostname FROM assets LIMIT 40"
    ).fetchall()]

    if not assets:
        print("[WARN] No assets found. Upload a scan first, then re-run this script.")
        conn.close()
        return

    now = _now()

    # ── Upsert 8 services ────────────────────────────────────────────────────
    SERVICES = [
        ("svc-auth",      "Authentication Service",    "auth"),
        ("svc-api-gw",    "API Gateway",               "api-gw"),
        ("svc-db-primary","Primary Database",          "db-primary"),
        ("svc-db-replica","Database Replica",          "db-replica"),
        ("svc-cache",     "Cache Cluster (Redis)",     "cache"),
        ("svc-ci",        "CI/CD Pipeline",            "ci"),
        ("svc-logging",   "Centralised Logging",       "logging"),
        ("svc-monitoring","Monitoring & Alerting",     "monitoring"),
    ]
    for svc_id, svc_name, _ in SERVICES:
        conn.execute("""
            INSERT OR IGNORE INTO services (id, name, description, created_at)
            VALUES (?, ?, ?, ?)
        """, (svc_id, svc_name, f"Demo service: {svc_name}", now))

    # ── Link first 20 assets round-robin to services ─────────────────────────
    svc_ids = [s[0] for s in SERVICES]
    for i, asset in enumerate(assets[:20]):
        svc = svc_ids[i % len(svc_ids)]
        conn.execute("""
            INSERT OR IGNORE INTO asset_services (asset_id, service_id)
            VALUES (?, ?)
        """, (asset["asset_id"], svc))

    # ── 5 dependency edges (makes blast radius multi-hop) ────────────────────
    DEPS = [
        ("svc-api-gw",    "svc-auth"),        # API GW → Auth
        ("svc-api-gw",    "svc-db-primary"),  # API GW → DB
        ("svc-db-primary","svc-db-replica"),  # primary → replica
        ("svc-auth",      "svc-cache"),       # Auth → Cache
        ("svc-monitoring","svc-logging"),     # Monitoring → Logging
    ]
    for parent, child in DEPS:
        conn.execute("""
            INSERT OR IGNORE INTO service_dependencies
                (parent_service_id, child_service_id, dep_type)
            VALUES (?, ?, 'depends_on')
        """, (parent, child))

    conn.commit()
    conn.close()

    print(f"[OK] Seeded {len(SERVICES)} services, "
          f"{min(20, len(assets))} asset-service links, "
          f"{len(DEPS)} dependency edges.")
    print("     Run: curl -X POST http://localhost:8000/api/graph/refresh -H 'Authorization: Bearer <token>'")


if __name__ == "__main__":
    main()
