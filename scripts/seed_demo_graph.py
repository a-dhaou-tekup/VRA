#!/usr/bin/env python3
"""seed_demo_graph.py — populate services, asset_services, and service_dependencies.

Usage
-----
    python scripts/seed_demo_graph.py          # platform.db (dev instance)
    python scripts/seed_demo_graph.py demo     # demo.db

Idempotent — safe to run multiple times; only inserts missing rows.

Service topology
----------------
  Network/Security  ──►  Web Frontend  ──►  API/Application  ──►  Database Cluster
                                        └──►  Cache / Redis
  Kubernetes Platform  ──►  API/Application
  Observability/SIEM  (linked to monitoring hosts)

7 services · hostname-pattern assignment · 5 dependency edges.
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT       = Path(__file__).parent.parent
PLATFORM_DB = ROOT / "data" / "cache" / "platform.db"
DEMO_DB    = ROOT / "data" / "cache" / "demo.db"

NOW = datetime.now(timezone.utc).isoformat()

# ── Service catalogue ─────────────────────────────────────────────────────────

SERVICES = [
    ("svc-web",   "Web Frontend",             "alice.martin@tek-up.tn",
     "Public-facing web tier — nginx, static assets, reverse proxy"),
    ("svc-api",   "API / Application Servers","bob.chen@tek-up.tn",
     "REST API layer — Spring Boot, FastAPI, microservices"),
    ("svc-db",    "Database Cluster",         "diana.okafor@tek-up.tn",
     "Primary + replica relational databases (PostgreSQL/MySQL)"),
    ("svc-cache", "Cache & Message Bus",      "diana.okafor@tek-up.tn",
     "Redis in-memory cache and lightweight message brokering"),
    ("svc-k8s",   "Kubernetes Platform",      "bob.chen@tek-up.tn",
     "Container orchestration — master and worker nodes"),
    ("svc-net",   "Network & Security",       "carlos.ruiz@tek-up.tn",
     "Perimeter firewalls, VPN gateways, switches, load balancers"),
    ("svc-obs",   "Observability & SIEM",     "bob.chen@tek-up.tn",
     "ELK stack, Prometheus, Grafana, SIEM, centralised logging"),
]

# parent --depends_on--> child
SERVICE_DEPS = [
    ("svc-net",   "svc-web"),    # Network edge fronts Web tier
    ("svc-web",   "svc-api"),    # Web calls API
    ("svc-api",   "svc-db"),     # API persists to Database
    ("svc-api",   "svc-cache"),  # API caches via Redis
    ("svc-k8s",   "svc-api"),   # K8s hosts API workloads
]

# (hostname-substring, service_id) — checked in order, first match wins
HOSTNAME_RULES: list[tuple[str, str]] = [
    # Web tier
    ("web-prod",     "svc-web"),
    ("prod-web",     "svc-web"),
    ("staging-web",  "svc-web"),
    ("cdn",          "svc-web"),
    # API / application tier
    ("api-prod",     "svc-api"),
    ("prod-api",     "svc-api"),
    ("app-prod",     "svc-api"),
    ("app-srv",      "svc-api"),
    ("app-dev",      "svc-api"),
    ("mail-",        "svc-api"),
    ("sharepoint",   "svc-api"),
    # Database
    ("db-prod",      "svc-db"),
    ("prod-db",      "svc-db"),
    ("db-staging",   "svc-db"),
    ("nas-",         "svc-db"),
    ("backup-",      "svc-db"),
    # Cache
    ("redis",        "svc-cache"),
    # Kubernetes
    ("k8s",          "svc-k8s"),
    # Network / security
    ("vpn",          "svc-net"),
    ("fortigate",    "svc-net"),
    ("fw-",          "svc-net"),
    ("-fw-",         "svc-net"),
    ("proxy",        "svc-net"),
    ("sw-",          "svc-net"),
    ("switch",       "svc-net"),
    ("jump",         "svc-net"),
    # Observability
    ("elk",          "svc-obs"),
    ("log-",         "svc-obs"),
    ("mon-",         "svc-obs"),
    ("siem",         "svc-obs"),
    ("prod-elk",     "svc-obs"),
    ("prod-mon",     "svc-obs"),
]


def _match(hostname: str) -> str | None:
    h = (hostname or "").lower()
    for pattern, svc in HOSTNAME_RULES:
        if pattern in h:
            return svc
    return None


def seed(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # ── 1. Services ────────────────────────────────────────────────────────────
    ins_svc = 0
    for sid, name, owner, desc in SERVICES:
        if not conn.execute("SELECT 1 FROM services WHERE id=?", (sid,)).fetchone():
            conn.execute(
                "INSERT INTO services (id, name, owner_id, description, created_at)"
                " VALUES (?,?,?,?,?)",
                (sid, name, owner, desc, NOW),
            )
            ins_svc += 1
    conn.commit()

    # ── 2. Asset → Service ────────────────────────────────────────────────────
    assets = conn.execute("SELECT asset_id, hostname FROM assets").fetchall()
    ins_lnk = 0
    unmatched: list[str] = []
    for a in assets:
        svc = _match(a["hostname"])
        if svc is None:
            unmatched.append(a["hostname"] or "?")
            continue
        if not conn.execute(
            "SELECT 1 FROM asset_services WHERE asset_id=? AND service_id=?",
            (a["asset_id"], svc),
        ).fetchone():
            conn.execute(
                "INSERT INTO asset_services (asset_id, service_id) VALUES (?,?)",
                (a["asset_id"], svc),
            )
            ins_lnk += 1
    conn.commit()

    # ── 3. Service → Service (depends_on) ─────────────────────────────────────
    ins_dep = 0
    for parent, child in SERVICE_DEPS:
        if not conn.execute(
            "SELECT 1 FROM service_dependencies"
            " WHERE parent_service_id=? AND child_service_id=?",
            (parent, child),
        ).fetchone():
            conn.execute(
                "INSERT INTO service_dependencies"
                " (parent_service_id, child_service_id, dep_type) VALUES (?,?,'depends_on')",
                (parent, child),
            )
            ins_dep += 1
    conn.commit()

    # ── 4. Report ─────────────────────────────────────────────────────────────
    print(f"\n  DB:              {db_path}")
    print(f"  Services added:  {ins_svc} / {len(SERVICES)}")
    print(f"  Asset links:     {ins_lnk}  ({len(unmatched)} assets unmatched)")
    print(f"  Dep edges:       {ins_dep} / {len(SERVICE_DEPS)}")
    if unmatched:
        sample = sorted(set(unmatched))[:8]
        print(f"  Unmatched hosts: {', '.join(sample)}"
              + (" …" if len(set(unmatched)) > 8 else ""))
    print()
    print("  Service breakdown:")
    for sid, name, _, _ in SERVICES:
        n = conn.execute(
            "SELECT COUNT(*) FROM asset_services WHERE service_id=?", (sid,)
        ).fetchone()[0]
        print(f"    {name:40s} {n:3d} assets")
    print()
    print("  Dependency edges:")
    for parent, child in SERVICE_DEPS:
        p = next(s[1] for s in SERVICES if s[0] == parent)
        c = next(s[1] for s in SERVICES if s[0] == child)
        print(f"    {p}  -->  {c}")

    conn.close()


def main() -> None:
    target  = sys.argv[1] if len(sys.argv) > 1 else "dev"
    db_path = DEMO_DB if target == "demo" else PLATFORM_DB

    if not db_path.exists():
        print(f"\nERROR: {db_path} not found.")
        print("Start the API first so migrations create the tables, then re-run.\n")
        sys.exit(1)

    print("\nSeeding demo graph…")
    seed(db_path)
    print("Done. Call  POST /api/graph/refresh  to rebuild the in-memory graph.\n")


if __name__ == "__main__":
    main()
