#!/usr/bin/env python3
"""
reset_demo.py — Reset the VRA demo database.

Two modes:

  [1] RESTORE from backup  (demo_seeded_backup.db → demo.db)
      Use this on demo day if something goes wrong mid-demo.
      Fast — takes ~2 seconds. Brings back a fully seeded state.

  [2] FULL WIPE
      Clears all seeded data from demo.db (keeps users + compliance controls).
      Use this if you need to re-run seed_demo.py from the beginning.

Usage:
    python scripts/reset_demo.py
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
from pathlib import Path

ROOT      = Path(__file__).parent.parent
DEMO_DB   = ROOT / "data" / "cache" / "demo.db"
BACKUP_DB = ROOT / "data" / "cache" / "demo_seeded_backup.db"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg: str)   -> None: print(f"  {GREEN}✓{RESET}  {msg}")
def warn(msg: str) -> None: print(f"  {YELLOW}!{RESET}  {msg}")
def err(msg: str)  -> None: print(f"  {RED}✗{RESET}  {msg}")
def hdr(msg: str)  -> None: print(f"\n{BOLD}{msg}{RESET}")

# ── Tables to wipe (everything except users, control_catalog, sqlite_sequence) ─
WIPE_ORDER = [
    # dependents first
    "conversation_turns",
    "conversations",
    "alert_jobs",
    "job_controls",
    "job_events",
    "finding_events",
    "auto_triage",
    "workaround_records",
    "llm_advice",
    "exec_reports",
    "ticket_links",
    "risk_acceptances",
    # main tables
    "findings",
    "threat_alerts",
    "jobs",
    "uploads",
    "cpe_cve_cache",
    # asset relationships
    "asset_services",
    "service_dependencies",
    "services",
    "asset_software",
    "assets",
]

KEEP_TABLES = {"users", "control_catalog", "sqlite_sequence"}


# ── Mode 1: restore from backup ───────────────────────────────────────────────

def restore_from_backup() -> None:
    hdr("Restoring demo.db from backup …")

    if not BACKUP_DB.exists():
        err(f"Backup not found: {BACKUP_DB}")
        err("Run seed_demo.py first — it creates the backup automatically.")
        sys.exit(1)

    # Close any lingering SQLite connections by just doing a file copy
    shutil.copy2(BACKUP_DB, DEMO_DB)
    ok(f"demo.db restored from demo_seeded_backup.db")
    ok(f"Backup size: {BACKUP_DB.stat().st_size // 1024} KB")

    print()
    print("  Restart the demo backend to pick up the restored DB:")
    print(f"  {YELLOW}Close the 'VRA Demo Backend' terminal, then re-run start_demo.bat{RESET}")
    print()


# ── Mode 2: full wipe ─────────────────────────────────────────────────────────

def full_wipe() -> None:
    hdr("Wiping all seeded data from demo.db …")

    if not DEMO_DB.exists():
        err(f"demo.db not found at {DEMO_DB}")
        err("Start the backend once (start_demo.bat) to create it, then re-run this script.")
        sys.exit(1)

    conn = sqlite3.connect(str(DEMO_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=OFF")  # skip FK checks — we control the order anyway

    # Verify every table in WIPE_ORDER exists
    existing_tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }

    total_deleted = 0
    for table in WIPE_ORDER:
        if table not in existing_tables:
            warn(f"Table '{table}' not found — skipping")
            continue
        before = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        conn.execute(f"DELETE FROM {table}")
        total_deleted += before
        status = f"{before} rows" if before else "already empty"
        ok(f"  {table:35s} cleared  ({status})")

    conn.commit()

    # Show what was kept
    print()
    for t in sorted(KEEP_TABLES):
        if t in existing_tables:
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            ok(f"  {t:35s} kept     ({n} rows)")

    conn.close()

    print()
    ok(f"Total rows removed: {total_deleted}")
    print()
    print("  Next steps:")
    print(f"  {YELLOW}1.{RESET} Restart the demo backend:")
    print("       Close the 'VRA Demo Backend' terminal, re-run start_demo.bat")
    print(f"  {YELLOW}2.{RESET} Re-seed the database:")
    print("       python scripts/seed_demo.py")
    print(f"  {YELLOW}3.{RESET} Pre-cache AI content (optional but recommended):")
    print("       python scripts/precache_demo_ai.py")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{'─'*55}")
    print("  ODDO BHF — VRA Demo Reset")
    print(f"{'─'*55}{RESET}")

    backup_exists = BACKUP_DB.exists()

    if backup_exists:
        backup_kb = BACKUP_DB.stat().st_size // 1024
        print(f"\n  Backup found: demo_seeded_backup.db  ({backup_kb} KB)")
        print()
        print("  [1]  RESTORE from backup   — fast, use on demo day if something breaks")
        print("  [2]  FULL WIPE             — clear everything, re-run seed_demo.py")
        print()
        choice = input("  Enter 1 or 2: ").strip()
    else:
        warn("No backup found (seed_demo.py hasn't been run yet, or backup was deleted).")
        print()
        print("  Only option available:")
        print("  [2]  FULL WIPE  — clear all seeded tables")
        print()
        choice = "2"

    if choice == "1":
        print()
        confirm = input("  Overwrite demo.db with backup? This cannot be undone. [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Cancelled.")
            sys.exit(0)
        restore_from_backup()

    elif choice == "2":
        print()
        print("  This will DELETE all assets, findings, jobs, alerts, and AI advice.")
        print("  Users and compliance controls will be kept.")
        print()
        confirm = input("  Type  yes  to confirm full wipe: ").strip().lower()
        if confirm != "yes":
            print("  Cancelled.")
            sys.exit(0)
        full_wipe()

    else:
        err("Invalid choice. Run the script again and enter 1 or 2.")
        sys.exit(1)


if __name__ == "__main__":
    main()
