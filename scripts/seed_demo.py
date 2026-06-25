#!/usr/bin/env python3
"""
seed_demo.py — ODDO BHF demo database seeder.

Pre-requisite: start_demo.bat must be running (backend on http://localhost:8001).
Ollama is NOT required for this script.

Run once the evening before the demo:
    python scripts/seed_demo.py

Steps:
  1. Verify backend is alive
  2. Login as admin → get JWT
  3. Import 25 assets from data/input/assets_demo1.csv
  4. Seed software inventory (vulnerable packages per host)
  5. Seed service topology (7 services, 5 dependency edges)
  6. Upload data/input/scanner_demo1.csv → creates findings + jobs
  7. Run CVE threat matching with auto-promote (creates ~thousands of alerts, jobs)
  8. Back up demo.db → demo_seeded_backup.db
"""
from __future__ import annotations

import csv
import shutil
import sys
import time
from pathlib import Path

import urllib.request
import urllib.parse
import json
import urllib.error

ROOT       = Path(__file__).parent.parent
DEMO_DB    = ROOT / "data" / "cache" / "demo.db"
BACKUP_DB  = ROOT / "data" / "cache" / "demo_seeded_backup.db"
ASSETS_CSV = ROOT / "data" / "input" / "assets_demo1.csv"
SCANNER_CSV= ROOT / "data" / "input" / "scanner_demo1.csv"
BASE_URL   = "http://localhost:8001"

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

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(path: str, token: str | None = None) -> dict:
    req = urllib.request.Request(f"{BASE_URL}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def _post_json(path: str, payload: dict, token: str | None = None) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())

def _post_form(path: str, fields: dict[str, str], files: dict[str, Path],
               token: str | None = None) -> dict:
    """Multipart/form-data POST."""
    boundary = "VRASeeder1234567890"
    body_parts: list[bytes] = []
    for name, value in fields.items():
        body_parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    for name, filepath in files.items():
        content = filepath.read_bytes()
        body_parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filepath.name}"\r\n'
            f'Content-Type: text/csv\r\n\r\n'.encode() + content + b'\r\n'
        )
    body_parts.append(f'--{boundary}--\r\n'.encode())
    body = b''.join(body_parts)
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())

def _post_login(username: str, password: str) -> str:
    """Returns JWT token."""
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/auth/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]

# ── Steps ─────────────────────────────────────────────────────────────────────

def step1_check_backend() -> None:
    hdr("Step 1/8 — Checking backend")
    try:
        result = _get("/health")
        if result.get("status") == "ok":
            ok("Backend is alive at http://localhost:8001")
        else:
            err("Backend responded but status is not OK")
            sys.exit(1)
    except Exception as e:
        err(f"Backend not reachable: {e}")
        err("Make sure start_demo.bat is running and the 'VRA Demo Backend' window shows 'Application startup complete'.")
        sys.exit(1)


def step2_login() -> str:
    hdr("Step 2/8 — Logging in as admin")
    try:
        token = _post_login("admin", "Admin1234!")
        ok("Got JWT token")
        return token
    except Exception as e:
        err(f"Login failed: {e}")
        sys.exit(1)


def step3_import_assets(token: str) -> None:
    hdr("Step 3/8 — Importing 25 assets from assets_demo1.csv")
    rows: list[dict] = []
    with open(ASSETS_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({
                "hostname":         row["hostname"],
                "ip_address":       row["ip_address"],
                "business_unit":    row["business_unit"],
                "business_owner":   row["business_owner"],
                "criticality":      row["criticality"],
                "internet_exposed": row["internet_exposed"].lower() == "true",
                "environment":      row["environment"],
            })

    try:
        result = _post_json("/api/assets/bulk", {"assets": rows, "upsert": True}, token)
        inserted = result.get("inserted", 0)
        updated  = result.get("updated", 0)
        ok(f"Assets: {inserted} inserted, {updated} updated")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        err(f"HTTP {e.code}: {body[:300]}")
        sys.exit(1)
    except Exception as e:
        err(f"Asset import failed: {e}")
        sys.exit(1)


def step4_seed_software() -> None:
    hdr("Step 4/8 — Seeding software inventory")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "seed_software_inventory",
        ROOT / "scripts" / "seed_software_inventory.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    if not DEMO_DB.exists():
        err(f"demo.db not found at {DEMO_DB}")
        sys.exit(1)

    mod.seed(DEMO_DB)
    ok("Software inventory seeded")


def step5_seed_graph() -> None:
    hdr("Step 5/8 — Seeding service topology")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "seed_demo_graph", ROOT / "scripts" / "seed_demo_graph.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.seed(DEMO_DB)
    ok("Service topology seeded")


def step6_upload_scan(token: str) -> str:
    hdr("Step 6/8 — Uploading scanner_demo1.csv")
    print("    Parsing findings, scoring, creating jobs — takes ~20s …")
    try:
        result = _post_form(
            "/api/uploads",
            fields={"scanner_type": "auto"},
            files={"file": SCANNER_CSV},
            token=token,
        )
        upload_id = result.get("upload_id", result.get("id", "?"))
        new_jobs  = result.get("new_jobs", "?")
        findings  = result.get("total_findings", result.get("findings_created", "?"))
        ok(f"Upload complete — upload_id={upload_id}, jobs={new_jobs}, findings={findings}")
        return str(upload_id)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        err(f"HTTP {e.code}: {body[:500]}")
        sys.exit(1)
    except Exception as e:
        err(f"Upload failed: {e}")
        sys.exit(1)


def step7_threat_match(token: str) -> None:
    hdr("Step 7/8 — Running CVE threat matching + auto-promote")
    print("    Matching installed software against KEV / EPSS / NVD …")
    print("    This step may take 2–5 minutes on first run (CPE lookups). Please wait.")
    t0 = time.time()
    try:
        result = _post_json(
            "/api/threat-alerts/match",
            {
                "force_reset":          True,
                "use_nvd":              True,
                "use_osv":              False,
                "auto_promote":         True,
                "auto_promote_grouping":"by_cve",
            },
            token,
        )
        elapsed = int(time.time() - t0)
        data    = result.get("data", result)
        alerts  = data.get("alerts_created", data.get("total_alerts", "?"))
        kev     = data.get("kev_matched",    "?")
        promo   = data.get("promotion", {})
        jobs    = promo.get("jobs_created",  "?") if isinstance(promo, dict) else "?"
        ok(f"Done in {elapsed}s — alerts={alerts}, kev_matched={kev}, jobs_promoted={jobs}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        err(f"HTTP {e.code}: {body[:500]}")
        sys.exit(1)
    except Exception as e:
        err(f"Threat matching failed: {e}")
        sys.exit(1)


def step8_backup() -> None:
    hdr("Step 8/8 — Backing up demo.db")
    shutil.copy2(DEMO_DB, BACKUP_DB)
    ok(f"Backup saved → data/cache/demo_seeded_backup.db")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{'─'*55}")
    print("  ODDO BHF — VRA Demo Seeder")
    print(f"{'─'*55}{RESET}")
    print("  This will populate demo.db with assets, software,")
    print("  findings, jobs, and threat alerts for the demo.")
    print("  Pre-requisite: start_demo.bat is running.")
    print()

    step1_check_backend()
    token = step2_login()
    step3_import_assets(token)
    step4_seed_software()
    step5_seed_graph()
    step6_upload_scan(token)
    step7_threat_match(token)
    step8_backup()

    print(f"\n{BOLD}{GREEN}{'─'*55}")
    print("  Seeding complete. Demo DB is ready.")
    print(f"{'─'*55}{RESET}")
    print()
    print("  Next step (requires Ollama):")
    print("    python scripts/precache_demo_ai.py")
    print()


if __name__ == "__main__":
    main()
