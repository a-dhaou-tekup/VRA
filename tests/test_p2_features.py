"""
Comprehensive test suite for P1 (RBAC) + P2 (Lifecycle, Risk Acceptance, Workarounds).

Run with:
    PYTHONPATH=src python tests/test_p2_features.py
"""

import sys
import io
import uuid

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from api.main import create_app
from fastapi.testclient import TestClient

app = create_app()
client = TestClient(app, raise_server_exceptions=False)

PASS = 0
FAIL = 0
ERRORS = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  PASS  {name}")
        PASS += 1
    else:
        msg = f"  FAIL  {name}" + (f": {detail}" if detail else "")
        print(msg)
        ERRORS.append(msg)
        FAIL += 1


def login(username, password):
    r = client.post("/api/auth/login", data={"username": username, "password": password})
    tok = r.json().get("access_token", "")
    return {"Authorization": f"Bearer {tok}"}


# ── Pre-flight: get tokens ────────────────────────────────────────────────────
aud = login("auditor", "Auditor1234!")
ana = login("analyst", "Analyst1234!")
adm = login("admin", "Admin1234!")
ro = login("risk_owner", "RiskOwner1234!")
rem = login("remediation_owner", "RemOwner1234!")


# =============================================================================
print("=== 1. SCHEMA ===")
# =============================================================================
from api.db.connection import get_connection

conn = get_connection()

tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
check("risk_acceptances table", "risk_acceptances" in tables)
check("workaround_records table", "workaround_records" in tables)

jobs_cols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
check("jobs.sla_paused_at", "sla_paused_at" in jobs_cols)
check("jobs.sla_paused_days", "sla_paused_days" in jobs_cols)
check("jobs.lifecycle_note", "lifecycle_note" in jobs_cols)

ra_cols = {r[1] for r in conn.execute("PRAGMA table_info(risk_acceptances)").fetchall()}
check("risk_acceptances.justification", "justification" in ra_cols)
check("risk_acceptances.expiry_date", "expiry_date" in ra_cols)
check("risk_acceptances.compensating_controls", "compensating_controls" in ra_cols)
check("risk_acceptances.status", "status" in ra_cols)

wr_cols = {r[1] for r in conn.execute("PRAGMA table_info(workaround_records)").fetchall()}
check("workaround_records.control_description", "control_description" in wr_cols)
check("workaround_records.followup_date", "followup_date" in wr_cols)
check("workaround_records.recorded_by", "recorded_by" in wr_cols)

conn.close()


# =============================================================================
print()
print("=== 2. STATE MACHINE DEFINITION ===")
# =============================================================================
from api.services.lifecycle_service import STATUS_TRANSITIONS, ALLOWED_STATUSES, SLA_PAUSING_STATES

EXPECTED = {
    "TO_DO", "TRIAGED", "PATCHABLE", "WORKAROUND_AVAILABLE", "NO_FIX",
    "IN_PROGRESS", "PATCHED", "MITIGATED", "DONE",
    "RISK_ACCEPTED", "FALSE_POSITIVE", "DEFERRED",
    "VERIFIED", "CLOSED", "RESURFACED",
}
check("15 states defined", ALLOWED_STATUSES == EXPECTED, str(ALLOWED_STATUSES ^ EXPECTED))
check("CLOSED is terminal", STATUS_TRANSITIONS["CLOSED"] == set())
check("VERIFIED -> CLOSED only", STATUS_TRANSITIONS["VERIFIED"] == {"CLOSED"})
check("PATCHED -> VERIFIED only", STATUS_TRANSITIONS["PATCHED"] == {"VERIFIED"})
check("RISK_ACCEPTED pauses SLA", "RISK_ACCEPTED" in SLA_PAUSING_STATES)
check("NO_FIX has RISK_ACCEPTED + DEFERRED + IN_PROGRESS",
      STATUS_TRANSITIONS["NO_FIX"] == {"RISK_ACCEPTED", "DEFERRED", "IN_PROGRESS"})
check("MITIGATED -> VERIFIED or RISK_ACCEPTED",
      STATUS_TRANSITIONS["MITIGATED"] == {"VERIFIED", "RISK_ACCEPTED"})
check("FALSE_POSITIVE -> TO_DO (reopen)",
      STATUS_TRANSITIONS["FALSE_POSITIVE"] == {"TO_DO"})
check("RESURFACED -> TO_DO or IN_PROGRESS",
      STATUS_TRANSITIONS["RESURFACED"] == {"TO_DO", "IN_PROGRESS"})


# =============================================================================
print()
print("=== 3. AUTH & ROLE ENFORCEMENT ===")
# =============================================================================
for uname, pwd, expected_role in [
    ("admin", "Admin1234!", "admin"),
    ("analyst", "Analyst1234!", "analyst"),
    ("remediation_owner", "RemOwner1234!", "remediation_owner"),
    ("risk_owner", "RiskOwner1234!", "risk_owner"),
    ("auditor", "Auditor1234!", "auditor"),
]:
    r = client.post("/api/auth/login", data={"username": uname, "password": pwd})
    check(f"login {expected_role}",
          r.status_code == 200 and r.json().get("role") == expected_role,
          r.text[:60])

r = client.post("/api/auth/login", data={"username": "admin", "password": "bad-password"})
check("wrong password -> 401", r.status_code == 401)

r = client.get("/api/jobs")
check("no token -> 401", r.status_code == 401)

r = client.get("/api/jobs", headers=aud)
check("auditor can read jobs", r.status_code == 200)

r = client.get("/api/risk-register", headers=aud)
check("auditor can read risk-register", r.status_code == 200)


# =============================================================================
print()
print("=== 4. LIFECYCLE TRANSITIONS (full walk-through) ===")
# =============================================================================

# Create a fresh synthetic job in TO_DO state
conn = get_connection()
from api.repositories.jobs_repo import upsert_job
test_jid = "test-" + str(uuid.uuid4())[:8]
upsert_job(conn, {
    "job_id": test_jid,
    "main_product": "TestProduct",
    "max_risk_level": "HIGH",
    "status": "TO_DO",
    "sla_days": 30,
})
conn.close()
print(f"  (synthetic job: {test_jid})")

# 4a. Auditor cannot transition
r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": "TRIAGED"}, headers=aud)
check("auditor cannot transition (403)", r.status_code == 403)

# 4b. Unknown status -> 400
r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": "BANANA"}, headers=rem)
check("unknown status -> 400", r.status_code == 400)

# 4c. Invalid transition TO_DO -> PATCHED -> 400
r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": "PATCHED"}, headers=rem)
check("TO_DO -> PATCHED is invalid (400)", r.status_code == 400)

# 4d. TO_DO -> TRIAGED
r = client.post(f"/api/jobs/{test_jid}/transition",
                json={"new_status": "TRIAGED", "comment": "confirmed"}, headers=rem)
check("TO_DO -> TRIAGED (200)", r.status_code == 200, r.text[:80])
if r.status_code == 200:
    check("status updated to TRIAGED", r.json()["data"]["status"] == "TRIAGED")

# 4e. TRIAGED -> PATCHABLE
r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": "PATCHABLE"}, headers=rem)
check("TRIAGED -> PATCHABLE (200)", r.status_code == 200)

# 4f. PATCHABLE -> IN_PROGRESS with lifecycle_note
r = client.post(f"/api/jobs/{test_jid}/transition",
                json={"new_status": "IN_PROGRESS", "lifecycle_note": "ticket-42"}, headers=rem)
check("PATCHABLE -> IN_PROGRESS (200)", r.status_code == 200)
if r.status_code == 200:
    check("lifecycle_note persisted", r.json()["data"]["lifecycle_note"] == "ticket-42")

# 4g. Analyst cannot enter RISK_ACCEPTED
r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": "RISK_ACCEPTED"}, headers=ana)
check("analyst cannot enter RISK_ACCEPTED (403)", r.status_code == 403)

# 4h. risk_owner enters RISK_ACCEPTED -> SLA pauses
r = client.post(f"/api/jobs/{test_jid}/transition",
                json={"new_status": "RISK_ACCEPTED", "comment": "board approved"}, headers=ro)
check("risk_owner -> RISK_ACCEPTED (200)", r.status_code == 200, r.text[:80])
if r.status_code == 200:
    d = r.json()["data"]
    check("sla_paused_at is set", d.get("sla_paused_at") is not None,
          str(d.get("sla_paused_at")))

# 4i. RISK_ACCEPTED -> IN_PROGRESS -> SLA resumes
r = client.post(f"/api/jobs/{test_jid}/transition",
                json={"new_status": "IN_PROGRESS", "comment": "patch released"}, headers=ro)
check("RISK_ACCEPTED -> IN_PROGRESS (200)", r.status_code == 200)
if r.status_code == 200:
    d = r.json()["data"]
    check("sla_paused_at cleared", d.get("sla_paused_at") is None)
    check("sla_paused_days >= 0", (d.get("sla_paused_days") or 0) >= 0)

# 4j. IN_PROGRESS -> PATCHED -> VERIFIED -> CLOSED
for step in ["PATCHED", "VERIFIED", "CLOSED"]:
    r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": step}, headers=rem)
    check(f"-> {step} (200)", r.status_code == 200, r.text[:60])

# 4k. CLOSED is terminal
r = client.post(f"/api/jobs/{test_jid}/transition", json={"new_status": "IN_PROGRESS"}, headers=adm)
check("CLOSED -> anything rejected (400)", r.status_code == 400)

# 4l. Workaround path: new job TO_DO -> WORKAROUND_AVAILABLE -> IN_PROGRESS -> MITIGATED -> VERIFIED -> CLOSED
conn = get_connection()
wa_jid = "test-wa-" + str(uuid.uuid4())[:8]
upsert_job(conn, {"job_id": wa_jid, "main_product": "WATest", "max_risk_level": "MEDIUM",
                  "status": "TO_DO", "sla_days": 30})
conn.close()

for from_s, to_s in [
    ("TO_DO", "TRIAGED"), ("TRIAGED", "WORKAROUND_AVAILABLE"),
    ("WORKAROUND_AVAILABLE", "IN_PROGRESS"), ("IN_PROGRESS", "MITIGATED"),
    ("MITIGATED", "VERIFIED"), ("VERIFIED", "CLOSED"),
]:
    r = client.post(f"/api/jobs/{wa_jid}/transition", json={"new_status": to_s}, headers=rem)
    check(f"WA path: {from_s} -> {to_s}", r.status_code == 200, r.text[:60])


# =============================================================================
print()
print("=== 5. RISK ACCEPTANCE ===")
# =============================================================================
ra_jid = jobs = client.get("/api/jobs?limit=1", headers=adm).json().get("data", [])
ra_jid = ra_jid[0]["job_id"] if ra_jid else test_jid

r = client.post(f"/api/jobs/{ra_jid}/risk-acceptance",
                json={
                    "justification": "Vendor patch unavailable until Q3",
                    "compensating_controls": "WAF rule + monitoring",
                    "expiry_date": "2026-09-30",
                    "review_trigger": "next quarterly scan",
                }, headers=ro)
check("risk_owner creates risk-acceptance (201)", r.status_code == 201, r.text[:80])
ra_id = r.json().get("data", {}).get("id") if r.status_code == 201 else None

if ra_id:
    # List by job
    r = client.get(f"/api/jobs/{ra_jid}/risk-acceptances", headers=aud)
    check("list risk-acceptances for job (200)", r.status_code == 200)
    data = r.json().get("data", [])
    check("at least 1 acceptance listed", len(data) >= 1)

    # Risk register
    r = client.get("/api/risk-register", headers=aud)
    check("risk-register (200)", r.status_code == 200)
    rows = r.json().get("data", [])
    check("risk-register has rows", len(rows) >= 1, f"got {len(rows)}")
    if rows:
        check("risk-register row has main_product", "main_product" in rows[0])
        check("risk-register row has overdue flag", "overdue" in rows[0])
        check("not overdue (expiry 2026-09-30)", rows[0].get("overdue") is False)

    # Expire
    r = client.patch(f"/api/risk-acceptances/{ra_id}", json={"status": "expired"}, headers=ro)
    check("risk_owner can expire RA (200)", r.status_code == 200)
    check("status set to expired", r.json()["data"]["status"] == "expired")

    # Invalid status value
    r2 = client.post(f"/api/jobs/{ra_jid}/risk-acceptance",
                     json={"justification": "tmp"}, headers=ro)
    ra2 = r2.json().get("data", {}).get("id")
    if ra2:
        r = client.patch(f"/api/risk-acceptances/{ra2}", json={"status": "invalid-value"}, headers=ro)
        check("invalid RA status rejected (400)", r.status_code == 400)

    # Analyst cannot expire
    r3 = client.post(f"/api/jobs/{ra_jid}/risk-acceptance",
                     json={"justification": "for analyst test"}, headers=ro)
    ra3 = r3.json().get("data", {}).get("id")
    if ra3:
        r = client.patch(f"/api/risk-acceptances/{ra3}", json={"status": "expired"}, headers=ana)
        check("analyst cannot expire RA (403)", r.status_code == 403)


# =============================================================================
print()
print("=== 6. WORKAROUNDS ===")
# =============================================================================
wr_jid = ra_jid

r = client.post(f"/api/jobs/{wr_jid}/workaround",
                json={"control_description": "Blocked port 8443 at perimeter",
                      "followup_date": "2026-07-15"}, headers=rem)
check("remediation_owner creates workaround (201)", r.status_code == 201, r.text[:80])
if r.status_code == 201:
    wd = r.json()["data"]
    check("workaround.recorded_by = remediation_owner", wd.get("recorded_by") == "remediation_owner")
    check("workaround.followup_date correct", wd.get("followup_date") == "2026-07-15")
    check("workaround.job_id correct", wd.get("job_id") == wr_jid)

r = client.get(f"/api/jobs/{wr_jid}/workarounds", headers=aud)
check("auditor can list workarounds (200)", r.status_code == 200)
check("at least 1 workaround", len(r.json().get("data", [])) >= 1)

# Auditor cannot create workaround
r = client.post(f"/api/jobs/{wr_jid}/workaround",
                json={"control_description": "auditor sneaking in"}, headers=aud)
check("auditor cannot create workaround (403)", r.status_code == 403)


# =============================================================================
print()
print("=== 7. AUDIT TRAIL ===")
# =============================================================================
r = client.get(f"/api/jobs/{test_jid}/events", headers=aud)
check("events endpoint (200)", r.status_code == 200)
raw = r.json()
evts = raw.get("data", raw if isinstance(raw, list) else [])
check("events recorded", len(evts) >= 5, f"got {len(evts)}")
types = {e.get("event_type") for e in evts}
check("STATUS_CHANGE events present", "STATUS_CHANGE" in types)
# Every event has changed_by
missing_by = [e for e in evts if not e.get("changed_by")]
check("all events have changed_by", len(missing_by) == 0, f"{len(missing_by)} missing")


# =============================================================================
print()
print("=== 8. API RESPONSE SHAPE ===")
# =============================================================================
r = client.get("/api/jobs?limit=5", headers=adm)
check("jobs list wrapped in {data, total}", "data" in r.json() and "total" in r.json())

any_jid = r.json().get("data", [{}])[0].get("job_id") if r.json().get("data") else None
if any_jid:
    r2 = client.get(f"/api/jobs/{any_jid}", headers=adm)
    check("job detail wrapped in {data}", "data" in r2.json())
    jd = r2.json()["data"]
    for field in ["job_id", "status", "max_risk_level", "sla_paused_days"]:
        check(f"job has field: {field}", field in jd)

r = client.get("/api/risk-register", headers=adm)
check("risk-register shape {data, total}", "data" in r.json() and "total" in r.json())


# =============================================================================
print()
print("=" * 50)
print(f"TOTAL:  PASS={PASS}  FAIL={FAIL}")
if ERRORS:
    print("\nFailed checks:")
    for e in ERRORS:
        print(e)
print("=" * 50)
