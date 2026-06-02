"""Verify all 10 VRA agent tools return correct data.

Run from the project root (no running API server needed — talks to SQLite directly):

    python scripts/verify_tools.py

Exit code 0 = all checks passed.  Exit code 1 = at least one failure.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Path / env setup ─────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PLATFORM_DB_PATH", "data/cache/platform.db")

# ── Imports ───────────────────────────────────────────────────────────────────
from agent.tools import (           # noqa: E402
    get_enrichment_status,
    get_job_detail,
    get_metrics,
    get_risk_acceptances,
    get_sla_compliance,
    get_threat_alerts,
    list_jobs,
    query_controls,
    search_cves,
    search_knowledge,
)
from agent.registry import get_tool, list_tools   # noqa: E402

ROLE   = "analyst"
GREEN  = "\033[32m"
RED    = "\033[31m"
RESET  = "\033[0m"
PASS   = f"{GREEN}PASS{RESET}"
FAIL   = f"{RED}FAIL{RESET}"

results: list[tuple[str, bool, str]] = []


# ── Assertion helper ──────────────────────────────────────────────────────────

def check(label: str, result: dict, *assertions: tuple):
    """Run assertions against *result* and record pass/fail."""
    ok   = result.get("ok", False)
    msgs = [] if ok else [f"ok=False — {result.get('error')}"]
    for pred, msg in assertions:
        try:
            if not pred(result):
                msgs.append(msg)
        except Exception as exc:
            msgs.append(f"assertion raised: {exc}")
    passed = not msgs
    results.append((label, passed, " | ".join(msgs) if msgs else ""))


def check_false(label: str, result: dict):
    """Assert that *result* has ok=False (expected failure path)."""
    passed = not result.get("ok", True)
    msg    = "" if passed else "expected ok=False but got ok=True"
    results.append((label, passed, msg))


# ═══════════════════════════════════════════════════════════════════════════════
# Tool checks
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1. get_metrics ────────────────────────────────────────────────────────────
r = get_metrics(ROLE)
check("get_metrics",  r,
      (lambda r: isinstance(r["data"].get("total_jobs"), int),      "total_jobs not int"),
      (lambda r: "sla_compliance_pct" in r["data"],                  "missing sla_compliance_pct"),
      (lambda r: "kev_past_sla" in r["data"],                        "missing kev_past_sla"),
      (lambda r: "jobs_by_status" in r["data"],                      "missing jobs_by_status"),
      (lambda r: "jobs_by_risk_level" in r["data"],                  "missing jobs_by_risk_level"),
      (lambda r: isinstance(r["data"]["sla_compliance_pct"], float), "sla_compliance_pct not float"),
)

# ── 2. get_sla_compliance ─────────────────────────────────────────────────────
r = get_sla_compliance(ROLE)
check("get_sla_compliance", r,
      (lambda r: "compliance_pct" in r["data"],               "missing compliance_pct"),
      (lambda r: "breached" in r["data"],                     "missing breached"),
      (lambda r: isinstance(r["data"]["breached"], int),      "breached not int"),
      (lambda r: isinstance(r["data"]["overdue_jobs"], list), "overdue_jobs not list"),
)

# ── 3a. list_jobs — CRITICAL, open ───────────────────────────────────────────
r = list_jobs(ROLE, status="open", risk_level="CRITICAL", limit=10)
check("list_jobs (open, CRITICAL)", r,
      (lambda r: isinstance(r["data"]["jobs"], list), "jobs not list"),
      (lambda r: all(j["max_risk_level"] == "CRITICAL"
                     for j in r["data"]["jobs"]),     "non-CRITICAL in result"),
      (lambda r: all(j["status"] not in {"DONE","CLOSED","FALSE_POSITIVE"}
                     for j in r["data"]["jobs"]),     "terminal status in open result"),
)

# ── 3b. list_jobs — KEV only ─────────────────────────────────────────────────
r = list_jobs(ROLE, kev_only=True, limit=20)
check("list_jobs (kev_only)", r,
      (lambda r: isinstance(r["data"]["jobs"], list),                      "jobs not list"),
      (lambda r: all(j.get("kev_present") == 1 for j in r["data"]["jobs"]),
       "non-KEV job in kev_only result"),
)

# ── 3c. list_jobs — past SLA ─────────────────────────────────────────────────
r = list_jobs(ROLE, past_sla=True, limit=20)
check("list_jobs (past_sla)", r,
      (lambda r: isinstance(r["data"]["jobs"], list),                             "jobs not list"),
      (lambda r: all(j.get("status") not in {"DONE","CLOSED","FALSE_POSITIVE"}
                     for j in r["data"]["jobs"]),                                 "terminal in past_sla"),
)

# ── 4a. get_job_detail — real job ────────────────────────────────────────────
jobs_r = list_jobs(ROLE, limit=1)
if jobs_r["ok"] and jobs_r["data"]["jobs"]:
    first_id = jobs_r["data"]["jobs"][0]["job_id"]
    r = get_job_detail(ROLE, first_id)
    check(f"get_job_detail ({first_id})", r,
          (lambda r: r["data"]["job_id"] == first_id, "job_id mismatch"),
          (lambda r: "cve_list" in r["data"],          "missing cve_list"),
          (lambda r: "status" in r["data"],             "missing status"),
    )
else:
    results.append(("get_job_detail (real job)", False, "no jobs in DB"))

# ── 4b. get_job_detail — missing id ──────────────────────────────────────────
check_false("get_job_detail (missing id)", get_job_detail(ROLE, "JOB-DOESNOTEXIST"))

# ── 5a. search_cves — known CVE ──────────────────────────────────────────────
r = search_cves(ROLE, "CVE-2024-21762")
check("search_cves (CVE-2024-21762)", r,
      (lambda r: r["data"]["cve_id"] == "CVE-2024-21762",      "cve_id mismatch"),
      (lambda r: isinstance(r["data"]["affected_jobs"], list),  "affected_jobs not list"),
      (lambda r: isinstance(r["data"]["found"], bool),          "found not bool"),
      (lambda r: isinstance(r["data"]["kev"], bool),            "kev not bool"),
)

# ── 5b. search_cves — bogus CVE ──────────────────────────────────────────────
r = search_cves(ROLE, "CVE-1999-99999")
check("search_cves (unknown CVE)", r,
      (lambda r: r["data"]["found"] is False,                  "unknown CVE should have found=False"),
      (lambda r: r["data"]["affected_jobs"] == [],             "should have empty affected_jobs"),
)

# ── 5c. search_cves — kev_only flag ─────────────────────────────────────────
r = search_cves(ROLE, "CVE-1999-99999", kev_only=True)
check("search_cves (kev_only, not in KEV)", r,
      (lambda r: r["data"]["kev"] is False, "kev should be False for unknown CVE"),
)

# ── 6. get_enrichment_status ──────────────────────────────────────────────────
r = get_enrichment_status(ROLE)
check("get_enrichment_status", r,
      (lambda r: "kev"  in r["data"],                          "missing kev key"),
      (lambda r: "epss" in r["data"],                          "missing epss key"),
      (lambda r: "nvd"  in r["data"],                          "missing nvd key"),
      (lambda r: "db_exists" in r["data"],                     "missing db_exists"),
      (lambda r: isinstance(r["data"]["kev"]["cached"], int),  "kev.cached not int"),
)

# ── 7. get_threat_alerts ──────────────────────────────────────────────────────
r = get_threat_alerts(ROLE, status="open", limit=10)
check("get_threat_alerts (open)", r,
      (lambda r: isinstance(r["data"]["alerts"], list), "alerts not list"),
      (lambda r: isinstance(r["data"]["total"], int),   "total not int"),
      (lambda r: r["data"]["total"] >= len(r["data"]["alerts"]),
       "total < len(alerts)"),
)

r = get_threat_alerts(ROLE, kev_only=True, limit=5)
check("get_threat_alerts (kev_only)", r,
      (lambda r: isinstance(r["data"]["alerts"], list), "alerts not list"),
      (lambda r: all(a.get("is_kev") == 1 for a in r["data"]["alerts"]),
       "non-KEV alert in kev_only result"),
)

# ── 8. get_risk_acceptances ───────────────────────────────────────────────────
r = get_risk_acceptances(ROLE)
check("get_risk_acceptances (active)", r,
      (lambda r: isinstance(r["data"]["risk_acceptances"], list), "not a list"),
      (lambda r: isinstance(r["data"]["count"], int),             "count not int"),
)

r = get_risk_acceptances(ROLE, expired=True)
check("get_risk_acceptances (expired)", r,
      (lambda r: isinstance(r["data"]["risk_acceptances"], list), "not a list"),
)

# ── 9a. query_controls — ISO framework ───────────────────────────────────────
r = query_controls(ROLE, framework="ISO27001")
check("query_controls (ISO27001)", r,
      (lambda r: r["data"]["count"] > 0,                                 "no ISO27001 controls returned"),
      (lambda r: all("evidence" in c for c in r["data"]["controls"]),    "control missing evidence"),
      (lambda r: all("status" in c for c in r["data"]["controls"]),      "control missing status"),
      (lambda r: all(c["framework"] == "ISO27001"
                     for c in r["data"]["controls"]),                    "wrong framework in result"),
)

# ── 9b. query_controls — specific control ────────────────────────────────────
r = query_controls(ROLE, control_id="CIS-7")
check("query_controls (CIS-7)", r,
      (lambda r: r["data"]["count"] == 1,                             "expected exactly 1"),
      (lambda r: r["data"]["controls"][0]["control_id"] == "CIS-7",  "wrong control_id"),
      (lambda r: r["data"]["controls"][0]["status"] in
                 {"full","partial","supporting","not_applicable"},    "invalid status value"),
)

# ── 9c. query_controls — all controls ────────────────────────────────────────
r = query_controls(ROLE)
check("query_controls (all)", r,
      (lambda r: r["data"]["count"] == 22, f"expected 22 controls, got {r['data']['count']}"),
)

# ── 10. search_knowledge ─────────────────────────────────────────────────────
r = search_knowledge(ROLE, "how to prioritize vulnerability remediation with limited capacity", top_k=3)
check("search_knowledge (3 chunks)", r,
      (lambda r: isinstance(r["data"]["chunks"], list),            "chunks not list"),
      (lambda r: r["data"]["count"] == len(r["data"]["chunks"]),   "count mismatch"),
      (lambda r: all("text" in c for c in r["data"]["chunks"]),    "chunk missing text"),
      (lambda r: all("metadata" in c for c in r["data"]["chunks"]), "chunk missing metadata"),
)

r = search_knowledge(ROLE, "compensating controls network segmentation", top_k=5)
check("search_knowledge (5 chunks)", r,
      (lambda r: len(r["data"]["chunks"]) > 0, "no chunks returned"),
)

# ── Invalid role ──────────────────────────────────────────────────────────────
check_false("role validation (bad role)", get_metrics("hacker"))

# ═══════════════════════════════════════════════════════════════════════════════
# Registry checks
# ═══════════════════════════════════════════════════════════════════════════════

EXPECTED_TOOLS = [
    "get_metrics", "get_sla_compliance", "list_jobs", "get_job_detail",
    "search_cves", "get_enrichment_status", "get_threat_alerts",
    "get_risk_acceptances", "query_controls", "search_knowledge",
]

tools = list_tools()
check(
    "registry.list_tools() — count",
    {"ok": len(tools) == len(EXPECTED_TOOLS)},
    (lambda _: len(tools) == len(EXPECTED_TOOLS),
     f"expected {len(EXPECTED_TOOLS)} tools, got {len(tools)}"),
)

for name in EXPECTED_TOOLS:
    entry = get_tool(name)
    check(
        f"registry.get_tool({name})",
        {"ok": entry is not None},
        (lambda _: entry is not None,               "not found in registry"),
        (lambda _: callable(entry["fn"]),           "fn not callable"),
        (lambda _: entry.get("readonly") is True,  "readonly must be True"),
        (lambda _: "input_schema" in entry,         "missing input_schema"),
        (lambda _: entry["input_schema"].get("type") == "object",
         "input_schema.type must be 'object'"),
    )

# ── schema has no unexpected extra required params ────────────────────────────
for name, entry in [(n, get_tool(n)) for n in EXPECTED_TOOLS]:
    schema   = entry["input_schema"]
    required = schema.get("required", [])
    props    = set(schema.get("properties", {}).keys())
    unknown  = [p for p in required if p not in props]
    check(
        f"schema.required fields exist ({name})",
        {"ok": not unknown},
        (lambda _: not unknown, f"required fields not in properties: {unknown}"),
    )

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

W = 64
SEP = "-" * W
print(f"\n{SEP}")
print(f"  VRA Tool Layer -- {len(results)} checks")
print(f"{SEP}")
passed = 0
for label, ok, msg in results:
    badge = PASS if ok else FAIL
    print(f"  {badge}  {label}")
    if msg:
        for line in msg.split(" | "):
            print(f"        -> {line}")
    if ok:
        passed += 1
print(f"{SEP}")
print(f"  {passed}/{len(results)} passed")
print(f"{SEP}\n")

sys.exit(0 if passed == len(results) else 1)
