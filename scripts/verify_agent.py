"""Verify the VRA agent orchestrator on 4 representative questions.

Imports the orchestrator directly — no HTTP server required.

    python scripts/verify_agent.py

For each question prints:
  - Mode (native/react) and iterations consumed
  - Full tools_called trace with args and ok flag
  - Number of RAG contexts returned
  - First 300 chars of the answer
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
import textwrap

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PLATFORM_DB_PATH", "data/cache/platform.db")

from agent.orchestrator import run_agent  # noqa: E402

ROLE     = "analyst"
USERNAME = "verify_script"

QUESTIONS = [
    (
        "L-SLA",
        "How many remediation jobs are past their SLA?",
    ),
    (
        "L-JOBS",
        "Show me the open critical jobs.",
    ),
    (
        "C-ISO",
        "What is our evidence for ISO A.8.8?",
    ),
    (
        "M-MULTI",
        "Which past-SLA critical jobs involve actively exploited CVEs, "
        "and what does best practice say about handling them?",
    ),
]

SEP  = "-" * 70
SEP2 = "=" * 70

print(f"\n{SEP2}")
print("  VRA Agent Verification")
print(f"{SEP2}\n")

all_pass = True

for tag, question in QUESTIONS:
    print(f"[{tag}]  {question}")
    print(SEP)

    try:
        result = run_agent(question, role=ROLE, username=USERNAME)
    except Exception as exc:
        print(f"  ERROR: {exc}")
        all_pass = False
        print()
        continue

    mode       = result.get("mode", "?")
    iterations = result.get("iterations", "?")
    model      = result.get("model", "?")
    tc         = result.get("tools_called", [])
    contexts   = result.get("contexts", [])
    answer     = result.get("answer", "")

    print(f"  mode={mode}  iterations={iterations}  model={model}")
    print()

    if tc:
        print("  tools_called:")
        for i, call in enumerate(tc, 1):
            status = "ok" if call.get("ok") else "FAIL"
            args_str = ", ".join(
                f"{k}={repr(v)}" for k, v in (call.get("args") or {}).items()
            ) or "(no args)"
            print(f"    {i}. [{status}]  {call['name']}({args_str})")
    else:
        print("  tools_called: (none)")

    print()
    print(f"  contexts: {len(contexts)} RAG chunk(s) returned")
    print()

    # Sanitise for Windows cp1252 console
    safe_answer = answer.encode("ascii", errors="replace").decode("ascii")
    wrapped = textwrap.fill(safe_answer[:400], width=68, initial_indent="  ", subsequent_indent="  ")
    print("  answer (first 400 chars):")
    print(wrapped)
    if len(answer) > 400:
        print("  [...]")

    # Basic checks
    checks = []
    if tag == "L-SLA":
        expected = {"get_sla_compliance", "get_metrics"}
        called   = {c["name"] for c in tc}
        hit      = bool(called & expected)
        checks.append(("called get_sla_compliance or get_metrics", hit))
    elif tag == "L-JOBS":
        called = {c["name"] for c in tc}
        checks.append(("called list_jobs", "list_jobs" in called))
    elif tag == "C-ISO":
        called = {c["name"] for c in tc}
        checks.append(("called query_controls", "query_controls" in called))
    elif tag == "M-MULTI":
        called = {c["name"] for c in tc}
        checks.append(("called list_jobs",       "list_jobs"       in called))
        checks.append(("called search_knowledge", "search_knowledge" in called))

    if checks:
        print()
        print("  assertions:")
        for desc, ok in checks:
            badge = "PASS" if ok else "FAIL"
            print(f"    [{badge}]  {desc}")
            if not ok:
                all_pass = False

    print()

print(SEP2)
print(f"  Overall: {'ALL PASSED' if all_pass else 'SOME CHECKS FAILED'}")
print(f"{SEP2}\n")

sys.exit(0 if all_pass else 1)
