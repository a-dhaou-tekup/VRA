#!/usr/bin/env python3
"""
precache_demo_ai.py — Pre-generate AI content for the demo.

Pre-requisites:
  - seed_demo.py must have been run first
  - start_demo.bat must be running (backend on http://localhost:8001)
  - Ollama must be running with qwen2.5:14b loaded
      check: ollama list   (should show qwen2.5:14b)

Run the evening before the demo, AFTER seed_demo.py:
    python scripts/precache_demo_ai.py

Steps:
  1. Verify Ollama has the model loaded
  2. Login as admin → get JWT
  3. Find the top critical jobs (Log4Shell, PAN-OS, Spring4Shell …)
  4. Generate + cache AI recommendation for each (calls Ollama)
  5. Pre-run demo chat conversations (stores Q&A in DB — instant replay on demo day)
  6. Generate executive PDF report (calls Ollama)
  7. Verify PDF is downloadable
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT     = Path(__file__).parent.parent
BASE_URL = "http://localhost:8001"
OLLAMA   = "http://localhost:11434"

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

def _get(path: str, base: str = BASE_URL, token: str | None = None) -> dict:
    req = urllib.request.Request(f"{base}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())

def _post_json(path: str, payload: dict, token: str | None = None,
               base: str = BASE_URL) -> dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(f"{base}{path}", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())

def _post_login(username: str, password: str) -> str:
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req  = urllib.request.Request(f"{BASE_URL}/api/auth/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]

# ── Steps ─────────────────────────────────────────────────────────────────────

def step1_check_ollama() -> None:
    hdr("Step 1/6 — Checking Ollama")
    try:
        result = _get("/api/tags", base=OLLAMA)
        models = [m["name"] for m in result.get("models", [])]
        qwen   = [m for m in models if "qwen2.5" in m.lower()]
        if qwen:
            ok(f"Ollama running — found: {', '.join(qwen)}")
        else:
            warn(f"qwen2.5 not found in loaded models: {models}")
            warn("Run: ollama pull qwen2.5:14b")
            warn("Continuing anyway — generation will fail if model is missing.")
    except Exception as e:
        err(f"Ollama not reachable at {OLLAMA}: {e}")
        err("Start Ollama:  ollama serve")
        err("Load model:    ollama pull qwen2.5:14b")
        sys.exit(1)


def step2_login() -> str:
    hdr("Step 2/6 — Logging in as admin")
    try:
        token = _post_login("admin", "Admin1234!")
        ok("Got JWT token")
        return token
    except Exception as e:
        err(f"Login failed: {e}")
        sys.exit(1)


def step3_find_demo_jobs(token: str) -> list[dict]:
    hdr("Step 3/6 — Finding top critical jobs to pre-cache")

    # Fetch up to 200 jobs sorted by risk
    result = _get("/api/jobs?limit=200&sort_by=max_risk_level&sort_dir=desc", token=token)
    jobs   = result.get("data", result.get("jobs", []))

    if not jobs:
        err("No jobs found. Did you run seed_demo.py first?")
        sys.exit(1)

    # Priority CVEs we want pre-cached for the demo
    priority_cves = [
        "CVE-2021-44228",   # Log4Shell  ← main demo job
        "CVE-2024-3400",    # PAN-OS     ← demo job 2
        "CVE-2022-22965",   # Spring4Shell
        "CVE-2021-26855",   # ProxyLogon (Exchange)
        "CVE-2024-21762",   # FortiOS
    ]

    selected: list[dict] = []
    seen_ids: set[str]   = set()

    # First pass: match priority CVEs
    for cve in priority_cves:
        for job in jobs:
            jid = job.get("job_id") or job.get("id", "")
            if jid in seen_ids:
                continue
            cves_in_job = (job.get("cve_ids") or job.get("primary_cve") or "")
            if isinstance(cves_in_job, list):
                cves_in_job = ",".join(cves_in_job)
            if cve.lower() in str(cves_in_job).lower():
                selected.append(job)
                seen_ids.add(jid)
                break

    # Second pass: fill up to 5 with top-risk jobs not already selected
    for job in jobs:
        if len(selected) >= 5:
            break
        jid = job.get("job_id") or job.get("id", "")
        if jid not in seen_ids:
            selected.append(job)
            seen_ids.add(jid)

    for j in selected:
        jid   = j.get("job_id") or j.get("id")
        title = j.get("product") or j.get("title") or j.get("primary_cve") or "?"
        risk  = j.get("max_risk_level") or "?"
        ok(f"  {jid}  [{risk:8s}]  {title}")

    return selected


def step4_cache_ai_advice(token: str, jobs: list[dict]) -> None:
    hdr("Step 4/6 — Generating AI recommendations (calls Ollama — takes 2–4 min each)")
    print("    Each job requires one full LLM inference pass. Do not interrupt.")

    for i, job in enumerate(jobs, 1):
        jid   = job.get("job_id") or job.get("id")
        title = job.get("product") or job.get("primary_cve") or jid

        print(f"\n    [{i}/{len(jobs)}] {title} ({jid}) …", flush=True)
        t0 = time.time()

        try:
            result  = _get(f"/api/rag/jobs/{jid}/recommend", token=token)
            cached  = result.get("cached", False)
            elapsed = int(time.time() - t0)
            src     = "already cached" if cached else f"generated in {elapsed}s"
            ok(f"  {title} → {src}")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            warn(f"  {title} → HTTP {e.code}: {body[:200]}")
        except Exception as e:
            warn(f"  {title} → {e}")


# ── Demo chat Q&A scripts ─────────────────────────────────────────────────────
# Each entry: CVE hint (matched against job cve_ids) + ordered list of questions.
# Multi-turn: later questions are sent in the same conversation so the LLM has context.
DEMO_CHAT_SCRIPTS: list[dict] = [
    {
        "label": "Log4Shell — RHEL 9 / SELinux (main demo question)",
        "cve_hint": "CVE-2021-44228",
        "turns": [
            # Act 5 scripted question — must be first
            (
                "Our Frankfurt servers run RHEL 9 with SELinux in enforcing mode. "
                "Does the log4j2 upgrade to 2.17.1 differ from the standard Ubuntu "
                "procedure, and are there any SELinux policy considerations?"
            ),
            # Follow-up — shows multi-turn context awareness
            (
                "Which specific log4j2 JAR files should we grep for in the JVM "
                "classpath on prod-api-01 and prod-api-02 to confirm full remediation?"
            ),
            # EPSS / KEV integration showcase
            (
                "What is the EPSS exploitation probability for Log4Shell and does the "
                "CISA KEV listing change our SLA deadline?"
            ),
        ],
    },
    {
        "label": "PAN-OS GlobalProtect — CVE-2024-3400",
        "cve_hint": "CVE-2024-3400",
        "turns": [
            (
                "Has CVE-2024-3400 been actively exploited in the wild targeting "
                "financial institutions, and are there known threat-actor TTPs we "
                "should brief the SOC team on?"
            ),
            (
                "What is the Palo Alto recommended workaround for vpn-gw-01 if we "
                "cannot immediately upgrade PAN-OS from 11.0.3 — can telemetry "
                "disabling fully mitigate the risk?"
            ),
        ],
    },
    {
        "label": "Spring4Shell — CVE-2022-22965",
        "cve_hint": "CVE-2022-22965",
        "turns": [
            (
                "Does Spring4Shell require JDK 9+ and a WAR deployment to be "
                "exploitable? Our prod-api-01 runs Spring WebMVC 5.3.17 on JDK 11 "
                "in an embedded Tomcat JAR — are we in scope?"
            ),
        ],
    },
    {
        "label": "FortiOS SSL-VPN — CVE-2024-21762",
        "cve_hint": "CVE-2024-21762",
        "turns": [
            (
                "What is the minimum FortiOS version that patches CVE-2024-21762, "
                "and does Fortinet recommend disabling SSL-VPN as an interim "
                "workaround for our fortigate-fw-01 running 7.4.2?"
            ),
        ],
    },
    {
        "label": "ProxyLogon — CVE-2021-26855",
        "cve_hint": "CVE-2021-26855",
        "turns": [
            (
                "What Exchange-specific indicators of compromise should our IR team "
                "look for on mail-srv-01 after ProxyLogon exposure — web shells, "
                "registry keys, unusual OWA traffic patterns?"
            ),
        ],
    },
    {
        "label": "PrintNightmare — CVE-2021-34527",
        "cve_hint": "CVE-2021-34527",
        "turns": [
            (
                "Can we safely disable the Windows Print Spooler service on "
                "sharepoint-01 (Windows Server 2019) without breaking SharePoint "
                "functionality, or should we apply the registry-based mitigation instead?"
            ),
        ],
    },
]


def _stream_chat_sse(path: str, payload: dict, token: str) -> str:
    """POST to the SSE chat endpoint and collect the full assistant response."""
    try:
        import requests as _req
    except ImportError:
        raise RuntimeError(
            "The 'requests' library is required for chat pre-caching.\n"
            "Install it: pip install requests"
        )

    resp = _req.post(
        f"{BASE_URL}{path}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        stream=True,
        timeout=600,
    )
    resp.raise_for_status()

    full: list[str] = []
    for raw in resp.iter_lines(decode_unicode=True):
        if not raw or not raw.startswith("data: "):
            continue
        try:
            event = json.loads(raw[6:])
        except json.JSONDecodeError:
            continue
        t = event.get("type")
        if t == "token":
            full.append(event.get("content", ""))
        elif t == "done":
            break
        elif t == "error":
            raise RuntimeError(f"SSE error: {event.get('detail', '?')}")

    return "".join(full)


def step5_cache_chat_conversations(token: str, jobs: list[dict]) -> None:
    hdr("Step 5/7 — Pre-running demo chat conversations (calls Ollama)")
    print("    Each turn is a full LLM inference. This takes several minutes.")

    # Build CVE → job_id index from already-found jobs
    cve_to_job: dict[str, dict] = {}
    for job in jobs:
        raw = job.get("cve_ids") or job.get("primary_cve") or job.get("cve_list") or ""
        if isinstance(raw, list):
            raw = ",".join(raw)
        for cve in str(raw).upper().split(","):
            cve = cve.strip()
            if cve:
                cve_to_job[cve] = job

    # Also fetch broader job list so we can match CVEs not in the top-5
    try:
        extra = _get("/api/jobs?limit=500&sort_by=max_risk_level&sort_dir=desc", token=token)
        for job in extra.get("data", []):
            raw = job.get("cve_ids") or job.get("primary_cve") or job.get("cve_list") or ""
            if isinstance(raw, list):
                raw = ",".join(raw)
            for cve in str(raw).upper().split(","):
                cve = cve.strip()
                if cve and cve not in cve_to_job:
                    cve_to_job[cve] = job
    except Exception:
        pass

    for script in DEMO_CHAT_SCRIPTS:
        label    = script["label"]
        cve_hint = script["cve_hint"].upper()
        turns    = script["turns"]

        job = cve_to_job.get(cve_hint)
        if not job:
            warn(f"No job found for {cve_hint} — skipping '{label}'")
            continue

        job_id = job.get("job_id") or job.get("id")
        print(f"\n    {label}")
        print(f"    Job: {job_id}", flush=True)

        conversation_id: str | None = None
        for qi, question in enumerate(turns, 1):
            q_short = question[:80].replace("\n", " ")
            print(f"      Q{qi}: {q_short}…", flush=True)
            t0 = time.time()
            try:
                payload: dict = {"message": question}
                if conversation_id:
                    payload["conversation_id"] = conversation_id

                # First call: no conv_id → backend creates one; subsequent calls reuse it
                # We need to intercept the "done" event to get the conversation_id.
                # Do a raw SSE call to capture it.
                try:
                    import requests as _req
                except ImportError:
                    raise RuntimeError("pip install requests")

                resp = _req.post(
                    f"{BASE_URL}/api/findings/{job_id}/chat",
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                    stream=True,
                    timeout=600,
                )
                resp.raise_for_status()

                tokens: list[str] = []
                for raw in resp.iter_lines(decode_unicode=True):
                    if not raw or not raw.startswith("data: "):
                        continue
                    try:
                        event = json.loads(raw[6:])
                    except json.JSONDecodeError:
                        continue
                    etype = event.get("type")
                    if etype == "token":
                        tokens.append(event.get("content", ""))
                    elif etype == "done":
                        if conversation_id is None:
                            conversation_id = event.get("conversation_id")
                        break
                    elif etype == "error":
                        raise RuntimeError(event.get("detail", "SSE error"))

                elapsed = int(time.time() - t0)
                word_count = len("".join(tokens).split())
                ok(f"      Q{qi} → {word_count} words in {elapsed}s (conv={conversation_id})")

            except Exception as exc:
                warn(f"      Q{qi} failed: {exc}")
                break  # Don't attempt follow-up turns if the first failed

        if conversation_id:
            ok(f"    Saved conversation {conversation_id} for {cve_hint}")


def step6_generate_pdf(token: str) -> str | None:
    hdr("Step 6/7 — Generating executive PDF report (calls Ollama — takes 3–6 min)")
    print("    Polling until status = done …")

    try:
        created = _post_json(
            "/api/reports/executive",
            {"period_days": 30},
            token=token,
        )
        report_id = created.get("data", created).get("id") or created.get("id")
        ok(f"Report queued — id={report_id}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        err(f"Failed to create report: HTTP {e.code}: {body[:300]}")
        return None
    except Exception as e:
        err(f"Failed to create report: {e}")
        return None

    # Poll until done (max 10 minutes)
    deadline = time.time() + 600
    dots     = 0
    while time.time() < deadline:
        time.sleep(10)
        dots += 1
        print(f"    waiting{'.' * (dots % 5)}    ", end="\r", flush=True)
        try:
            status = _get(f"/api/reports/executive/{report_id}", token=token)
            s      = (status.get("data") or status).get("status", "?")
            if s == "done":
                print()
                ok(f"PDF generated — report_id={report_id}")
                return report_id
            if s == "failed":
                print()
                msg = (status.get("data") or status).get("error_message", "unknown error")
                err(f"PDF generation failed: {msg}")
                return None
        except Exception:
            pass

    print()
    err("PDF generation timed out after 10 minutes")
    return None


def step6_verify_pdf(token: str, report_id: str | None) -> None:
    hdr("Step 7/7 — Verifying PDF download")
    if not report_id:
        warn("Skipped — no report_id (PDF generation failed or was skipped)")
        return

    try:
        req = urllib.request.Request(
            f"{BASE_URL}/api/reports/executive/{report_id}/pdf"
        )
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=30) as r:
            size_kb = len(r.read()) // 1024
        ok(f"PDF downloads successfully — {size_kb} KB")
        ok(f"  URL: {BASE_URL}/api/reports/executive/{report_id}/pdf")
    except Exception as e:
        warn(f"PDF download check failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{'─'*55}")
    print("  ODDO BHF — VRA AI Pre-cache")
    print(f"{'─'*55}{RESET}")
    print("  Pre-generates AI recommendations + executive PDF.")
    print("  Requires: Ollama running with qwen2.5:14b loaded.")
    print()

    step1_check_ollama()
    token     = step2_login()
    jobs      = step3_find_demo_jobs(token)
    step4_cache_ai_advice(token, jobs)
    step5_cache_chat_conversations(token, jobs)
    report_id = step6_generate_pdf(token)
    step6_verify_pdf(token, report_id)

    print(f"\n{BOLD}{GREEN}{'─'*55}")
    print("  AI pre-cache complete. Demo is ready.")
    print(f"{'─'*55}{RESET}")
    print()
    print("  On demo day, start with:")
    print("    start_demo.bat")
    print()
    print("  Then open: http://localhost:5174")
    print("  Login:     admin / Admin1234!")
    print()


if __name__ == "__main__":
    main()
