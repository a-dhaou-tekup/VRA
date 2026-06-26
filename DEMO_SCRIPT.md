# VRA — Demo Script
**ODDO BHF · TEK-UP End-of-Studies Defence**
*Run time: ~15 min · Login: `admin / Admin1234!` · URL: http://localhost:5174*

---

## Pre-Demo Checklist

Run the night before:
```
python scripts/seed_demo.py          # seeds demo.db with assets, scan, jobs
python scripts/precache_demo_ai.py   # pre-generates AI advice + chat Q&A (needs Ollama)
```

Morning of demo — verify all green:
```
ollama list                          # must show qwen2.5:14b
curl http://localhost:8001/health    # {"status":"ok"}
curl http://localhost:5174           # React app responds
curl http://localhost:8001/api/rag/stats  # count > 0 (RAG indexed)
```

> **If Ollama is slow on demo day**: every AI response is pre-cached.
> Use the **History** button in the Chat tab to load the pre-run conversation instantly.

---

## Act 1 — The Problem (1 min)
**Page: Overview Dashboard**

Open the dashboard. Let the jury see it cold for a moment.

> *"This is what a security team at ODDO BHF sees after running their quarterly vulnerability scan.
> The scanner returned over 50 raw findings across production, DMZ, and workstations.
> Without VRA, that's 50 rows in a spreadsheet. The team has to manually triage, prioritise,
> and assign each one. With VRA, that work is done automatically."*

Point to the KPI cards:
- **Critical / High jobs** — risk-scored, not raw CVSS
- **KEV count** — findings already exploited in the wild
- **SLA breached** — jobs past their deadline (red indicator)

> *"The dashboard is live. Let me show you how a finding goes from raw scanner output
> to a prioritised remediation job — and how the AI explains what to do."*

---

## Act 2 — Risk Scoring & Job Detail (2 min)
**Page: Remediation Jobs → any CRITICAL job**

1. Navigate to **Remediation Jobs**. Sort by Risk Level → click the top CRITICAL job
   (Log4Shell on `prod-api-01` / `prod-api-02`).

2. Point to the **risk score breakdown** card:

   > *"The raw CVSS for Log4Shell is 10.0. But VRA adds four more signals:
   > CISA KEV (exploited in the wild — +20), EPSS probability (+15),
   > asset criticality (+15 for a production API server), and internet exposure (+10).
   > The result is a score of 99 — CRITICAL with a **7-day SLA**.
   > The same CVE on a dev box scores 78 — HIGH, 14-day SLA.
   > Same vulnerability, different urgency — that's the whole point."*

3. Show the **AI Recommendation** tab — the cached response renders instantly.

   > *"This advice was generated locally by Qwen2.5-14B running on the machine
   > behind me — no cloud, no API call, no data leaves ODDO BHF's perimeter."*

4. Point to the **Blast Radius graph** tab:
   - Graph loads, shows CVE → component → asset → service → owner chain
   - Drag a node to demonstrate free movement

   > *"This is the dependency blast radius: if Log4Shell is exploited on prod-api-01,
   > it can pivot to the Trading Platform service. The owners are automatically
   > identified for notification."*

---

## Act 3 — Upload Scan Results: DMZ Perimeter Scan (2 min)
**Page: Upload Scan Results**
**File: `data/input/scanner_demo_dmz.csv`**

**Narrative:** *"After the morning FS-ISAC alert the security team ran an unscheduled targeted
scan of the DMZ and perimeter systems — hosts not covered by the Q2 scan.
Let me import those results now."*

1. Navigate to **Upload Scan Results**
2. Drag-and-drop **`scanner_demo_dmz.csv`** onto the drop zone
   *(or click to browse → navigate to `data/input/scanner_demo_dmz.csv`)*
3. **Scanner Type**: Auto-detect · **Uploaded by**: `vuln-scan-team`
4. Click **⬆ Upload & Run Pipeline**

Watch the pipeline progress bar step through:
```
Uploading  →  Parsing findings…  →  Running risk scoring…  →  Building jobs…  →  Done!
```

Results panel shows:
| Stat | Value | Talking point |
|------|-------|---------------|
| Re-detected findings | **2** | Log4Shell + Spring4Shell still open on `prod-api-01` — SLA breached |
| New findings | **4** | ActiveMQ, FortiOS FGFM, Ivanti SSRF, ConnectWise ScreenConnect |
| New jobs | **4** | One per new CVE/host group, already risk-scored |

> *"The two re-detections are telling us something important: prod-api-01's
> Log4Shell job was created in the Q2 scan and the SLA clock has been running.
> The system knows these aren't new — they're overdue.*
>
> *The ConnectWise ScreenConnect finding on the management jump server
> is brand new — CVSS 10, KEV listed, ransomware entry point.
> That job just jumped to the top of the queue automatically."*

Click **View Remediation Jobs →** to land on the jobs page filtered to the new upload.

---

## Act 4 — Manual Entry: FS-ISAC Morning Alert (2 min)
**Page: Manual Entry → Add Findings by Hand**

**Narrative:** *"Now here's a scenario that happens every week: CISA publishes a new advisory
at 6 AM. The next scheduled scan is three weeks away. We can't wait.*
*An analyst can enter the findings directly — they go through the exact same
pipeline as a scanner export."*

1. Navigate to **Manual Entry**
2. Click **"Load real-CVE example"** — the form pre-fills with three ODDO BHF findings:

| CVE | Host | CVSS | Why it matters |
|-----|------|------|----------------|
| **CVE-2024-6387** | `prod-db-primary-01` | 8.1 HIGH | regreSSHion — unauthenticated OpenSSH RCE. CISA KEV. Race-condition PoC is publicly available. |
| **CVE-2023-23397** | `workstation-fin-01` | 9.8 CRITICAL | Microsoft Outlook zero-click NTLM hash theft. No user interaction required. Critical for ODDO BHF finance workstations. |
| **CVE-2025-58413** | `fortigate-fw-01` | 7.5 HIGH | Brand-new FortiOS buffer overflow advisory — same firewall as the existing CVE-2024-21762 finding. |

3. **Uploaded by**: `soc-analyst`
4. Click **Submit findings to pipeline**
5. Watch the status: `pending → enriching → scoring → building`
6. Stats appear: new jobs created → click **View jobs →**

> *"Three CVEs, three hosts, under 10 seconds — enriched with KEV flags,
> EPSS probability, SLA deadlines, and grouped into jobs.
> No scanner needed. No spreadsheet. No manual scoring.*
>
> *The Outlook finding on the finance workstation just became a CRITICAL job
> because it's in CISA KEV and the workstation touches the trading network.
> A raw CVSS of 9.8 on its own would have been HIGH on a dev machine —
> asset context changes the answer."*

---

## Act 5 — Context-Aware AI Chat (2 min)
**Page: Job Detail (Log4Shell) → Chat tab**

Navigate to the Log4Shell job (CVE-2021-44228 on `prod-api-01`).

Click the **Chat** tab. Type — or paste — the following question:

```
Our Frankfurt servers run RHEL 9 with SELinux in enforcing mode.
Does the log4j2 upgrade to 2.17.1 differ from the standard Ubuntu
procedure, and are there any SELinux policy considerations?
```

The response streams token by token. When it completes:

> *"This answer is grounded in our local advisory corpus — it knows the RHEL 9
> specifics because we indexed CISA KEV notes and NVD vulnerability descriptions.
> It's not pulling from the internet.*
>
> *Everything stays inside ODDO BHF's perimeter. The model runs on the GPU
> in this machine. No hostname, no CVE count, no internal IP has left this room."*

**If Ollama is slow**: click **History** in the chat panel → select the pre-cached
conversation from last night. The full transcript renders instantly from the database.

### Optional follow-up questions (same conversation):
```
Which specific log4j2 JAR files should we grep for in the JVM classpath
on prod-api-01 to confirm full remediation?
```
```
What is the EPSS exploitation probability for Log4Shell and does the
CISA KEV listing change our SLA deadline?
```

---

## Act 6 — Threat Alerts & Asset Inventory (2 min)
**Pages: Threat Alerts · Asset Inventory**

### Threat Alerts
1. Navigate to **Threat Alerts**
2. Use the chip-based filter bar — click **Severity** → select `CRITICAL` → **Apply**
3. Show the filtered table: CVE, matched hostname, matched product version

   > *"These are live CVE matches against the software inventory.
   > Every asset runs a known software version; VRA cross-references that against
   > the KEV catalogue and EPSS scores — zero scanning required for this view."*

### Asset Inventory
1. Navigate to **Assets**
2. Click the **KEV Matches** column header to sort — assets with the most KEV exposures rise
3. Expand a row to show the KEV alert chips

   > *"An asset's criticality label isn't just metadata — it's a direct input to
   > the risk formula. Marking `prod-db-primary-01` as Critical adds 15 points to
   > every finding on that host. The CMDB becomes a risk multiplier."*

---

## Act 7 — Metrics & SLA Compliance (1 min)
**Page: Metrics**

1. Navigate to **Metrics**
2. Point to the **SLA compliance** chart

   > *"NIS2 and ISO 27001 both require documented remediation timelines.
   > This chart is the evidence trail — not a manual report, not a spreadsheet,
   > but a live view generated directly from the remediation job lifecycle."*

3. Show the **risk distribution** and **KEV coverage** tiles

   > *"At a glance: how much of our exposure is actively exploited,
   > how much is high-EPSS but not yet weaponised, and how much is long-tail noise.
   > That segmentation changes what the team works on Monday morning."*

---

## Fallback Reference — Pre-Cached Chat Topics

If Ollama is unresponsive, open **Chat → History** to load any of these pre-run conversations:

| Job | Question | Pre-cached |
|-----|----------|-----------|
| Log4Shell (CVE-2021-44228) | RHEL 9 + SELinux upgrade procedure | ✓ |
| Log4Shell (CVE-2021-44228) | Which JAR files confirm full remediation | ✓ |
| Log4Shell (CVE-2021-44228) | EPSS probability and SLA impact | ✓ |
| PAN-OS (CVE-2024-3400) | Threat actors targeting financial institutions | ✓ |
| PAN-OS (CVE-2024-3400) | Telemetry-disable workaround | ✓ |
| Spring4Shell (CVE-2022-22965) | JDK 9+ scope + embedded Tomcat | ✓ |
| FortiOS (CVE-2024-21762) | Minimum patch version + workaround | ✓ |
| ProxyLogon (CVE-2021-26855) | Exchange IoC indicators | ✓ |
| PrintNightmare (CVE-2021-34527) | Safe Spooler disable on SharePoint | ✓ |

---

## Demo Data Reference

| File | Purpose | Used in |
|------|---------|---------|
| `data/input/scanner_demo1.csv` | Q2 production scan — 55 findings, 25 hosts | Seeded automatically by `seed_demo.py` |
| `data/input/scanner_demo_dmz.csv` | DMZ perimeter scan — 6 findings, 4 new hosts + 2 re-detections | Drag-drop live in Act 3 |
| Manual entry (pre-filled form) | FS-ISAC morning alert — 3 CVEs on 3 ODDO BHF hosts | Click "Load real-CVE example" in Act 4 |

### DMZ scan findings (`scanner_demo_dmz.csv`)
| CVE | Host | CVSS | Type |
|-----|------|------|------|
| CVE-2021-44228 | prod-api-01 | 10.0 | Re-detected (Log4Shell still open) |
| CVE-2022-22965 | prod-api-01 | 9.8 | Re-detected (Spring4Shell still open) |
| CVE-2023-46604 | backup-srv-01 | 10.0 | New — Apache ActiveMQ RCE (ransomware) |
| CVE-2024-23113 | dmz-fw-01 | 9.8 | New — FortiOS FGFM format string RCE |
| CVE-2024-21893 | vpn-access-01 | 8.2 | New — Ivanti Connect Secure SSRF |
| CVE-2024-1709 | mgmt-jump-01 | 10.0 | New — ConnectWise ScreenConnect auth bypass |

### Manual entry findings (pre-filled via "Load real-CVE example")
| CVE | Host | CVSS | Context |
|-----|------|------|---------|
| CVE-2024-6387 | prod-db-primary-01 | 8.1 | regreSSHion — OpenSSH RCE, CISA KEV |
| CVE-2023-23397 | workstation-fin-01 | 9.8 | Outlook zero-click NTLM theft, CISA KEV |
| CVE-2025-58413 | fortigate-fw-01 | 7.5 | FortiOS stack buffer overflow (new advisory) |

---

## Key Talking Points for the Jury

**"Where does the data come from?"**
> CISA KEV, FIRST EPSS, and NVD are all real live feeds — cached locally for
> offline demo stability. The scan file contains real CVE IDs sourced from those feeds.
> No synthetic or AI-generated CVE data.

**"Why not just use Nessus's dashboard?"**
> Nessus does not enrich with KEV/EPSS, does not group by package across hosts,
> does not generate remediation advice, and locks data in a vendor silo.
> VRA is a vendor-neutral prioritisation layer that works on top of any scanner.

**"Could the AI give wrong advice?"**
> Yes — that is why every advice card shows the retrieved source references,
> a "verify before applying" banner, and the underlying CVE links.
> VRA is decision support, not autopilot.

**"What if the company doesn't use a scanner?"**
> Act 4 — manual entry. Same pipeline, same enrichment, same risk score.
> The ingestion path is source-agnostic.

**"How is this compliant with NIS2 / ISO 27001?"**
> Every status change writes a `job_events` row — full audit trail.
> SLA clocks are calculated from risk level (CRITICAL = 7 days, HIGH = 14 days)
> and visible on every job. The Metrics page is the compliance evidence.

**"Nothing leaves the network?"**
> The only outbound calls are `cve_id`-only lookups to CISA/FIRST/NVD —
> no hostnames, no IP addresses, no scan data. The LLM is bound to
> `localhost:11434` and cannot call out. Demonstrated live in Act 5.
