# VRA — Extended Plan & Build Specs (target: operational by June 3)

**Today:** May 21 · **Defense:** June 3 · **Window:** ~13 days, with a hard freeze June 1–2.
**Mode:** Claude Code (Desktop "Code" tab) does the coding; you operate, verify, and judge AI quality.

This extends `VRA_Next_Phase_Plan.md`. The core-verification work (Phase 0 below) is unchanged from
that plan and from the prompts in `VRA_ClaudeCode_Prompts.md` — do it first, it's the gate for
everything else.

---

## 0. Feasibility verdict (honest)

| Tier | Features | By June 3? |
|---|---|---|
| **Spine (must)** | Core verification · RBAC + role separation · Full lifecycle (risk acceptance / workaround) · KPI dashboards + export | **Yes, comfortably** |
| **High-value (should)** | Fleet management expansion · External threat-exposure matching (legitimate feeds) | **Yes if spine goes smoothly** |
| **Stretch (cut-able)** | External exposure scan (nmap-based) | **Only if ahead — designed to be dropped** |

The spine alone fully addresses your supervisor's note (RBAC, lifecycle states, dashboards/SLAs/KPIs
for control). Everything above the spine is upside.

> **One reframe carried over from our discussion:** the "scan breach forums for zero-days" idea is
> replaced by **external threat-exposure matching from legitimate sources** (NVD/OSV CPE→CVE, KEV/EPSS
> per-asset alerts, and an opt-in breach-*notification* API for your own domain). No forum/dark-web
> crawling: those sources host illegally-obtained data and storing it is itself a legal liability for a
> student tool. The legitimate version is more defensible and demos just as well.

---

## 1. Revised timeline (13 days)

| Day(s) | Phase | Output |
|---|---|---|
| 1–2 | **P0 Core verification** | LLM/RAG proven live; corpus indexed; 3 bugs fixed; EPSS in; pipeline rebuilt; recs pre-cached |
| 3–4 | **P1 RBAC + role separation** | Users, roles, login, role-gated endpoints + UI; separation of duties |
| 5–6 | **P2 Lifecycle + risk acceptance** | Full vuln lifecycle state machine; risk-acceptance register; workaround/mitigation |
| 7–8 | **P3 KPI dashboards + export** | Operational / executive / compliance dashboards; PDF + CSV + XLSX export |
| 9 | **P4a Fleet management** | Software inventory per asset (CPE); fleet grouping |
| 10 | **P4b Threat-exposure matching** | CPE→CVE alerts; KEV/EPSS per-asset; optional domain breach check |
| 11 | **P5 External exposure scan (STRETCH)** | nmap-based exposure level feeding the risk model — *cut if behind* |
| 12–13 | **FREEZE** | Dry-run, pre-cache, screenshots, **report update**, tag `v1.0` |

**Cut rule:** if you reach Day 11 and the spine + P4 aren't rock-solid, **skip P5** and spend the day
hardening. A flawless spine beats a shaky external scanner at a defense.

**Report:** the LaTeX report needs new functional requirements, the lifecycle state diagram, the RBAC
actor model, and KPI definitions. Do this during the freeze (Days 12–13) — I can extend the `.tex` for
you so it's a paste-in, not a rewrite.

---

## 2. Build specs (give these to Claude Code)

Each spec lists the data model, API, UI, and **acceptance criteria** so Claude Code builds the right
thing and you can verify it. All of it follows your existing pattern: raw `sqlite3`, repository →
service → router, `migrate.py` creates schema on startup, React pages + axios client.

### P1 — RBAC + role separation
- **Data:** new `users` (id, username, password_hash, role, active, created_at). Roles:
  `admin, analyst, remediation_owner, risk_owner, auditor`.
- **Auth:** replace the single API key with per-user login → token; FastAPI dependency
  `require_role(*roles)` enforced per endpoint. Seed one user per role for the demo.
- **Separation of duties:** only `risk_owner` may approve risk acceptance; only `admin` manages users
  and policy/SLA config; `auditor` is read-only everywhere incl. the audit trail.
- **UI:** login page; role-aware nav (hide/disable actions the role can't perform).
- **Acceptance:** each seeded role can do exactly its allowed actions and is blocked elsewhere; an
  analyst cannot approve a risk acceptance; the audit trail shows who did what.

### P2 — Vulnerability lifecycle + risk acceptance + workaround
- **Lifecycle states:** `scanned → triaged → {patchable | workaround_available | no_fix} → in_progress
  → {patched | mitigated | risk_accepted | false_positive} → verified → closed`, with `resurfaced` as a
  regression path. Store on the job; every transition writes a `job_events` row.
- **Risk acceptance:** new `risk_acceptances` (job_id, accepted_by, justification,
  compensating_controls, expiry_date, review_trigger, created_at). While accepted, the **SLA clock
  pauses**; the job appears on a dedicated **Accepted-Risk Register** with expiry tracking.
- **Workaround/mitigation:** capture the compensating control + a follow-up "patch properly" date;
  `mitigated` is distinct from `patched`.
- **UI:** status workflow control on Job Detail (valid transitions only); risk-acceptance form (gated to
  `risk_owner`); Accepted-Risk Register page; visual badge for state.
- **Acceptance:** invalid transitions rejected; risk acceptance pauses SLA and shows on the register
  with expiry; expired acceptances flagged; all transitions audited.

### P3 — KPI dashboards + export
- **KPIs:** MTTR by severity; SLA-compliance %; KEV findings open past SLA; open + expired
  risk-acceptances; remediation backlog trend; reopen/resurface rate.
- **Dashboards (per audience):** Operational (analyst/ops), Executive (posture + compliance %),
  Compliance/Audit (accepted-risk register + audit trail + SLA-breach evidence).
- **Export:** each dashboard to **CSV + XLSX + PDF**. Backend endpoints return the file; PDF via a
  Python lib (e.g. reportlab) or server-side render.
- **Acceptance:** each dashboard renders from real data; each export downloads a correct file; numbers
  reconcile with the DB.

### P4a — Fleet management
- **Data:** extend `assets` (os_version, environment, site, owning_team); new `asset_software`
  (asset_id, product, version, cpe). Fleet = logical grouping by environment / business unit /
  exposure zone.
- **Upload:** extend the asset import to accept a software inventory (CPEs ideal — they're the bridge to
  CVE feeds).
- **Acceptance:** upload a fleet with software; assets show their software; can group/filter by fleet.

### P4b — External threat-exposure matching (legitimate sources only)
- **CPE→CVE:** match each asset's `asset_software` CPEs against NVD/OSV; surface newly-matching CVEs as
  **per-asset alerts**.
- **KEV/EPSS per-asset:** when a KEV or high-EPSS CVE matches installed software, raise an alert tied to
  the specific assets.
- **Domain breach check (optional):** opt-in integration with a legitimate breach-*notification* API
  (e.g. HIBP domain API) for your **own** domain only — uses an aggregator that already did lawful
  collection; never touches raw stolen data. Stub/sample is fine for the demo if no API key.
- **Acceptance:** a newly-matching CVE for an installed product appears as an alert linked to the right
  asset(s); KEV match raises a priority alert. **No forum/dark-web crawling anywhere.**

### P5 — External exposure scan (STRETCH, cut-able)
- **Scan:** wrap `nmap` (and optionally `nuclei`) to determine, for an asset's public IP/hostname, what
  is reachable externally: open ports, service/version, inferred exposure level
  (none/internal/restricted/internet-facing).
- **Authorization gate (required):** a scan only runs against targets recorded as **authorized/owned**;
  the UI forces an explicit scope-of-authorization acknowledgement. For the demo, scan a local VM you
  control or `scanme.nmap.org` (explicitly authorized for testing).
- **Feeds the risk model:** measured exposure replaces the manual `internet_exposed` flag as the
  `f_expo` factor.
- **Acceptance:** scanning an authorized target stores results and updates that asset's exposure level,
  which then changes its risk scores.

---

## 3. Claude Code prompts (paste one per session)

Phase 0 prompts are in `VRA_ClaudeCode_Prompts.md` (Session 1 = core). Do those first. Below are the new
phases. Start a fresh session per phase; keep `CLAUDE.md` + this file in the repo root.

### P1 — RBAC
```
Read CLAUDE.md and VRA_Extended_Plan_to_June3.md. Build P1 (RBAC + role separation) per its spec.
Plan FIRST and show me the diff before editing — this touches auth, which is sensitive.

1. Add a users table + roles (admin, analyst, remediation_owner, risk_owner, auditor) in migrate.py.
2. Replace the single API key with per-user login returning a token; add a require_role(*roles)
   FastAPI dependency and apply it per endpoint per the spec.
3. Enforce separation of duties: only risk_owner approves risk acceptance; only admin manages
   users/policy; auditor is read-only.
4. Seed one user per role for the demo.
5. Add a login page and make the React nav role-aware.

Verify by logging in as each role and proving it can/can't do the right actions. Show me the checks.
```

### P2 — Lifecycle + risk acceptance
```
Read CLAUDE.md and VRA_Extended_Plan_to_June3.md. Build P2 (lifecycle + risk acceptance + workaround).
Plan the state machine and schema changes first; show me the diff before editing.

1. Implement the lifecycle states from the spec on jobs; enforce valid transitions; write a job_events
   row on every transition.
2. Add risk_acceptances (justification, compensating_controls, expiry, review_trigger, accepted_by);
   pause the SLA clock while accepted; build an Accepted-Risk Register page; flag expired acceptances.
3. Add workaround/mitigation tracking (control + follow-up date); mitigated must be distinct from
   patched.
4. UI: status workflow control on Job Detail (valid transitions only), risk-acceptance form gated to
   risk_owner.

Verify: invalid transition rejected; risk acceptance pauses SLA and shows on the register; transitions
audited. Show me the audit rows.
```

### P3 — KPI dashboards + export
```
Read CLAUDE.md and VRA_Extended_Plan_to_June3.md. Build P3 (KPI dashboards + export).

1. Add metrics endpoints for: MTTR by severity, SLA-compliance %, KEV open past SLA, open/expired risk
   acceptances, backlog trend, reopen/resurface rate.
2. Build three dashboards: Operational, Executive, Compliance/Audit (per the spec).
3. Add CSV + XLSX + PDF export for each dashboard (backend endpoints; PDF via a Python lib).
4. Keep existing Tailwind/Recharts styling.

Verify each dashboard renders from real data and each export downloads a correct file whose numbers
reconcile with the DB. Show me one exported file.
```

### P4 — Fleet + threat-exposure matching
```
Read CLAUDE.md and VRA_Extended_Plan_to_June3.md. Build P4a then P4b.

P4a Fleet: extend assets (os_version, environment, site, owning_team); add asset_software
(product, version, cpe); extend the asset import to accept a software inventory; allow grouping/
filtering by fleet.

P4b Threat-exposure matching (LEGITIMATE SOURCES ONLY — no forum/dark-web crawling):
- Match asset_software CPEs against NVD/OSV; surface per-asset alerts for newly-matching CVEs.
- Raise priority alerts when a KEV or high-EPSS CVE matches installed software.
- (Optional) opt-in domain breach-notification check for our own domain only; stub if no API key.

Verify: a matching CVE for an installed product appears as an alert tied to the right asset(s).
```

### P5 — External exposure scan (STRETCH)
```
Read CLAUDE.md and VRA_Extended_Plan_to_June3.md. Build P5 (external exposure scan). This is stretch —
keep it self-contained so it can be reverted cleanly if we run out of time.

1. Add a scan service wrapping nmap to determine open ports, service/version, and an inferred exposure
   level for an asset's target.
2. REQUIRED: a scan only runs against targets explicitly recorded as authorized/owned; force a
   scope-of-authorization acknowledgement in the UI. For testing use a local VM I control or
   scanme.nmap.org.
3. Feed the measured exposure into the risk model as the f_expo factor (replacing the manual flag).

Verify against an authorized target only; show the stored result and the updated exposure level.
```

### Freeze (Days 12–13)
```
Final pass. Walk me through a full timed demo dry-run via bootstrap, the exact click path (login as
each role -> upload fleet -> jobs -> lifecycle incl. a risk acceptance -> AI recommendation -> KPI
dashboards -> export), flag anything rough, help me capture screenshots, then tag v1.0. Bug-fixes only.
```

---

## 4. Append this to your CLAUDE.md

```
## New scope (extended plan to June 3) — see VRA_Extended_Plan_to_June3.md
- RBAC: users table + roles (admin, analyst, remediation_owner, risk_owner, auditor); require_role
  dependency per endpoint; separation of duties (only risk_owner approves risk acceptance).
- Lifecycle: scanned/triaged/patchable/workaround_available/no_fix/in_progress/patched/mitigated/
  risk_accepted/false_positive/verified/closed/resurfaced; every transition writes job_events.
- risk_acceptances table pauses the SLA clock and feeds an Accepted-Risk Register with expiry.
- KPI dashboards (operational/executive/compliance) + CSV/XLSX/PDF export.
- Fleet: assets gain os_version/environment/site/owning_team; asset_software(product,version,cpe).
- Threat-exposure matching: CPE->CVE via NVD/OSV, KEV/EPSS per-asset alerts, optional domain
  breach-NOTIFICATION API for our own domain. NEVER crawl breach forums or dark-web sources.
- External exposure scan (stretch): nmap wrapper, runs ONLY against authorized/owned targets with an
  explicit authorization gate; feeds the f_expo risk factor.
- Build order: P0 core -> P1 RBAC -> P2 lifecycle -> P3 KPIs -> P4 fleet+matching -> P5 scan (cut-able).
  Plan-first + diff review on auth and any schema change. Verify each phase with real output.
```
