# Re-scan Detection

Re-scan is VRA's mechanism for keeping the job database in sync with reality after a new
vulnerability scan is run. It answers two questions automatically:

> **Did a fixed vulnerability come back?**  
> **Did an open vulnerability disappear?**

---

## The Core Idea: Job Fingerprints

Every remediation job carries a `job_fingerprint` — a SHA-256 hash computed from the
sorted list of affected asset IDs and sorted list of CVE IDs:

```python
payload = ",".join(sorted(asset_ids)) + "|" + ",".join(sorted(cve_list))
fingerprint = hashlib.sha256(payload.encode()).hexdigest()
```

The fingerprint is **content-addressable**: the same combination of assets + CVEs always
produces the same hash, regardless of when or how the scan was run. This lets VRA match
jobs across scans without relying on scanner-assigned IDs.

---

## Two Detection Algorithms

### 1. Resurface Detection

**Question:** Is a job we thought was fixed actually broken again?

```
For each job with status DONE or CLOSED:
    If its fingerprint appears in the new scan's remediation_jobs.csv
    → transition to RESURFACED
```

The new scan produced a job with the exact same asset+CVE combination, meaning the
vulnerability is present again on the same assets. VRA flips the status and writes an
audit event:

```
"Auto-resurfaced: vulnerability re-detected in new scan"
```

### 2. Auto-Fix Detection

**Question:** Did an open job get resolved without someone manually closing it?

```
For each job with status TO_DO or IN_PROGRESS:
    If NONE of its CVEs appear anywhere in the new scan's vuln_enriched.csv
    → transition to DONE
```

The absence of all the job's CVEs from the enriched output means the scanner found no
more instances of those vulnerabilities. VRA closes the job automatically:

```
"Auto-closed: CVEs no longer present in new scan"
```

> **Note:** A job with even one CVE still present stays open. All CVEs must be gone.

---

## What the Two Inputs Are

| File | Default path | What it contains |
|---|---|---|
| `vuln_enriched.csv` | `data/output/vuln_enriched.csv` | One row per finding, with `cve_id`. Used by Auto-Fix to check CVE presence. |
| `remediation_jobs.csv` | `data/output/remediation_jobs.csv` | One row per grouped job, with `job_fingerprint`. Used by Resurface to match jobs. |

Both files are produced by the enrichment + remediation pipeline:

```
python src/enrichment/build_vuln_enriched.py   →  vuln_enriched.csv
python src/remediation/build_remediation_jobs.py →  remediation_jobs.csv
```

---

## Triggering a Re-scan

### Via the API

```http
POST /api/rescan/run
Authorization: Bearer <token>
Content-Type: application/json

{
  "enriched_csv": "data/output/vuln_enriched.csv",
  "jobs_csv":     "data/output/remediation_jobs.csv",
  "changed_by":   "analyst"
}
```

**Roles allowed:** `analyst`, `remediation_owner`, `admin`

**Response:**

```json
{
  "data": {
    "resurfaced":      3,
    "fixed":           7,
    "scan_timestamp":  "2025-05-29T14:22:01.003Z"
  }
}
```

### Via the Dashboard

The **Upload** page includes a "Run Re-scan" button that fires the same endpoint with
the default CSV paths.

---

## Monitoring Status

### API

```http
GET /api/rescan/status
```

Returns the current count of `RESURFACED` jobs and jobs that moved to `DONE` in the
last 48 hours:

```json
{
  "data": {
    "resurfaced_jobs":     3,
    "recently_fixed_jobs": 7
  }
}
```

### Sidebar Widget

The sidebar polls `GET /api/rescan/status` every **60 seconds** and shows:

| Condition | Display |
|---|---|
| 0 resurfaced jobs | Green dot — "All clear" |
| ≥ 1 resurfaced jobs | Pulsing red dot — "N resurfaced" |
| API unreachable | "Unavailable" |

---

## Job Lifecycle Integration

Re-scan participates in the full 15-state lifecycle machine. The relevant transitions are:

```
DONE      ──(resurface)──→  RESURFACED  ──→  TO_DO or IN_PROGRESS
CLOSED    ──(resurface)──→  RESURFACED  ──→  TO_DO or IN_PROGRESS

TO_DO     ──(auto-fix)───→  DONE        ──→  VERIFIED → CLOSED
IN_PROGRESS ─(auto-fix)──→  DONE        ──→  VERIFIED → CLOSED
```

Both transitions go through `update_job_status`, which:

1. Writes the new status to the `jobs` table.
2. Stamps `fixed_at` (for DONE transitions) or clears it (for RESURFACED).
3. Appends a row to `job_events` with the automatic comment and `changed_by` actor.

Every re-scan action is therefore fully auditable in the job's Events Timeline.

---

## Sequence Diagram

```
Analyst runs new scan
        │
        ▼
build_vuln_enriched.py  ──→  vuln_enriched.csv
build_remediation_jobs.py ─→  remediation_jobs.csv
        │
        ▼
POST /api/rescan/run
        │
        ├─ load_new_scan_cves()          read CVEs from vuln_enriched.csv
        ├─ load_new_job_fingerprints()   read fingerprints from remediation_jobs.csv
        │
        ├─ detect_resurfaced()
        │     query: jobs WHERE status IN (DONE, CLOSED)
        │                   AND fingerprint IN new_fingerprints
        │     → update_job_status(RESURFACED) + job_events row
        │
        └─ detect_newly_fixed()
              query: jobs WHERE status IN (TO_DO, IN_PROGRESS)
              for each: if no CVE overlap with new scan CVEs
              → update_job_status(DONE) + job_events row
```

---

## Edge Cases

| Scenario | Behaviour |
|---|---|
| Enriched CSV missing | Warning logged; resurface/auto-fix skipped for CVE check; resurfaced detection still runs if jobs CSV exists |
| Job has no `cve_list` | Skipped by auto-fix detection (cannot determine absence) |
| Same fingerprint in DB twice | `job_fingerprint` is `UNIQUE` in the schema — duplicates are dropped at job-build time |
| Job already RESURFACED | `update_job_status` writes a no-op event; state machine allows the transition |
| Partial overlap (some CVEs gone, some remain) | Job stays open — all CVEs must be absent for auto-close |
