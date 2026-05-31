# VRA Agents

## Auto-triage agent  (`finding.triage`)

### Purpose

For every vulnerability finding that enters the platform the triage agent produces a **tentative classification** so high-confidence exploitable findings surface at the top of the analyst's queue. The analyst always makes the final decision; the agent only re-orders and annotates.

### Safety constraint

> **The agent MUST NOT transition the state of any finding, job, or other workflow entity.**

This constraint is enforced in two places:

1. **Code** — `src/api/services/triage_agent.py` writes exclusively to `auto_triage` and `finding_events`. It never calls any state-machine function.
2. **Prompt** — the system prompt sent to the LLM at every call contains the exact sentence:  
   *"You are advising a human analyst who will make the final decision. You do not have authority to mark a finding as a false positive or to dismiss it. Your job is to estimate likelihood."*

### Prompt template

```
System:
  You are advising a human analyst who will make the final decision.
  You do not have authority to mark a finding as a false positive or to dismiss it.
  Your job is to estimate likelihood.

  Classify the finding and respond with ONLY a valid JSON object with exactly
  three keys:
    "triage_class":  one of "likely_false_positive", "likely_valid",
                     "needs_investigation"
    "confidence":    float [0.0, 1.0]
    "justification": single sentence, max 200 characters

  Do not include markdown fences or any text outside the JSON.

User:
  Finding to classify:
    CVE ID:      <cve_id>
    Severity:    <CRITICAL|HIGH|MEDIUM|LOW|INFO>
    EPSS score:  <0.0000>
    KEV listed:  Yes/No [— short description if KEV]
    Component:   <component>
    Host:        <hostname>
    Criticality: <asset criticality>
    Environment: <asset environment>
    Exposed:     Yes/No

  Advisory context:
  [source_class:source_id] <text excerpt>
  ...

  Return JSON only.
```

**Temperature is fixed at 0** for all extraction calls to ensure deterministic, idempotent output.

### Classification classes

| Class | UI colour | Meaning |
|-------|-----------|---------|
| `likely_valid` | Red | High likelihood this is a real exploitable finding |
| `needs_investigation` | Blue | Ambiguous — analyst should review manually |
| `likely_false_positive` | Grey | Low likelihood of real impact |

### Validation and retry

Every LLM response is validated against the `TriageResult` Pydantic model. On failure:
1. One retry is attempted with the validation error appended to the conversation.
2. If the retry also fails, the agent falls back to `triage_class='needs_investigation'`, `confidence=0.0`, with the validation error as justification.

No exception is raised — the agent always produces a usable result.

### Idempotency

The `auto_triage` table holds **one row per finding** (`finding_id TEXT PRIMARY KEY`). Every run uses `INSERT OR REPLACE`, so the latest result always wins. Re-running POST `/findings/{id}/auto-triage` is safe and expected.

### State guard

The agent will skip (and return the existing result) if `findings.state` is not `NEW` or `TRIAGED` **unless** `force=true` is passed. This prevents overwriting a result after an analyst has explicitly acted on a finding.

### RAG context

Context retrieval uses the multi-collection hybrid search (`multi_collection_search(query, k=10)`) followed by a cross-encoder re-rank (`rerank(query, candidates, top_n=3)`). Three chunks maximum are included in the prompt to avoid context overflow.

If the RAG stack is unavailable (ChromaDB not initialised, sentence-transformers not installed), the agent falls back gracefully to classification without advisory context.

### Audit trail

Every triage run writes a row to `finding_events`:

```sql
SELECT * FROM finding_events
WHERE event_type = 'finding.triage'
ORDER BY created_at DESC LIMIT 5;
```

Fields: `finding_id`, `event_type='finding.triage'`, `actor` (username or 'system'), `detail` (JSON with triage_class, confidence, model, latency_ms), `created_at`.

### API

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| `GET` | `/api/findings` | any authenticated | List findings with AI suggestion (LEFT JOIN) |
| `POST` | `/api/findings/{id}/auto-triage` | analyst, admin | Run or re-run triage |
| `GET` | `/api/findings/{id}/auto-triage` | any authenticated | Get current suggestion |

Query params for POST: `force=true` overrides the state guard.

### Auto-trigger after enrichment

Set `ENABLE_AUTO_TRIAGE=true` in `.env` to automatically trigger background triage for every new finding after the upload pipeline completes. Default is off to avoid unexpected LLM usage on large scan files.

### Schema

```sql
CREATE TABLE auto_triage (
    finding_id     TEXT PRIMARY KEY REFERENCES findings(id),
    triage_class   TEXT NOT NULL CHECK (triage_class IN (
                       'likely_false_positive',
                       'likely_valid',
                       'needs_investigation')),
    confidence     REAL NOT NULL,
    justification  TEXT NOT NULL,
    model_version  TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE finding_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT 'system',
    detail      TEXT,
    created_at  TEXT NOT NULL
);
```
