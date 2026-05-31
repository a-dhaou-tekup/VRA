# Chat with Finding

Conversational interface that lets analysts, risk managers, and auditors ask
follow-up questions about a specific remediation job and receive grounded,
source-cited answers from the local LLM.

---

## Data Model

Two new tables in `platform.db` (added by the startup migration):

```sql
conversations (
  id           TEXT PRIMARY KEY,        -- "conv_<12 hex chars>"
  job_id       TEXT NOT NULL REFERENCES jobs(job_id),
  started_by   TEXT NOT NULL,           -- username
  started_at   TEXT NOT NULL,           -- ISO-8601 UTC
  title        TEXT                     -- optional free-text label
)

conversation_turns (
  id                  TEXT PRIMARY KEY, -- "turn_<12 hex chars>"
  conversation_id     TEXT NOT NULL REFERENCES conversations(id),
  role                TEXT NOT NULL CHECK (role IN ('user','assistant','partial')),
  content             TEXT NOT NULL,
  retrieved_docs_json TEXT,             -- JSON array: [{source_class, source_id, snippet}]
  created_at          TEXT NOT NULL
)
```

### `partial` role

When the client navigates away mid-stream, the partial response is written as
`role='partial'`.  On the next session, the partial row is promoted to
`role='assistant'` once streaming completes, or it remains as a recovery
checkpoint.  There is at most one `partial` row per conversation at any time.

---

## Retrieval Strategy

Each user turn triggers a two-stage retrieval using the **multi-collection
hybrid pipeline** (introduced in `feat/rag-multi-collection`):

```
user_message + prev_user_turn (sliding window)
        │
        ▼
multi_collection_search(query, k=50)   ← 3 collections, weighted RRF
        │
        ▼
rerank(query, candidates, top_n=5)     ← cross-encoder ms-marco-MiniLM-L-6-v2
        │
        ▼
5 chunks  →  injected into prompt with [source_class:source_id] tags
```

**Sliding-window query** — the retrieval query is the concatenation of the
new user message and the **previous user turn only** (not the full history).
This keeps the retrieval signal specific to the current topic.  Including the
full history would dilute the BM25 and semantic signals.

**Conversation history in the prompt** — the last 4 turns (user + assistant
alternating) are included in the prompt separately from the retrieved chunks.
This lets the LLM maintain conversational context without polluting retrieval.

---

## Prompt Assembly

```
[System]
You are a security remediation assistant.
Ground every claim in retrieved sources.
Cite inline as [source_class:source_id].
If sources don't contain the answer, say so.
Do not invent facts.

[User]
## Vulnerability Job
Job ID: job-a30565bd
Product: Fortinet
CVEs: CVE-2024-21762
Risk Level: CRITICAL
Status: IN_PROGRESS
KEV Present: True

## Retrieved Advisory Sources
[1][cve_descriptions:CVE-2024-21762] CVE: CVE-2024-21762 …
[2][internal_runbooks:patch-management] INTERNAL RUNBOOK: Patch Management …
…

## Conversation History
User: Does this patch apply to RHEL 9?
Assistant: Yes, according to [cve_descriptions:CVE-2024-21762] …

## Current Question
What about Windows targets?
```

---

## SSE Protocol

**Endpoint:** `POST /api/findings/{job_id}/chat`

**Request body:**
```json
{ "message": "Does this apply to RHEL 9?", "conversation_id": "conv_abc123" }
```
Omit `conversation_id` to start a new conversation.

**Response:** `Content-Type: text/event-stream`

Each SSE event is a single line `data: <json>\n\n`.  Three event types:

| `type`    | Fields                              | Meaning |
|-----------|-------------------------------------|---------|
| `token`   | `content: string`                   | One LLM text chunk — append to display buffer |
| `done`    | `conversation_id`, `turn_id`        | Stream finished; fetch the full transcript |
| `error`   | `detail: string`                    | Fatal error; stream terminates |

**Example stream:**
```
data: {"type":"token","content":"Yes"}

data: {"type":"token","content":", according to"}

data: {"type":"token","content":" [cve_descriptions:CVE-2024-21762]"}

data: {"type":"done","conversation_id":"conv_abc123","turn_id":"turn_xyz456"}
```

The frontend's `streamFindingChat()` helper (in `api/client.js`) handles the
`fetch` + `ReadableStream` parsing and exposes `onToken / onDone / onError`
callbacks.  It returns an `{ abort }` handle so navigating away can cleanly
cancel the stream.

---

## RBAC

| Role | POST /chat | GET conversations | GET transcript |
|---|---|---|---|
| `admin` | ✓ | ✓ | ✓ |
| `analyst` | ✓ | ✓ | ✓ |
| `remediation_owner` | ✓ | ✓ | ✓ |
| `risk_owner` | ✓ | ✓ | ✓ |
| `auditor` | **403** | ✓ | ✓ |

Auditors receive a 403 before the stream opens.  The `ChatPanel` component
renders in read-only mode for auditors (no input box, "READ-ONLY" badge).

---

## Audit Trail

Every user message and assistant reply writes a row to `job_events`:

```
event_type: "chat.user_message"   | changed_by: <username>
event_type: "chat.assistant_reply" | changed_by: "system"
comment: "chat conversation conv_abc123"
```

An auditor can reconstruct who asked what and when by querying `job_events`
filtered by `event_type LIKE 'chat.%'`.

---

## API Reference

```http
POST   /api/findings/{job_id}/chat
GET    /api/findings/{job_id}/conversations
GET    /api/conversations/{conversation_id}
```

---

## Frontend

The `ChatPanel` component (`frontend/src/components/ChatPanel.jsx`) is mounted
in `JobDetail.jsx` between the AI Recommendation card and the Events Timeline.

Features:
- **Collapsible history list** — lists all conversations for this job with
  turn counts and timestamps.
- **New conversation** button — clears the active thread.
- **Streaming display** — tokens appear in real time with an animated cursor.
- **Citation chips** — `[source_class:source_id]` tags in the assistant text
  are replaced with clickable chips.  Clicking a chip opens a tooltip with the
  source name and a 200-character snippet.
- **Auditor mode** — read-only, no input box.
- **Navigate-away safety** — `controller.abort()` is called on unmount;
  the backend writes a `partial` row so the response is not lost.
