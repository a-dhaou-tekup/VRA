# Ingestion Pipeline

## Fallback chain order

Every uploaded file passes through the following chain, in strict order:

| Priority | Parser | Trigger |
|----------|--------|---------|
| 1 | **Nessus XML** (`nessus.NessusAdapter`) | Extension `.nessus` **or** `.xml` with `NessusClientData` in first 200 bytes |
| 2 | **OpenVAS XML** (`openvas.OpenVASAdapter`) | Extension `.xml` with `openvas` / `gvm` in first 200 bytes |
| 3 | **CSV Generic** (`csv_generic.CSVGenericAdapter`) | Extension `.csv`, or any file when scanner_type is resolved to `csv_generic` |
| 4 | **LLM Parser** (`llm_parser.LLMParser`) | Fallback — see conditions below |

**LLM parser is invoked when:**
- No structured parser matched the file's extension, **OR**
- A structured parser ran but returned fewer than `LLM_INGEST_TRIGGER_MIN_FINDINGS` findings (default: `1`).

**LLM parser is NOT invoked when:**
- The file bears a recognized scanner signature (`.nessus` extension, or `.xml` with Nessus/OpenVAS root element in the first 200 bytes). This guard is enforced even if the structured parser returns zero findings.

## Known-format detection

`_is_known_scanner_format(file_path)` inspects the file extension and the first 200 bytes:

```
.nessus                              → always known (Nessus XML)
.xml + "NessusClientData" in head    → known (Nessus)
.xml + "openvas" / "gvm" in head     → known (OpenVAS)
everything else                      → not known → LLM fallback eligible
```

## LLM parser details

**File:** `src/ingestion/adapters/llm_parser.py`  
**Prompts:** `src/ingestion/adapters/llm_parser_prompts.py` (edit examples here, no code change needed)

### Extraction schema

```python
class ExtractedFinding(BaseModel):
    cve_id: str | None         # CVE-YYYY-NNNNN if present, else None
    severity: str              # critical/high/medium/low/info
    component: str
    component_version: str | None
    affected_host: str
    port: int | None
    raw_description: str
```

### Chunking

Files larger than `LLM_INGEST_MAX_CHARS` (default `30000`) are split into non-overlapping chunks.
The LLM is called once per chunk. Results are merged and de-duplicated on `(cve_id, component, affected_host)`.

### Validation and retry

Every LLM response is validated against `ExtractedFindings` (Pydantic model).  
On schema failure, one retry is attempted with the validation error appended to the conversation.  
If the retry also fails, the upload status is set to `llm_extraction_failed` and no findings are created.

### Determinism guarantee

The Ollama call sets `options.temperature = 0`.  
Re-uploading the same file against the same model will produce the same `(cve_id, component, host)` tuples.  
This holds as long as the model weights do not change between runs.

## Audit trail

The `findings` table records every finding with its ingest method:

```sql
SELECT ingest_method, COUNT(*) FROM findings GROUP BY ingest_method;
-- structured | N
-- llm        | M
```

Structured-parser findings → `ingest_method = 'structured'`  
LLM-parser findings       → `ingest_method = 'llm'`

The `uploads` table also carries a `parser_used` column and the same value in `stats_json.parser_used`.

## Metric

`GET /api/metrics/ingest-breakdown` returns findings counts per ingest method over the last 30 days:

```json
{
  "ingest_method_breakdown": {
    "structured": 1240,
    "llm": 83
  }
}
```

The same key is included in `GET /api/metrics/overview` under `data.ingest_method_breakdown`.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `LLM_INGEST_TRIGGER_MIN_FINDINGS` | `1` | Invoke LLM when structured parser returns fewer than this many findings |
| `LLM_INGEST_MAX_CHARS` | `30000` | Max characters per LLM chunk; larger files are split |
| `OLLAMA_TIMEOUT_SECONDS` | `300` | Shared with the RAG recommender |

## UI

The Uploads page shows an amber **LLM** badge next to the scanner type for any upload processed by the LLM parser.
The analyst should treat LLM-extracted findings as requiring extra review before acting on them.
