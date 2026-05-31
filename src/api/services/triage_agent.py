"""
Auto-triage agent for individual findings.

═══════════════════════════════════════════════════════════════════════════════
SAFETY CONSTRAINT — READ BEFORE MODIFYING
───────────────────────────────────────────────────────────────────────────────
This agent MUST NOT transition the state of any finding, job, or other
workflow entity. It writes ONLY to the `auto_triage` and `finding_events`
tables. The state machine (findings.state, jobs.status) is the analyst's
exclusive domain.

The LLM prompt also enforces this boundary at inference time by explicitly
telling the model it has no authority to dismiss or accept findings.
═══════════════════════════════════════════════════════════════════════════════

Registered job kind:  finding.triage
Trigger:              POST /findings/{id}/auto-triage
                      Automatically after finding.enrich when ENABLE_AUTO_TRIAGE=true
Re-run guard:         skips if findings.state NOT IN ('NEW','TRIAGED')
                      unless force=True
Idempotency:          INSERT OR REPLACE into auto_triage → one row per finding,
                      latest result always wins
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import yaml
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

ROOT           = Path(__file__).parent.parent.parent.parent
ENRICHMENT_DB  = ROOT / "data" / "cache" / "enrichment.db"
_CONFIG_PATH   = ROOT / "config" / "policy.yaml"

# States in which the agent may (re-)run without force=True
_AUTO_STATES = {"NEW", "TRIAGED"}


# ── Pydantic response schema ─────────────────────────────────────────────────

class TriageResult(BaseModel):
    triage_class:  str
    confidence:    float
    justification: str

    @field_validator("triage_class", mode="before")
    @classmethod
    def _valid_class(cls, v: str) -> str:
        valid = {"likely_false_positive", "likely_valid", "needs_investigation"}
        v = str(v).lower().strip()
        if v not in valid:
            raise ValueError(f"triage_class must be one of {valid}, got {v!r}")
        return v

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_conf(cls, v) -> float:
        return max(0.0, min(1.0, float(v)))

    @field_validator("justification", mode="before")
    @classmethod
    def _trim_justification(cls, v: str) -> str:
        return str(v).strip()[:200]


# ── Config ───────────────────────────────────────────────────────────────────

def _load_rag_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh).get("rag", {})
    except Exception:
        return {}


# ── Enrichment cache lookup ───────────────────────────────────────────────────

def _lookup_enrichment(cve_id: str) -> dict:
    """Return EPSS score and KEV data for a CVE from the local enrichment cache."""
    if not cve_id or not ENRICHMENT_DB.exists():
        return {"epss_score": 0.0, "kev_flag": 0}
    try:
        conn = sqlite3.connect(str(ENRICHMENT_DB), timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT epss_score, kev_flag, kev_short_description, kev_required_action "
            "FROM cve_context WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        conn.close()
        if row:
            return {
                "epss_score":          float(row["epss_score"] or 0.0),
                "kev_flag":            int(row["kev_flag"] or 0),
                "kev_description":     row["kev_short_description"] or "",
                "kev_required_action": row["kev_required_action"] or "",
            }
    except Exception as exc:
        logger.warning("triage_agent: enrichment lookup failed — %s", exc)
    return {"epss_score": 0.0, "kev_flag": 0}


# ── Asset lookup ──────────────────────────────────────────────────────────────

def _lookup_asset(hostname: str, conn: sqlite3.Connection) -> dict:
    """Return asset metadata from the platform DB."""
    if not hostname:
        return {}
    try:
        row = conn.execute(
            "SELECT criticality, environment, internet_exposed, business_unit "
            "FROM assets WHERE hostname = ? OR asset_id = ? LIMIT 1",
            (hostname, hostname),
        ).fetchone()
        if row:
            return {
                "criticality":      row["criticality"] or "unknown",
                "environment":      row["environment"] or "unknown",
                "internet_exposed": bool(row["internet_exposed"]),
                "business_unit":    row["business_unit"] or "",
            }
    except Exception as exc:
        logger.warning("triage_agent: asset lookup failed — %s", exc)
    return {"criticality": "unknown", "environment": "unknown", "internet_exposed": False}


# ── RAG context retrieval ────────────────────────────────────────────────────

def _retrieve_context(cve_id: str, component: str, severity: str) -> list[dict]:
    """Retrieve top-3 advisory chunks for this finding via multi-collection RAG."""
    try:
        from rag.multi_collection import multi_collection_search
        from rag.reranker import rerank

        query_parts = []
        if cve_id:
            query_parts.append(cve_id)
        if component:
            query_parts.append(component)
        if severity:
            query_parts.append(f"{severity} vulnerability")
        query = " ".join(query_parts) or "vulnerability advisory"

        candidates = multi_collection_search(query, k=10)
        top = rerank(query, candidates, top_n=3)
        return [{"text": d["text"], "source": d.get("source_class", ""), "id": d.get("source_id", "")}
                for d in top]
    except Exception as exc:
        logger.warning("triage_agent: RAG retrieval failed (continuing without context) — %s", exc)
        return []


# ── Prompt builder ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are advising a human analyst who will make the final decision. \
You do not have authority to mark a finding as a false positive or to dismiss it. \
Your job is to estimate likelihood.

Classify the finding and respond with ONLY a valid JSON object with exactly three keys:
  "triage_class":  one of "likely_false_positive", "likely_valid", "needs_investigation"
  "confidence":    a float between 0.0 and 1.0
  "justification": a single sentence (max 200 characters) explaining your classification

Do not include markdown fences, explanation, or any text outside the JSON object."""


def _build_prompt(finding: dict, enrichment: dict, asset: dict, chunks: list[dict]) -> str:
    kev_line = "Yes" if enrichment.get("kev_flag") else "No"
    if enrichment.get("kev_description"):
        kev_line += f" — {enrichment['kev_description'][:120]}"

    context_block = ""
    for i, c in enumerate(chunks, start=1):
        src = f"[{c.get('source', '')}:{c.get('id', '')}]" if c.get("source") else f"[{i}]"
        context_block += f"\n{src} {c['text'][:400]}"

    return (
        f"Finding to classify:\n"
        f"  CVE ID:     {finding.get('cve_id') or 'N/A'}\n"
        f"  Severity:   {finding.get('severity', 'N/A')}\n"
        f"  EPSS score: {enrichment.get('epss_score', 0.0):.4f}\n"
        f"  KEV listed: {kev_line}\n"
        f"  Component:  {finding.get('component') or 'N/A'}\n"
        f"  Host:       {finding.get('hostname') or 'N/A'}\n"
        f"  Criticality:{asset.get('criticality', 'unknown')}\n"
        f"  Environment:{asset.get('environment', 'unknown')}\n"
        f"  Exposed:    {'Yes' if asset.get('internet_exposed') else 'No'}\n"
        + (f"\nAdvisory context:{context_block}" if context_block else "\n(No advisory context retrieved)")
        + "\n\nReturn JSON only."
    )


# ── Ollama call ───────────────────────────────────────────────────────────────

def _call_ollama(system: str, user: str, config: dict) -> str:
    url = f"{config.get('ollama_url', 'http://localhost:11434')}/api/chat"
    timeout = int(config.get("ollama_timeout") or os.getenv("OLLAMA_TIMEOUT_SECONDS", "300"))
    payload = {
        "model": config.get("model", "qwen2.5:14b"),
        "format": "json",
        "stream": False,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("message", {}).get("content", "")


# ── Validation + retry ───────────────────────────────────────────────────────

def _validate_response(raw: str, retry_context: str = "") -> TriageResult:
    """Parse LLM output against TriageResult. Raises on failure."""
    return TriageResult.model_validate_json(raw)


def _call_with_retry(system: str, user: str, config: dict) -> TriageResult:
    """Call the LLM, validate, and retry once on failure.

    On double failure sets triage_class='needs_investigation', confidence=0.0.
    """
    raw = _call_ollama(system, user, config)
    try:
        return _validate_response(raw)
    except Exception as first_err:
        logger.warning("triage_agent: validation failed — %s — retrying", first_err)
        retry_user = (
            user
            + f"\n\nYour previous output failed validation with: {first_err}. "
            "Return only valid JSON conforming to the schema."
        )
        raw2 = _call_ollama(system, retry_user, config)
        try:
            return _validate_response(raw2)
        except Exception as second_err:
            logger.error("triage_agent: retry also failed — %s", second_err)
            return TriageResult(
                triage_class="needs_investigation",
                confidence=0.0,
                justification=f"Validation error: {str(second_err)[:160]}",
            )


# ── Audit writer ──────────────────────────────────────────────────────────────

def _write_finding_event(
    conn: sqlite3.Connection,
    finding_id: str,
    event_type: str,
    actor: str,
    detail: Optional[str] = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO finding_events (finding_id, event_type, actor, detail, created_at)
           VALUES (?,?,?,?,?)""",
        (finding_id, event_type, actor, detail, now),
    )


# ── Public entry point ────────────────────────────────────────────────────────

def run_auto_triage(
    finding_id: str,
    conn: sqlite3.Connection,
    *,
    force: bool = False,
    actor: str = "system",
) -> dict:
    """Run the auto-triage agent for one finding.

    Parameters
    ----------
    finding_id : str
        Primary key of the `findings` row.
    conn : sqlite3.Connection
        Open connection to platform.db (caller owns it).
    force : bool
        If True, overwrite even if finding.state is not NEW/TRIAGED.
    actor : str
        Who triggered the run (stored in finding_events).

    Returns
    -------
    dict  with keys: finding_id, triage_class, confidence, justification,
                     model_version, created_at, skipped (bool)
    """
    # ── Fetch finding ─────────────────────────────────────────────────────────
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"Finding '{finding_id}' not found.")

    finding = dict(row)
    state   = finding.get("state", "NEW")

    # ── State guard ───────────────────────────────────────────────────────────
    if not force and state not in _AUTO_STATES:
        logger.info(
            "triage_agent: skipping finding %s (state=%s, force=False)", finding_id, state
        )
        existing = conn.execute(
            "SELECT * FROM auto_triage WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if existing:
            result = dict(existing)
            result["skipped"] = True
            return result
        return {"finding_id": finding_id, "skipped": True, "reason": f"state={state}"}

    config   = _load_rag_config()
    model_v  = config.get("model", "qwen2.5:14b")

    # ── Gather context ────────────────────────────────────────────────────────
    cve_id    = finding.get("cve_id", "")
    component = finding.get("component", "")
    severity  = finding.get("severity", "")
    hostname  = finding.get("hostname", "")

    enrichment = _lookup_enrichment(cve_id)
    asset      = _lookup_asset(hostname, conn)
    chunks     = _retrieve_context(cve_id, component, severity)

    logger.info(
        "triage_agent: running for finding=%s  cve=%s  epss=%.4f  kev=%s  chunks=%d",
        finding_id, cve_id, enrichment.get("epss_score", 0.0),
        bool(enrichment.get("kev_flag")), len(chunks),
    )

    # ── LLM call ──────────────────────────────────────────────────────────────
    user_msg = _build_prompt(finding, enrichment, asset, chunks)
    t_start  = time.monotonic()
    result   = _call_with_retry(_SYSTEM_PROMPT, user_msg, config)
    latency  = int((time.monotonic() - t_start) * 1000)

    now = datetime.now(timezone.utc).isoformat()

    # ── Persist (UPSERT — latest wins) ────────────────────────────────────────
    conn.execute(
        """INSERT OR REPLACE INTO auto_triage
               (finding_id, triage_class, confidence, justification, model_version, created_at)
           VALUES (?,?,?,?,?,?)""",
        (
            finding_id,
            result.triage_class,
            result.confidence,
            result.justification,
            model_v,
            now,
        ),
    )

    # ── Audit event ───────────────────────────────────────────────────────────
    _write_finding_event(
        conn,
        finding_id,
        event_type="finding.triage",
        actor=actor,
        detail=json.dumps({
            "triage_class": result.triage_class,
            "confidence":   result.confidence,
            "model":        model_v,
            "latency_ms":   latency,
        }),
    )
    conn.commit()

    logger.info(
        "triage_agent: finding=%s → %s (conf=%.2f) in %d ms",
        finding_id, result.triage_class, result.confidence, latency,
    )

    return {
        "finding_id":   finding_id,
        "triage_class": result.triage_class,
        "confidence":   result.confidence,
        "justification": result.justification,
        "model_version": model_v,
        "created_at":   now,
        "skipped":      False,
    }
