"""LLM fallback parser — invoked when no structured parser matches or the structured
parser returns fewer than LLM_INGEST_TRIGGER_MIN_FINDINGS findings (default: 1).

Calls Ollama with temperature=0 for deterministic, idempotent extraction.
Re-uploading the same file will produce the same findings set given the same model.
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from pathlib import Path
from typing import Optional

import pandas as pd
import requests
import yaml
from pydantic import BaseModel, field_validator

from .base import ScannerAdapter
from .llm_parser_prompts import FEW_SHOT_EXAMPLES, SYSTEM_PROMPT

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "policy.yaml"

# ── Configurable thresholds (env-overridable) ─────────────────────────────────

LLM_INGEST_MAX_CHARS: int = int(os.getenv("LLM_INGEST_MAX_CHARS", "30000"))

# ── Custom exception ──────────────────────────────────────────────────────────


class LLMExtractionError(ValueError):
    """Raised when the LLM parser fails validation on both the initial and retry attempt."""


# ── Pydantic extraction schema ────────────────────────────────────────────────


class ExtractedFinding(BaseModel):
    cve_id: Optional[str] = None
    severity: str = "info"
    component: str = "unknown"
    component_version: Optional[str] = None
    affected_host: str = "unknown"
    port: Optional[int] = None
    raw_description: str = ""

    @field_validator("cve_id", mode="before")
    @classmethod
    def _clean_cve(cls, v) -> Optional[str]:
        if not v:
            return None
        s = str(v).strip().upper()
        return s if re.match(r"^CVE-\d{4}-\d{4,}$", s) else None

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_severity(cls, v) -> str:
        _map = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "informational": "info",
            "none": "info", "unknown": "info",
        }
        return _map.get(str(v).lower().strip(), "medium")

    @field_validator("component", mode="before")
    @classmethod
    def _norm_component(cls, v) -> str:
        return str(v).strip() if v else "unknown"

    @field_validator("affected_host", mode="before")
    @classmethod
    def _norm_host(cls, v) -> str:
        return str(v).strip() if v else "unknown"

    @field_validator("port", mode="before")
    @classmethod
    def _norm_port(cls, v) -> Optional[int]:
        if v is None:
            return None
        try:
            p = int(str(v))
            return p if 1 <= p <= 65535 else None
        except (ValueError, TypeError):
            return None

    @field_validator("component_version", mode="before")
    @classmethod
    def _norm_version(cls, v) -> Optional[str]:
        return str(v).strip() if v else None


class ExtractedFindings(BaseModel):
    findings: list[ExtractedFinding] = []


# ── Config helper ─────────────────────────────────────────────────────────────


def _load_rag_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        return cfg.get("rag", {})
    except Exception:
        return {}


# ── Ollama call (temperature=0 for determinism) ───────────────────────────────


def _call_ollama_extract(messages: list[dict], config: dict) -> str:
    """POST a chat request to Ollama and return the raw response text."""
    url = f"{config.get('ollama_url', 'http://localhost:11434')}/api/chat"
    timeout_sec = int(
        config.get("ollama_timeout")
        or os.getenv("OLLAMA_TIMEOUT_SECONDS", "300")
    )
    payload = {
        "model": config.get("model", "qwen2.5:14b"),
        "format": "json",
        "stream": False,
        "options": {"temperature": 0},
        "messages": messages,
    }
    resp = requests.post(url, json=payload, timeout=timeout_sec)
    resp.raise_for_status()
    data = resp.json()
    return data.get("message", {}).get("content", "")


# ── Text chunking ─────────────────────────────────────────────────────────────


def _chunk_text(text: str, max_chars: int) -> list[str]:
    """Split text into non-overlapping chunks of at most max_chars characters."""
    if len(text) <= max_chars:
        return [text]
    return [text[i: i + max_chars] for i in range(0, len(text), max_chars)]


# ── Single-chunk extraction with one retry ────────────────────────────────────


def _extract_chunk(chunk_text: str, config: dict) -> list[ExtractedFinding]:
    """Extract findings from one text chunk.  Retries once on schema-validation failure."""
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        *FEW_SHOT_EXAMPLES,
        {"role": "user", "content": f"Extract vulnerability findings from this text:\n\n{chunk_text}"},
    ]

    raw = _call_ollama_extract(messages, config)

    try:
        return ExtractedFindings.model_validate_json(raw).findings
    except Exception as first_err:
        logger.warning("LLMParser: validation failed on first attempt — %s", first_err)
        retry_messages = messages + [
            {"role": "assistant", "content": raw},
            {
                "role": "user",
                "content": (
                    f"Your previous output failed validation with: {first_err}. "
                    "Return only valid JSON conforming to the schema."
                ),
            },
        ]
        raw2 = _call_ollama_extract(retry_messages, config)
        try:
            return ExtractedFindings.model_validate_json(raw2).findings
        except Exception as second_err:
            raise LLMExtractionError(
                f"LLM extraction failed after retry. "
                f"Error: {second_err}. "
                f"Last response (truncated): {raw2[:300]}"
            ) from second_err


# ── Deduplication ─────────────────────────────────────────────────────────────


def _dedup_findings(findings: list[ExtractedFinding]) -> list[ExtractedFinding]:
    """Remove duplicates keyed on (cve_id, component, affected_host)."""
    seen: set[tuple] = set()
    result: list[ExtractedFinding] = []
    for f in findings:
        key = (f.cve_id, f.component.lower(), f.affected_host.lower())
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


# ── DataFrame conversion ──────────────────────────────────────────────────────

_SEVERITY_TO_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _findings_to_df(findings: list[ExtractedFinding]) -> pd.DataFrame:
    """Convert a list of ExtractedFinding to the normalised DataFrame format."""
    if not findings:
        return pd.DataFrame(columns=[
            "asset_id", "hostname", "ip_address", "cve_id", "cvss_base_score",
            "severity", "plugin_id", "plugin_name", "plugin_family", "vuln_title",
            "first_seen", "last_seen", "scanner_source", "component",
            "component_version", "port", "raw_description",
        ])

    rows = []
    for f in findings:
        host = f.affected_host
        is_ip = bool(_IP_RE.match(host))
        hostname = "" if is_ip else host
        ip_address = host if is_ip else ""

        severity_upper = f.severity.upper()
        cvss = _SEVERITY_TO_CVSS.get(f.severity, 5.0)

        rows.append({
            "asset_id":          f"asset-{uuid.uuid5(uuid.NAMESPACE_DNS, host)}",
            "hostname":          hostname or host,
            "ip_address":        ip_address or host,
            "cve_id":            f.cve_id or "",
            "cvss_base_score":   cvss,
            "severity":          severity_upper,
            "plugin_id":         "",
            "plugin_name":       (f.raw_description[:100] if f.raw_description else ""),
            "plugin_family":     "LLM-Extracted",
            "vuln_title":        f"{f.component} — {severity_upper}",
            "first_seen":        "",
            "last_seen":         "",
            "scanner_source":    "llm",
            "component":         f.component,
            "component_version": f.component_version or "",
            "port":              str(f.port) if f.port is not None else "",
            "raw_description":   f.raw_description,
        })

    return pd.DataFrame(rows)


# ── Public parser class ───────────────────────────────────────────────────────


class LLMParser(ScannerAdapter):
    """Fallback parser that uses Ollama (qwen2.5:14b) to extract findings from
    arbitrary text.  Temperature is fixed at 0 to ensure idempotent extraction.
    """

    name = "llm"

    def parse(
        self,
        file_path: Path,
        asset_inventory: Optional[pd.DataFrame] = None,
    ) -> pd.DataFrame:
        logger.info("LLMParser: extracting findings from '%s'", file_path.name)

        config = _load_rag_config()

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise ValueError(f"LLMParser: cannot read '{file_path.name}' as text — {exc}") from exc

        chunks = _chunk_text(text, LLM_INGEST_MAX_CHARS)
        logger.info(
            "LLMParser: %d chunk(s) for '%s' (%d chars total)",
            len(chunks), file_path.name, len(text),
        )

        all_findings: list[ExtractedFinding] = []
        for i, chunk in enumerate(chunks, start=1):
            logger.info("LLMParser: chunk %d/%d", i, len(chunks))
            chunk_findings = _extract_chunk(chunk, config)  # raises LLMExtractionError on double-fail
            all_findings.extend(chunk_findings)

        deduped = _dedup_findings(all_findings)
        logger.info(
            "LLMParser: %d raw → %d deduped findings from '%s'",
            len(all_findings), len(deduped), file_path.name,
        )

        return _findings_to_df(deduped)
