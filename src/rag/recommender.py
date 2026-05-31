"""RAG Recommender.

Retrieves advisory context from ChromaDB and asks Ollama/Qwen2.5-14B
to generate a structured JSON remediation recommendation.
"""

import json
import logging
import time
from pathlib import Path

import requests
import yaml

from rag.retriever import retrieve_for_job
# Hybrid imports are intentionally deferred inside generate_recommendation
# so neither the cross-encoder nor the FTS5 DB open at module-import time.

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policy.yaml"

# Guaranteed keys in every returned recommendation
_EMPTY_RECOMMENDATION: dict = {
    "summary": "",
    "exploitation_likelihood": "medium",
    "remediation_steps": [],
    "compensating_controls": [],
    "verification": "",
    "references": [],
    "confidence": 0.0,
}


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg["rag"]


def estimate_tokens(text: str) -> int:
    """Rough token count: word count × 1.33."""
    return int(len(text.split()) * 1.33)


def build_prompt(job: dict, chunks: list[dict]) -> tuple[str, str]:
    """Construct the system prompt and user message for the LLM.

    Returns (system_prompt, user_message).
    """
    system_prompt = (
        "You are a senior cybersecurity engineer specializing in vulnerability remediation.\n"
        "You provide specific, actionable, technically accurate remediation guidance.\n"
        "You MUST respond with valid JSON only. Do not include markdown fences.\n"
        "Never invent CVE IDs, CVSS scores, or patch versions — only use information from the context provided.\n"
        'If information is insufficient, set "confidence" to a low value and note this in "summary".'
    )

    # Normalise cve_list to a Python list
    cve_list = job.get("cve_list", "[]")
    if isinstance(cve_list, str):
        try:
            cves = json.loads(cve_list)
        except (json.JSONDecodeError, ValueError):
            cves = [cve_list] if cve_list else []
    else:
        cves = list(cve_list) if isinstance(cve_list, (list, tuple)) else []

    meta_lines = [
        f"Job ID: {job.get('job_id', 'N/A')}",
        f"Product: {job.get('main_product', 'N/A')}",
        f"CVEs: {', '.join(str(c) for c in cves) or 'N/A'}",
        f"Max Risk Level: {job.get('max_risk_level', 'N/A')}",
        f"KEV Present: {job.get('kev_present', False)}",
        f"Risk Score Max: {job.get('risk_score_max', 'N/A')}",
        f"Business Unit: {job.get('business_unit', 'N/A')}",
        f"Affected Assets: {job.get('affected_asset_count', 'N/A')}",
    ]

    context_lines = [f"[{i}] {chunk['text']}" for i, chunk in enumerate(chunks, start=1)]

    schema_example = json.dumps(
        {
            "summary": "string — 2-3 sentence plain-language summary",
            "exploitation_likelihood": "high|medium|low",
            "remediation_steps": ["string", "..."],
            "compensating_controls": ["string", "..."],
            "verification": "string — how to confirm the fix was applied",
            "references": ["CVE-XXXX-XXXXX", "vendor URL", "..."],
            "confidence": 0.0,
        },
        indent=2,
    )

    user_message = (
        "## Vulnerability Job Metadata\n"
        + "\n".join(meta_lines)
        + "\n\n## Retrieved Advisory Context\n"
        + (
            "\n\n".join(context_lines)
            if context_lines
            else "(No advisory context retrieved)"
        )
        + "\n\n## Required JSON Output Schema\n"
        + schema_example
        + "\n\nRespond with valid JSON only. Match the schema exactly."
    )

    return system_prompt, user_message


def call_ollama(
    system_prompt: str,
    user_message: str,
    config: dict,
) -> tuple[str, int, int, int]:
    """POST a chat request to Ollama and return (response_text, prompt_tokens, response_tokens, latency_ms).

    On timeout or connection error returns an error-stub JSON and zero token counts.
    """
    url = f"{config['ollama_url']}/api/chat"
    payload = {
        "model": config["model"],
        "format": "json",
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    }

    import os
    timeout_sec = int(
        config.get("ollama_timeout")
        or os.getenv("OLLAMA_TIMEOUT_SECONDS", "300")
    )

    start = time.monotonic()
    try:
        resp = requests.post(url, json=payload, timeout=timeout_sec)
        resp.raise_for_status()
        data = resp.json()
        latency_ms = int((time.monotonic() - start) * 1000)

        message = data.get("message", {})
        response_text = message.get("content", "")
        prompt_tokens = data.get("prompt_eval_count", 0)
        response_tokens = data.get("eval_count", 0)
        return response_text, prompt_tokens, response_tokens, latency_ms

    except requests.exceptions.Timeout:
        latency_ms = int((time.monotonic() - start) * 1000)
        logger.error("Ollama request timed out after %d ms", latency_ms)
        stub = json.dumps(
            {
                **_EMPTY_RECOMMENDATION,
                "summary": "Request to Ollama timed out. Please retry.",
                "confidence": 0.0,
            }
        )
        return stub, 0, 0, latency_ms

    except requests.exceptions.ConnectionError as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        logger.error("Ollama connection error: %s", exc)
        stub = json.dumps(
            {
                **_EMPTY_RECOMMENDATION,
                "summary": (
                    f"Could not connect to Ollama at {config['ollama_url']}. "
                    "Ensure Ollama is running."
                ),
                "confidence": 0.0,
            }
        )
        return stub, 0, 0, latency_ms


def generate_recommendation(job: dict) -> dict:
    """Full RAG pipeline: retrieve → build prompt → call LLM → parse JSON.

    Returns the recommendation dict with all schema fields guaranteed present,
    plus a ``_meta`` key containing model/token/latency metadata.
    """
    config = _load_config()
    use_hybrid: bool = config.get("RAG_USE_HYBRID", True)

    if use_hybrid:
        # ── Hybrid path: vector + BM25 → RRF → cross-encoder re-rank ─────────
        from rag.hybrid_search import hybrid_search
        from rag.reranker import rerank

        # Build a query that gives BM25 exact-match signals (CVE IDs) AND
        # semantic signals (product + risk level).
        cve_raw = job.get("cve_list", "[]")
        if isinstance(cve_raw, str):
            try:
                cves = json.loads(cve_raw)
            except (json.JSONDecodeError, ValueError):
                cves = [cve_raw] if cve_raw else []
        else:
            cves = list(cve_raw) if isinstance(cve_raw, (list, tuple)) else []

        query_parts: list[str] = []
        query_parts.extend(str(c) for c in cves[:4])       # CVE IDs for BM25
        if job.get("main_product"):
            query_parts.append(job["main_product"])
        if job.get("plugin_family"):
            query_parts.append(job["plugin_family"])
        if job.get("max_risk_level"):
            query_parts.append(f"{job['max_risk_level']} vulnerability remediation")
        hybrid_query = " ".join(query_parts) or "vulnerability remediation advisory"

        logger.info(
            "finding.advise [hybrid] query=%.80s  job=%s",
            hybrid_query, job.get("job_id", "?"),
        )

        candidates = hybrid_search(hybrid_query, k=50)
        reranked   = rerank(hybrid_query, candidates, top_n=5)

        # Convert RetrievedDoc → the plain-dict shape the rest of the pipeline expects
        chunks = [
            {"text": d["text"], "metadata": d["metadata"], "distance": d.get("distance", 0.0)}
            for d in reranked
        ]
        logger.info(
            "finding.advise [hybrid] candidates=%d → reranked=%d",
            len(candidates), len(chunks),
        )
    else:
        # ── Legacy path: two-pass ChromaDB (CVE direct + semantic) ───────────
        logger.info(
            "finding.advise [legacy] RAG_USE_HYBRID=False  job=%s",
            job.get("job_id", "?"),
        )
        chunks = retrieve_for_job(job)

    # Truncate to top 3 if combined context would exceed the token threshold
    combined_text = " ".join(c["text"] for c in chunks)
    if estimate_tokens(combined_text) > config.get("max_tokens_before_truncation", 6000):
        logger.info(
            "Token estimate (%d) exceeds threshold; truncating to top 3 chunks",
            estimate_tokens(combined_text),
        )
        chunks = chunks[:3]

    system_prompt, user_message = build_prompt(job, chunks)
    response_text, prompt_tokens, response_tokens, latency_ms = call_ollama(
        system_prompt, user_message, config
    )

    try:
        recommendation: dict = json.loads(response_text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse Ollama JSON response; wrapping raw text")
        recommendation = {
            **_EMPTY_RECOMMENDATION,
            "summary": (
                response_text[:500]
                if response_text
                else "No response received from model."
            ),
            "confidence": 0.0,
        }

    # Guarantee every schema key is present
    for key, default in _EMPTY_RECOMMENDATION.items():
        recommendation.setdefault(key, default)

    recommendation["_meta"] = {
        "model": config["model"],
        "prompt_tokens": prompt_tokens,
        "response_tokens": response_tokens,
        "latency_ms": latency_ms,
        "chunks_used": len(chunks),
    }

    return recommendation
