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

    start = time.monotonic()
    try:
        resp = requests.post(url, json=payload, timeout=300)
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
