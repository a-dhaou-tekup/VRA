"""VRA Agent Orchestrator.

Two-mode agentic loop:
  1. Native  — Ollama /api/chat with ``tools`` param (qwen2.5:14b supports this).
               Tool calls are parsed from ``message.tool_calls``, executed, and
               results fed back as ``role: "tool"`` messages.
  2. ReAct   — Constrained JSON loop using ``format: "json"`` when Ollama is
               unavailable or returns a non-tool-call response on the first turn.
               The model outputs {"tool","args"} or {"answer":"..."} each step.

Both modes are bounded to MAX_ITERATIONS = 5.
All tool calls go through agent.registry, which enforces read-only access and
validates the caller role before delegation.

Return shape:
    {
        "answer":       str,
        "tools_called": [{"name": str, "args": dict, "ok": bool}],
        "contexts":     [RAG chunk dicts from search_knowledge],
        "iterations":   int,
        "mode":         "native" | "react",
        "model":        str,
    }
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import requests
import yaml

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 5
_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policy.yaml"


# ── Config ────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    with open(_CONFIG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)["rag"]


# ── Low-level Ollama call ─────────────────────────────────────────────────────

def _ollama_chat(
    messages:  list[dict],
    config:    dict,
    tools:     Optional[list[dict]] = None,
    json_mode: bool = False,
) -> dict:
    """POST to Ollama /api/chat and return the parsed response dict.

    Raises requests.exceptions.* on network failure so callers can fall back.
    """
    url     = f"{config['ollama_url']}/api/chat"
    timeout = int(config.get("ollama_timeout") or 300)

    payload: dict = {
        "model":  config["model"],
        "stream": False,
        "messages": messages,
    }
    if tools:
        payload["tools"] = tools
    if json_mode:
        payload["format"] = "json"

    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ── Tool helpers ──────────────────────────────────────────────────────────────

def _build_tool_specs() -> list[dict]:
    """Convert TOOL_REGISTRY entries into Ollama-compatible tool specs."""
    from agent.registry import list_tools
    specs = []
    for t in list_tools():
        specs.append({
            "type": "function",
            "function": {
                "name":        t["name"],
                "description": t["description"],
                "parameters":  t["input_schema"],
            },
        })
    return specs


def _execute_tool(
    name: str,
    args: dict,
    role: str,
    tools_called: list[dict],
    contexts: list[dict],
) -> dict:
    """Run a named tool, record the call, collect RAG contexts, return result."""
    from agent.registry import get_tool
    entry = get_tool(name)
    if entry is None:
        result = {"ok": False, "data": None, "error": f"Unknown tool '{name}'"}
    elif not entry.get("readonly", False):
        result = {"ok": False, "data": None, "error": f"Tool '{name}' is not read-only — blocked."}
    else:
        try:
            result = entry["fn"](role=role, **args)
        except TypeError as exc:
            result = {"ok": False, "data": None, "error": f"Bad args for '{name}': {exc}"}
        except Exception as exc:
            result = {"ok": False, "data": None, "error": str(exc)}

    tools_called.append({"name": name, "args": args, "ok": result.get("ok", False)})

    # Collect advisory chunks for the caller's contexts field
    if name == "search_knowledge" and result.get("ok") and result.get("data"):
        contexts.extend(result["data"].get("chunks", []))

    return result


def _tool_payload(result: dict) -> str:
    """Serialise tool result for inclusion as a message content string."""
    body = result.get("data") if result.get("ok") else {"error": result.get("error")}
    return json.dumps(body, ensure_ascii=False, default=str)


def _parse_args(raw) -> dict:
    """Normalise tool arguments — Ollama may return a dict or a JSON string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


# ── System prompts ────────────────────────────────────────────────────────────

_SYSTEM_NATIVE = (
    "You are the VRA Security Agent - an expert AI assistant for vulnerability remediation management.\n"
    "\n"
    "MANDATORY RULES - follow exactly:\n"
    "1. ALWAYS call a tool before answering any question about jobs, metrics, CVEs, controls, or enrichment.\n"
    "   Never answer data questions from memory.\n"
    "2. For ANY advisory question (how should we, what should we do, where should we focus,\n"
    "   how often, best practice, compensating controls, prioritize, re-scan frequency)\n"
    "   call search_knowledge FIRST before any data tool.\n"
    "3. For posture/summary questions (overall security posture, where to focus) call BOTH\n"
    "   get_metrics (live KPIs) AND search_knowledge (advisory guidance).\n"
    "4. When a question names a specific control ID (ISO A.8.8, CIS 7, CIS Control 7, CSF-ID.AM)\n"
    "   pass control_id to query_controls - do NOT use framework filter for specific controls.\n"
    "5. Be concise. Cite specific numbers from tools. Never invent data."
)

def _build_react_system(specs: list[dict]) -> str:
    lines = [
        "You are the VRA Security Agent — an expert AI assistant for vulnerability remediation.",
        "Answer questions using the VRA tools. NEVER invent data; call a tool to look things up.",
        "",
        "AVAILABLE TOOLS:",
    ]
    for s in specs:
        fn     = s["function"]
        props  = fn.get("parameters", {}).get("properties", {})
        params = ", ".join(
            f"{k}" + (f": {v['type']}" if "type" in v else "")
            for k, v in props.items()
        ) or "no parameters"
        desc = fn["description"].split("\n")[0][:140]
        lines.append(f"  {fn['name']}({params})")
        lines.append(f"    {desc}")

    lines += [
        "",
        "RESPONSE FORMAT — output ONLY valid JSON, nothing else:",
        "",
        "  To call a tool:",
        '  {"tool": "<tool_name>", "args": {"param_name": value, ...}}',
        "",
        "  To give the final answer:",
        '  {"answer": "<complete answer for the user>"}',
        "",
        "RULES:",
        "- Never include both 'tool' and 'answer' in the same response.",
        "- For advisory questions (how should we, best practice, compensating controls, prioritize, where to focus)",
        "  call search_knowledge FIRST. For posture questions call get_metrics AND search_knowledge.",
        "- If a tool errors, try a different approach or answer with what you know.",
        "- Keep answers factual, concise, and grounded in tool results.",
    ]
    return "\n".join(lines)


# ── Advice-question detection ─────────────────────────────────────────────────

_ADVICE_KEYWORDS = frozenset([
    "how should", "what should", "where should", "how often",
    "best practice", "compensating control", "prioritize", "re-scan",
    "rescan", "advice", "recommend", "guidance", "what are reasonable",
    "how do we", "how can we", "what can we",
])


def _is_advice_question(question: str) -> bool:
    q = question.lower()
    return any(kw in q for kw in _ADVICE_KEYWORDS)


# ── Native tool-calling mode ──────────────────────────────────────────────────

def _run_native(
    messages:     list[dict],
    config:       dict,
    tool_specs:   list[dict],
    role:         str,
    tools_called: list[dict],
    contexts:     list[dict],
    question:     str = "",
) -> dict:
    """Ollama native tool-calling loop (up to MAX_ITERATIONS).

    Guard: if the model answers an advice question without calling any tool on
    the first iteration, we force a search_knowledge call so the answer is
    grounded in the RAG corpus rather than the model's training data alone.
    """
    for iteration in range(MAX_ITERATIONS):
        data       = _ollama_chat(messages, config, tools=tool_specs)
        msg        = data.get("message", {})
        content    = (msg.get("content") or "").strip()
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            # ── Advice guard: force search_knowledge on first no-tool reply ──
            if iteration == 0 and _is_advice_question(question) and not tools_called:
                logger.info("Advice guard triggered for: %s", question[:60])
                rag_result = _execute_tool(
                    "search_knowledge",
                    {"query": question, "top_k": 5},
                    role,
                    tools_called,
                    contexts,
                )
                # Inject the tool exchange into message history so the model
                # synthesises an answer grounded in the corpus.
                messages.append({
                    "role":       "assistant",
                    "content":    content,
                    "tool_calls": [{
                        "function": {
                            "name":      "search_knowledge",
                            "arguments": {"query": question, "top_k": 5},
                        }
                    }],
                })
                messages.append({"role": "tool", "content": _tool_payload(rag_result)})
                continue  # next iteration will synthesise using the corpus

            # Model answered (grounded or after guard) — return
            return {
                "answer":       content,
                "tools_called": tools_called,
                "contexts":     contexts,
                "iterations":   iteration + 1,
                "mode":         "native",
                "model":        config["model"],
            }

        # Append the assistant turn (with tool_calls) to message history
        messages.append({
            "role":       "assistant",
            "content":    content,
            "tool_calls": tool_calls,
        })

        # Execute each tool and feed results back
        for tc in tool_calls:
            fn     = tc.get("function", {})
            t_name = fn.get("name", "")
            t_args = _parse_args(fn.get("arguments"))

            result   = _execute_tool(t_name, t_args, role, tools_called, contexts)
            messages.append({"role": "tool", "content": _tool_payload(result)})

    # Hit iteration cap — request a synthesis without further tool calls
    messages.append({
        "role":    "user",
        "content": "Based on all the tool results above, provide a clear, concise final answer.",
    })
    try:
        data    = _ollama_chat(messages, config, tools=None)
        content = (data.get("message", {}).get("content") or "").strip()
    except Exception:
        content = "I reached the iteration limit and could not synthesise a complete answer."

    return {
        "answer":       content,
        "tools_called": tools_called,
        "contexts":     contexts,
        "iterations":   MAX_ITERATIONS,
        "mode":         "native",
        "model":        config["model"],
    }


# ── ReAct JSON fallback ───────────────────────────────────────────────────────

def _run_react(
    messages:     list[dict],
    config:       dict,
    tool_specs:   list[dict],
    role:         str,
    tools_called: list[dict],
    contexts:     list[dict],
) -> dict:
    """Constrained ReAct JSON loop — format:json enforced each turn."""
    for iteration in range(MAX_ITERATIONS):
        data    = _ollama_chat(messages, config, json_mode=True)
        content = (data.get("message", {}).get("content") or "").strip()

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            # Not valid JSON — accept as final answer
            return {
                "answer":       content or "Unable to parse model response.",
                "tools_called": tools_called,
                "contexts":     contexts,
                "iterations":   iteration + 1,
                "mode":         "react",
                "model":        config["model"],
            }

        # ── Final answer ──────────────────────────────────────────────────────
        if "answer" in parsed:
            return {
                "answer":       str(parsed["answer"]),
                "tools_called": tools_called,
                "contexts":     contexts,
                "iterations":   iteration + 1,
                "mode":         "react",
                "model":        config["model"],
            }

        # ── Tool call ─────────────────────────────────────────────────────────
        if "tool" in parsed:
            t_name = str(parsed["tool"])
            t_args = parsed.get("args") or {}
            if not isinstance(t_args, dict):
                t_args = {}

            result = _execute_tool(t_name, t_args, role, tools_called, contexts)
            payload = result.get("data") if result.get("ok") else {"error": result.get("error")}

            messages.append({"role": "assistant", "content": content})
            messages.append({
                "role":    "user",
                "content": (
                    f"Tool '{t_name}' result: {json.dumps(payload, ensure_ascii=False, default=str)}\n"
                    "Continue: call another tool if needed, or provide the final answer."
                ),
            })
            continue

        # ── Unrecognised shape — treat as answer ──────────────────────────────
        answer = (
            parsed.get("answer")
            or parsed.get("message")
            or parsed.get("response")
            or content
        )
        return {
            "answer":       str(answer),
            "tools_called": tools_called,
            "contexts":     contexts,
            "iterations":   iteration + 1,
            "mode":         "react",
            "model":        config["model"],
        }

    return {
        "answer": (
            "I reached the maximum reasoning steps without a complete answer. "
            "Please try rephrasing your question."
        ),
        "tools_called": tools_called,
        "contexts":     contexts,
        "iterations":   MAX_ITERATIONS,
        "mode":         "react",
        "model":        config["model"],
    }


# ── Public entry point ────────────────────────────────────────────────────────

def run_agent(
    question: str,
    role:     str,
    username: str,
    history:  Optional[list[dict]] = None,
) -> dict:
    """Run the agent loop for *question* and return the result envelope.

    Tries Ollama native tool-calling first (qwen2.5:14b supports this).
    Falls back to a constrained ReAct JSON loop if Ollama is unreachable,
    returns an HTTP error, or fails for any other reason.
    """
    config      = _load_config()
    tool_specs  = _build_tool_specs()
    tools_called: list[dict] = []
    contexts:     list[dict] = []

    # ── Sanitised prior history (user + assistant turns only) ─────────────────
    safe_history: list[dict] = []
    if history:
        for h in history:
            if isinstance(h, dict) and h.get("role") in ("user", "assistant"):
                safe_history.append({
                    "role":    h["role"],
                    "content": str(h.get("content", "")),
                })

    # ── Native mode messages ──────────────────────────────────────────────────
    native_messages: list[dict] = [{"role": "system", "content": _SYSTEM_NATIVE}]
    native_messages.extend(safe_history)
    native_messages.append({"role": "user", "content": question})

    try:
        logger.info("Agent [%s/%s] native mode: %s", username, role, question[:80])
        return _run_native(
            native_messages, config, tool_specs, role, tools_called, contexts,
            question=question,
        )

    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
    ) as exc:
        logger.warning(
            "Agent native mode failed (%s) — falling back to ReAct loop", exc
        )

    except Exception as exc:
        logger.warning(
            "Agent native mode unexpected error (%s) — falling back to ReAct loop", exc
        )

    # ── ReAct fallback messages ───────────────────────────────────────────────
    react_system   = _build_react_system(tool_specs)
    react_messages: list[dict] = [{"role": "system", "content": react_system}]
    react_messages.extend(safe_history)
    react_messages.append({"role": "user", "content": question})

    tools_called_react: list[dict] = []
    contexts_react:     list[dict] = []

    logger.info("Agent [%s/%s] ReAct fallback: %s", username, role, question[:80])
    return _run_react(
        react_messages, config, tool_specs, role,
        tools_called_react, contexts_react,
    )
