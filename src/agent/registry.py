"""VRA agent tool registry.

``TOOL_REGISTRY`` maps each tool name to its callable, JSON-Schema input
definition, human-readable description, and metadata.  The orchestrator uses:

    list_tools()    — discover available tools (name + description + schema)
    get_tool(name)  — retrieve a specific ToolEntry for invocation

All registered tools are read-only (``readonly=True``).  The schema follows
the Claude tool_use / Anthropic SDK ``input_schema`` format.
"""

from __future__ import annotations

from typing import Any, Callable, TypedDict

from agent.tools import (
    get_enrichment_status,
    get_job_detail,
    get_metrics,
    get_risk_acceptances,
    get_sla_compliance,
    get_threat_alerts,
    list_jobs,
    query_controls,
    search_cves,
    search_knowledge,
)


class ToolEntry(TypedDict):
    fn:           Callable[..., dict]
    description:  str
    readonly:     bool
    input_schema: dict[str, Any]


TOOL_REGISTRY: dict[str, ToolEntry] = {

    # ── 1 ─────────────────────────────────────────────────────────────────────
    "get_metrics": {
        "fn": get_metrics,
        "description": (
            "Return live VRA KPI metrics: total job count, breakdown by status "
            "and risk level, KEV job count, overdue (past-SLA) count, SLA "
            "compliance percentage, critical/high open counts, and the "
            "KEV-past-SLA sub-count.  Use this for any dashboard or overall "
            "security-posture question."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },

    # ── 2 ─────────────────────────────────────────────────────────────────────
    "get_sla_compliance": {
        "fn": get_sla_compliance,
        "description": (
            "Return detailed SLA compliance data: total open job count, how many "
            "are within SLA vs breached, the compliance percentage, and a list of "
            "overdue jobs with days-overdue, risk level, and product per entry."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },

    # ── 3 ─────────────────────────────────────────────────────────────────────
    "list_jobs": {
        "fn": list_jobs,
        "description": (
            "List remediation jobs with optional filters. "
            "``status`` accepts TO_DO, IN_PROGRESS, DONE, CLOSED, FALSE_POSITIVE, "
            "or the alias 'open' (all non-terminal). "
            "``risk_level`` accepts CRITICAL, HIGH, MEDIUM, LOW. "
            "Set ``kev_only=true`` for jobs containing a CISA KEV CVE. "
            "Set ``past_sla=true`` for jobs that have breached their SLA deadline."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": (
                        "Workflow status filter: TO_DO, IN_PROGRESS, DONE, CLOSED, "
                        "FALSE_POSITIVE, or the alias 'open' (non-terminal)."
                    ),
                },
                "risk_level": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "Maximum risk level of the job.",
                },
                "business_unit": {
                    "type": "string",
                    "description": "Filter by business unit name.",
                },
                "kev_only": {
                    "type": "boolean",
                    "description": "Return only jobs containing at least one CISA KEV CVE.",
                    "default": False,
                },
                "past_sla": {
                    "type": "boolean",
                    "description": "Return only jobs whose SLA deadline has passed.",
                    "default": False,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default 50, max 200).",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 200,
                },
            },
            "required": [],
        },
    },

    # ── 4 ─────────────────────────────────────────────────────────────────────
    "get_job_detail": {
        "fn": get_job_detail,
        "description": (
            "Return the complete record for a single remediation job by ID. "
            "Includes CVE list, risk score breakdown, SLA dates, triage decision, "
            "assigned team, KEV flag, and lifecycle timestamps."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "string",
                    "description": "Job identifier, e.g. 'JOB-0123' or a UUID string.",
                },
            },
            "required": ["job_id"],
        },
    },

    # ── 5 ─────────────────────────────────────────────────────────────────────
    "search_cves": {
        "fn": search_cves,
        "description": (
            "Look up a specific CVE in the enrichment cache (KEV flag, EPSS score, "
            "CVSS, NVD description) and identify which remediation jobs are affected. "
            "Set ``kev_only=true`` to return data only when the CVE is on the CISA "
            "KEV catalog."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier, e.g. 'CVE-2024-3094'. Case-insensitive.",
                },
                "kev_only": {
                    "type": "boolean",
                    "description": "Return data only when the CVE is in the CISA KEV catalog.",
                    "default": False,
                },
            },
            "required": ["cve_id"],
        },
    },

    # ── 6 ─────────────────────────────────────────────────────────────────────
    "get_enrichment_status": {
        "fn": get_enrichment_status,
        "description": (
            "Return the freshness status of VRA enrichment feeds: how many CVEs are "
            "cached for KEV, EPSS, and NVD; when each feed was last fetched; "
            "the RAG advisory corpus file count; and the enrichment DB size."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },

    # ── 7 ─────────────────────────────────────────────────────────────────────
    "get_threat_alerts": {
        "fn": get_threat_alerts,
        "description": (
            "List threat-exposure alerts from the asset–CVE matching engine, ordered "
            "by KEV flag DESC then EPSS score DESC. "
            "Filter by ``status`` (open / acknowledged / dismissed), "
            "``alert_type`` (kev_match / high_epss), or set ``kev_only=true``."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["open", "acknowledged", "dismissed"],
                    "description": "Alert lifecycle status.",
                },
                "alert_type": {
                    "type": "string",
                    "enum": ["kev_match", "high_epss"],
                    "description": "Type of threat signal that triggered the alert.",
                },
                "kev_only": {
                    "type": "boolean",
                    "description": "Restrict to alerts from CISA KEV-matched CVEs.",
                    "default": False,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of alerts to return (default 50, max 500).",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": [],
        },
    },

    # ── 8 ─────────────────────────────────────────────────────────────────────
    "get_risk_acceptances": {
        "fn": get_risk_acceptances,
        "description": (
            "Return the risk acceptance register. By default returns all active "
            "entries joined with job data. "
            "Set ``expired=true`` to restrict to acceptances whose expiry_date "
            "has already passed — logically overdue for re-review."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "expired": {
                    "type": "boolean",
                    "description": "Return only acceptances past their expiry date.",
                    "default": False,
                },
            },
            "required": [],
        },
    },

    # ── 9 ─────────────────────────────────────────────────────────────────────
    "query_controls": {
        "fn": query_controls,
        "description": (
            "Return compliance controls from the VRA catalog with live evidence "
            "snapshots and computed coverage status (full / partial / supporting / "
            "not_applicable). "
            "Filter by ``framework`` key ('ISO27001', 'CIS', 'CSF') or by "
            "``control_id`` (e.g. 'ISO-A.8.8', 'CIS-7', 'CSF-ID.AM'). "
            "Returns all 22 controls when no filter is supplied."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": ["ISO27001", "CIS", "CSF"],
                    "description": (
                        "Compliance framework key: 'ISO27001' (ISO/IEC 27001:2022), "
                        "'CIS' (CIS Controls v8), or 'CSF' (NIST CSF 2.0)."
                    ),
                },
                "control_id": {
                    "type": "string",
                    "description": (
                        "Specific control identifier, e.g. 'ISO-8.8', 'CIS-7', "
                        "'CSF-ID.AM'."
                    ),
                },
            },
            "required": [],
        },
    },

    # ── 10 ────────────────────────────────────────────────────────────────────
    "search_knowledge": {
        "fn": search_knowledge,
        "description": (
            "Search the VRA advisory knowledge base (RAG corpus) using semantic "
            "similarity and return the most relevant advisory text chunks — grounded "
            "in CISA advisories, NVD entries, and vendor security bulletins. "
            "Use for advice, best-practice, and 'how to handle X' questions."
        ),
        "readonly": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Natural-language question or topic to search, e.g. "
                        "'compensating controls for unpatched critical vulnerability'."
                    ),
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of advisory chunks to return (1–20, default 5).",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 20,
                },
            },
            "required": ["query"],
        },
    },
}


# ── Public API ────────────────────────────────────────────────────────────────

def list_tools() -> list[dict[str, Any]]:
    """Return a list of tool descriptors for the orchestrator.

    Each entry contains: name, description, readonly, input_schema.
    This is the shape the LLM system prompt / tool-use header is built from.
    """
    return [
        {
            "name":         name,
            "description":  entry["description"],
            "readonly":     entry["readonly"],
            "input_schema": entry["input_schema"],
        }
        for name, entry in TOOL_REGISTRY.items()
    ]


def get_tool(name: str) -> ToolEntry | None:
    """Return the full ToolEntry for *name*, or None if not registered."""
    return TOOL_REGISTRY.get(name)
