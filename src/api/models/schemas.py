"""Pydantic v2 schemas for all API request/response bodies."""

from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime


class JobStatusUpdate(BaseModel):
    status: str
    changed_by: str = "api"
    comment: Optional[str] = None


class TriageUpdate(BaseModel):
    triage_decision: str  # CONFIRMED | FALSE_POSITIVE | RISK_ACCEPTED | DEFERRED
    assigned_team: Optional[str] = None
    changed_by: str = "api"
    comment: Optional[str] = None


class RescanRequest(BaseModel):
    enriched_csv: str = "data/output/vuln_enriched.csv"
    jobs_csv: str = "data/output/remediation_jobs.csv"
    changed_by: str = "pipeline"


class TicketRequest(BaseModel):
    provider: str = "console"  # console | jira


class FeedbackRequest(BaseModel):
    feedback: int  # 1 = helpful, -1 = not helpful


class AdviceFeedbackRequest(BaseModel):
    """Rate a specific llm_advice row by its PK. Preferred over job-level feedback."""
    feedback: int           # 1 = helpful, -1 = not helpful
    note: Optional[str] = None


class DispositionRequest(BaseModel):
    """Record what the analyst did with the advice after reading it."""
    disposition: str        # accepted | edited | rejected


# ── P2: lifecycle transition ───────────────────────────────────────────────────

class LifecycleTransition(BaseModel):
    new_status: str
    comment: Optional[str] = None
    lifecycle_note: Optional[str] = None


# ── P2: risk acceptance ───────────────────────────────────────────────────────

class RiskAcceptanceCreate(BaseModel):
    justification: str
    compensating_controls: Optional[str] = None
    expiry_date: Optional[str] = None       # ISO date string YYYY-MM-DD
    review_trigger: Optional[str] = None


class RiskAcceptanceExpire(BaseModel):
    """Mark an existing acceptance as expired or superseded."""
    status: str = "expired"                 # expired | superseded


# ── P2: workaround record ─────────────────────────────────────────────────────

class WorkaroundCreate(BaseModel):
    control_description: str
    followup_date: Optional[str] = None     # ISO date string YYYY-MM-DD


# ── Custom SLA override ───────────────────────────────────────────────────────

class SlaOverrideUpdate(BaseModel):
    sla_override_days: Optional[int] = Field(None, ge=1, le=3650, description="Custom SLA in days (null to clear)")
    comment: Optional[str] = None
