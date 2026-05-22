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
