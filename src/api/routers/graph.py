"""Graph API — blast-radius, similar findings, manual cache refresh."""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import get_current_user, require_role
from api.db.connection import get_db, DB_PATH

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Graph"])

# Configure the graph cache's DB path once at import time
from api.services.graph import cache as _graph_cache
_graph_cache.configure(Path(DB_PATH))


# ── POST /graph/refresh ───────────────────────────────────────────────────────

@router.post("/api/graph/refresh")
def refresh_graph(user: dict = Depends(require_role("admin"))):
    """Invalidate and synchronously rebuild the in-memory graph. Admin only."""
    stats = _graph_cache.invalidate()
    return {"data": stats}


# ── GET /api/findings/{id}/blast-radius ───────────────────────────────────────

@router.get("/api/findings/{finding_id}/blast-radius")
def get_blast_radius(
    finding_id: str,
    depth:     int = Query(2, ge=1, le=4),
    max_nodes: int = Query(80, ge=10, le=500),
    conn:  sqlite3.Connection = Depends(get_db),
    user:  dict               = Depends(get_current_user),
):
    """Return the blast-radius subgraph (bounded BFS from the affected asset)."""
    from api.services.graph.queries import blast_radius
    result = blast_radius(finding_id, depth=depth, max_nodes=max_nodes, conn=conn)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"data": result}


# ── GET /api/findings/{id}/similar ────────────────────────────────────────────

@router.get("/api/findings/{finding_id}/similar")
def get_similar_findings(
    finding_id: str,
    k: int = Query(10, ge=1, le=50),
    conn:  sqlite3.Connection = Depends(get_db),
    user:  dict               = Depends(get_current_user),
):
    """Return up to k findings similar to the given one (graph + embedding hybrid)."""
    from api.services.graph.queries import similar_findings
    results = similar_findings(finding_id, k=k, conn=conn)
    return {"data": results, "total": len(results)}
