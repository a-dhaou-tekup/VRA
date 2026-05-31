"""In-process graph cache with configurable TTL refresh.

Single-process only.  If VRA is deployed behind a multi-worker uvicorn, each
worker will maintain its own copy; see docs/graph.md for the known limitation
and the recommended upgrade path.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

import networkx as nx

logger = logging.getLogger(__name__)

_REFRESH_INTERVAL = int(os.getenv("GRAPH_REFRESH_INTERVAL_SECONDS", "60"))

_lock:       threading.Lock   = threading.Lock()
_graph:      Optional[nx.DiGraph] = None
_built_at:   float            = 0.0  # monotonic time of last successful build
_db_path:    Optional[Path]   = None


def _build_now() -> nx.DiGraph:
    from api.services.graph.builder import build_graph
    return build_graph(_db_path)


def get_graph() -> nx.DiGraph:
    """Return the cached graph, rebuilding if the TTL has expired."""
    global _graph, _built_at
    now = time.monotonic()
    with _lock:
        if _graph is None or (now - _built_at) > _REFRESH_INTERVAL:
            logger.info("graph.cache: rebuilding (age=%.1f s)", now - _built_at)
            _graph    = _build_now()
            _built_at = time.monotonic()
    return _graph


def invalidate() -> dict:
    """Force a synchronous rebuild and return stats."""
    global _graph, _built_at
    t0 = time.monotonic()
    new_g = _build_now()
    with _lock:
        _graph    = new_g
        _built_at = time.monotonic()
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return {
        "nodes":      new_g.number_of_nodes(),
        "edges":      new_g.number_of_edges(),
        "elapsed_ms": elapsed_ms,
    }


def configure(db_path: Path) -> None:
    """Set the platform DB path before the first build."""
    global _db_path
    _db_path = db_path
