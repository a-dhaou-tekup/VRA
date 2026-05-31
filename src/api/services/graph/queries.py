"""Graph queries: blast_radius and similar_findings.

blast_radius  — bounded BFS from the finding's asset node; returns a
                JSON-serialisable subgraph (nodes + edges).

similar_findings — combines:
  (a) shared-graph-neighbour overlap (Jaccard over 2-hop sets)
  (b) RAG embedding similarity via multi_collection_search if available
  Weights: GRAPH_SIM_WEIGHT (default 0.4) + EMBED_SIM_WEIGHT (default 0.6)
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from typing import Optional

import networkx as nx

logger = logging.getLogger(__name__)

GRAPH_WEIGHT = float(os.getenv("GRAPH_SIM_WEIGHT", "0.4"))
EMBED_WEIGHT = float(os.getenv("EMBED_SIM_WEIGHT", "0.6"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _node_to_dict(node_id: str, attrs: dict) -> dict:
    return {"id": node_id, **{k: v for k, v in attrs.items() if isinstance(v, (str, int, float, bool, type(None)))}}


def _subgraph_to_json(G: nx.DiGraph, nodes: set[str]) -> dict:
    node_list, edge_list = [], []
    for nid in nodes:
        if nid in G:
            node_list.append(_node_to_dict(nid, G.nodes[nid]))
    for u, v, data in G.edges(data=True):
        if u in nodes and v in nodes:
            edge_list.append({"source": u, "target": v,
                               "kind": data.get("kind", "")})
    return {"nodes": node_list, "edges": edge_list}


# ── Finding → asset lookup ────────────────────────────────────────────────────

def _get_finding_asset_node(finding_id: str, G: nx.DiGraph, conn: sqlite3.Connection) -> Optional[str]:
    """Return the graph node id for the asset associated with this finding."""
    row = conn.execute(
        "SELECT cve_id, hostname FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    if not row:
        return None
    hostname = row["hostname"] or ""
    cve_id   = row["cve_id"]   or ""

    # Find asset node by hostname
    for nid, attrs in G.nodes(data=True):
        if attrs.get("kind") == "asset" and attrs.get("hostname") == hostname:
            return nid

    # Fallback: find via CVE edge
    cve_nid = f"cve:{cve_id}" if cve_id else None
    if cve_nid and cve_nid in G:
        for _, tgt, data in G.out_edges(cve_nid, data=True):
            if data.get("kind") == "finding_of" and G.nodes[tgt].get("kind") == "asset":
                return tgt
    return None


# ── blast_radius ──────────────────────────────────────────────────────────────

def blast_radius(finding_id: str, depth: int = 2, conn: Optional[sqlite3.Connection] = None) -> dict:
    """Bounded BFS from the affected asset; returns JSON-serialisable subgraph.

    Performance target: < 200 ms for depth <= 3.
    """
    from api.services.graph.cache import get_graph
    from api.db.connection import get_connection

    t0 = time.monotonic()
    G  = get_graph()

    _conn = conn or get_connection()
    owned = conn is not None

    try:
        # 1. Find the finding row
        row = _conn.execute(
            "SELECT cve_id, hostname, component, severity FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        if not row:
            return {"error": f"Finding '{finding_id}' not found.", "nodes": [], "edges": []}

        hostname = row["hostname"] or ""
        cve_id   = row["cve_id"]   or ""

        # 2. Locate the asset node
        asset_nid = _get_finding_asset_node(finding_id, G, _conn)

        # 3. BFS outward from the asset (and also include the CVE node)
        visited: set[str] = set()
        if asset_nid:
            for nid in nx.bfs_tree(G.to_undirected(), asset_nid, depth_limit=depth).nodes():
                visited.add(nid)
        else:
            logger.warning("blast_radius: no asset node found for finding %s", finding_id)

        # Always include the CVE node
        cve_nid = f"cve:{cve_id}" if cve_id else None
        if cve_nid and cve_nid in G:
            visited.add(cve_nid)
            # Add 1-hop neighbours of the CVE as well
            for nbr in list(G.successors(cve_nid)) + list(G.predecessors(cve_nid)):
                visited.add(nbr)

        result = _subgraph_to_json(G, visited)

    finally:
        if not owned:
            _conn.close()

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    result["elapsed_ms"] = elapsed_ms
    result["finding_id"] = finding_id
    result["depth"]      = depth

    if elapsed_ms > 200:
        logger.warning("blast_radius: exceeded 200 ms target (%d ms)", elapsed_ms)

    logger.info("blast_radius: %d nodes %d edges in %d ms",
                len(result["nodes"]), len(result["edges"]), elapsed_ms)
    return result


# ── similar_findings ──────────────────────────────────────────────────────────

def _graph_neighbours(G: nx.DiGraph, node_id: str, hops: int = 2) -> set[str]:
    """Return the set of node IDs within `hops` edges in either direction."""
    nbrs: set[str] = set()
    if node_id not in G:
        return nbrs
    ug = G.to_undirected()
    for nid in nx.single_source_shortest_path_length(ug, node_id, cutoff=hops).keys():
        nbrs.add(nid)
    return nbrs


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _embed_similarity(cve_id: str, component: str, k: int) -> list[tuple[str, float]]:
    """Try RAG-based embedding similarity. Returns [(cve_id_or_text, score), ...]."""
    try:
        from rag.multi_collection import multi_collection_search
        query = " ".join(filter(None, [cve_id, component]))
        if not query.strip():
            return []
        docs = multi_collection_search(query, k=k * 2)
        out = []
        for d in docs[:k]:
            meta = d.get("metadata", {})
            src_id = meta.get("source_id") or d.get("source_id") or ""
            out.append((src_id, float(d.get("rrf_score", 0.0))))
        return out
    except Exception as exc:
        logger.debug("embed_similarity failed: %s", exc)
        return []


def similar_findings(
    finding_id: str,
    k: int = 10,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Return up to k findings similar to the given one.

    Score = EMBED_WEIGHT × embed_sim + GRAPH_WEIGHT × graph_jaccard
    """
    from api.services.graph.cache import get_graph
    from api.db.connection import get_connection

    G    = get_graph()
    _conn = conn or get_connection()
    owned = conn is not None

    try:
        # Load the reference finding
        ref = _conn.execute(
            "SELECT id, cve_id, hostname, component, severity FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        if not ref:
            return []

        ref_cve   = ref["cve_id"]   or ""
        ref_comp  = ref["component"] or ""
        ref_asset = _get_finding_asset_node(finding_id, G, _conn)

        # Load all OTHER findings
        others = _conn.execute(
            "SELECT id, cve_id, hostname, component, severity FROM findings WHERE id != ?",
            (finding_id,),
        ).fetchall()

        if not others:
            return []

        # Graph neighbours of reference finding's asset
        ref_nbrs = _graph_neighbours(G, ref_asset, hops=2) if ref_asset else set()

        # Embedding similarity (returns cve-level scores)
        embed_scores_raw = _embed_similarity(ref_cve, ref_comp, k=min(k * 3, 30))
        embed_cve_map: dict[str, float] = {}
        if embed_scores_raw:
            max_s = max(s for _, s in embed_scores_raw) or 1.0
            for src_id, score in embed_scores_raw:
                if src_id.startswith("CVE-"):
                    embed_cve_map[src_id] = score / max_s

        results = []
        for row in others:
            oid    = row["id"]
            o_cve  = row["cve_id"] or ""
            o_comp = row["component"] or ""

            # Graph score: Jaccard of 2-hop neighbourhoods
            o_asset = _get_finding_asset_node(oid, G, _conn)
            o_nbrs  = _graph_neighbours(G, o_asset, hops=2) if o_asset else set()
            graph_s = _jaccard(ref_nbrs, o_nbrs)

            # Embedding score: use CVE-level score if available, else 0
            embed_s = embed_cve_map.get(o_cve, 0.0)

            total = EMBED_WEIGHT * embed_s + GRAPH_WEIGHT * graph_s

            if total > 0:
                results.append({
                    "finding_id":   oid,
                    "cve_id":       o_cve,
                    "hostname":     row["hostname"] or "",
                    "component":    o_comp,
                    "severity":     row["severity"] or "",
                    "score":        round(total, 4),
                    "breakdown": {
                        "embed":  round(embed_s,  4),
                        "graph":  round(graph_s,  4),
                        "weights": {"embed": EMBED_WEIGHT, "graph": GRAPH_WEIGHT},
                    },
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:k]

    finally:
        if not owned:
            _conn.close()
