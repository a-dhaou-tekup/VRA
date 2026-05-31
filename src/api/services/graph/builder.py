"""Graph builder — reads platform.db and returns a NetworkX DiGraph.

Node kinds  : cve | component | asset | owner | service
Edge kinds  : finding_of | runs | owned_by | serves | depends_on

Called by cache.py; do not import at module level to keep startup fast.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path

import networkx as nx

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent.parent.parent
DB_PATH = ROOT / "data" / "cache" / "platform.db"


def _open(db_path: Path | None = None) -> sqlite3.Connection:
    path = str(db_path or DB_PATH)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ── Node helpers ──────────────────────────────────────────────────────────────

def _n_cve(cve_id: str)       -> str: return f"cve:{cve_id}"
def _n_component(comp: str)   -> str: return f"component:{comp}"
def _n_asset(asset_id: str)   -> str: return f"asset:{asset_id}"
def _n_owner(owner: str)      -> str: return f"owner:{owner}"
def _n_service(svc_id: str)   -> str: return f"service:{svc_id}"


def build_graph(db_path: Path | None = None) -> nx.DiGraph:
    """Read platform.db and build a fully-connected DiGraph.

    Performance target: < 2 s on the demo dataset (~20 assets, 50 findings, 8 services).
    """
    t0 = time.monotonic()
    G  = nx.DiGraph()
    conn = _open(db_path)

    try:
        # ── Assets ────────────────────────────────────────────────────────────
        for row in conn.execute(
            "SELECT asset_id, hostname, ip_address, business_owner, owning_team, "
            "criticality, environment, internet_exposed FROM assets"
        ).fetchall():
            nid = _n_asset(row["asset_id"])
            G.add_node(nid, kind="asset", label=row["hostname"] or row["asset_id"],
                       asset_id=row["asset_id"], hostname=row["hostname"] or "",
                       criticality=row["criticality"] or "unknown",
                       environment=row["environment"] or "")

            # owned_by edge
            owner = row["business_owner"] or row["owning_team"]
            if owner:
                oid = _n_owner(owner)
                if oid not in G:
                    G.add_node(oid, kind="owner", label=owner)
                G.add_edge(nid, oid, kind="owned_by")

        # ── Findings → CVE + component edges ─────────────────────────────────
        for row in conn.execute(
            "SELECT id, cve_id, hostname, component, severity, state FROM findings"
        ).fetchall():
            cve_id = row["cve_id"]
            if not cve_id:
                continue

            cid = _n_cve(cve_id)
            if cid not in G:
                G.add_node(cid, kind="cve", label=cve_id, cve_id=cve_id,
                           severity=row["severity"] or "")
            G.nodes[cid]["severity"] = row["severity"] or G.nodes[cid].get("severity", "")

            # link CVE → asset (finding_of)
            host = row["hostname"] or ""
            asset_nid = _find_asset_node(G, host)
            if asset_nid:
                G.add_edge(cid, asset_nid, kind="finding_of", finding_id=row["id"])

            # component node  (runs edge: asset → component)
            comp = row["component"]
            if comp:
                comp_nid = _n_component(comp)
                if comp_nid not in G:
                    G.add_node(comp_nid, kind="component", label=comp)
                if asset_nid:
                    G.add_edge(asset_nid, comp_nid, kind="runs")

        # ── Jobs: extract CVE+asset edges not already covered by findings ────
        for row in conn.execute("SELECT cve_list, asset_ids, main_product FROM jobs"):
            cves   = _parse_json_list(row["cve_list"])
            assets = _parse_json_list(row["asset_ids"])
            product = row["main_product"] or ""

            for cve_id in cves:
                if not cve_id:
                    continue
                cid = _n_cve(cve_id)
                if cid not in G:
                    G.add_node(cid, kind="cve", label=cve_id, cve_id=cve_id)

            for aid in assets:
                nid = _n_asset(aid)
                if nid not in G:
                    G.add_node(nid, kind="asset", label=aid, asset_id=aid)
                # component from main_product
                if product:
                    cnid = _n_component(product)
                    if cnid not in G:
                        G.add_node(cnid, kind="component", label=product)
                    if not G.has_edge(nid, cnid):
                        G.add_edge(nid, cnid, kind="runs")

        # ── Services ─────────────────────────────────────────────────────────
        try:
            for row in conn.execute("SELECT id, name, owner_id FROM services"):
                sid = _n_service(row["id"])
                G.add_node(sid, kind="service", label=row["name"] or row["id"],
                           service_id=row["id"])
                if row["owner_id"]:
                    oid = _n_owner(row["owner_id"])
                    if oid not in G:
                        G.add_node(oid, kind="owner", label=row["owner_id"])
                    G.add_edge(sid, oid, kind="owned_by")
        except Exception:
            pass  # table may not exist on old DBs

        # ── Asset → Service  (serves) ─────────────────────────────────────────
        try:
            for row in conn.execute("SELECT asset_id, service_id FROM asset_services"):
                a = _n_asset(row["asset_id"])
                s = _n_service(row["service_id"])
                if a in G and s in G:
                    G.add_edge(a, s, kind="serves")
        except Exception:
            pass

        # ── Service → Service  (depends_on) ─────────────────────────────────
        try:
            for row in conn.execute(
                "SELECT parent_service_id, child_service_id FROM service_dependencies"
            ):
                p = _n_service(row["parent_service_id"])
                c = _n_service(row["child_service_id"])
                if p in G and c in G:
                    G.add_edge(p, c, kind="depends_on")
        except Exception:
            pass

    finally:
        conn.close()

    elapsed = (time.monotonic() - t0) * 1000
    logger.info(
        "graph.build: %d nodes  %d edges  %.1f ms",
        G.number_of_nodes(), G.number_of_edges(), elapsed,
    )
    if elapsed > 2000:
        logger.warning("graph.build: exceeded 2 s target (%.0f ms) — profile schema!", elapsed)

    return G


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_asset_node(G: nx.DiGraph, hostname: str) -> str | None:
    """Return the first asset node whose hostname matches."""
    if not hostname:
        return None
    for nid, attrs in G.nodes(data=True):
        if attrs.get("kind") == "asset" and attrs.get("hostname") == hostname:
            return nid
    return None


def _parse_json_list(val) -> list[str]:
    if not val:
        return []
    if isinstance(val, list):
        return [str(v) for v in val if v]
    try:
        parsed = json.loads(val)
        return [str(v) for v in parsed if v]
    except Exception:
        return [val] if val else []
