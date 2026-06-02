"""Threat-exposure matching service (P4b).

Legitimate sources only:
  - NVD API v2  → CPE-to-CVE lookup (cached in cpe_cve_cache)
  - enrichment.db cve_context → KEV flag + EPSS score
  - OSV.dev API → package-based CVE lookup (no CPE needed)
  - HIBP Domain API → breach-notification opt-in (stub if no API key)

No forum / dark-web crawling. All outbound calls hit official public APIs.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

NVD_API         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API         = "https://api.osv.dev/v1/query"
HIBP_DOMAIN_API = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
NVD_DELAY       = 0.7   # free-tier: ~50 req/30s without key
CPE_CACHE_TTL   = 30    # days before re-fetching a CPE from NVD

HIGH_EPSS_THRESHOLD = 0.4   # >= 40 % exploitation probability → high-epss alert

ROOT    = Path(__file__).parent.parent.parent.parent
ENRICH_DB_PATH = ROOT / os.getenv("ENRICHMENT_DB_PATH", "data/cache/enrichment.db")


# ── Enrichment DB helper ──────────────────────────────────────────────────────

def _enrich_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(ENRICH_DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _get_cve_context(enrich: sqlite3.Connection, cve_id: str) -> dict:
    row = enrich.execute(
        "SELECT kev_flag, epss_score, epss_percentile FROM cve_context WHERE cve_id = ?",
        (cve_id,),
    ).fetchone()
    return dict(row) if row else {}


# ── NVD CPE→CVE lookup (with local cache) ────────────────────────────────────

def _is_cache_fresh(conn: sqlite3.Connection, cpe: str) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=CPE_CACHE_TTL)).isoformat()
    row = conn.execute(
        "SELECT MIN(cached_at) FROM cpe_cve_cache WHERE cpe = ?", (cpe,)
    ).fetchone()
    return bool(row and row[0] and row[0] > cutoff)


def _cache_cpe_cves(conn: sqlite3.Connection, cpe: str, cves: list[dict]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for entry in cves:
        conn.execute(
            """INSERT OR REPLACE INTO cpe_cve_cache (cpe, cve_id, severity, cached_at)
               VALUES (?, ?, ?, ?)""",
            (cpe, entry["cve_id"], entry.get("severity"), now),
        )
    conn.commit()


def _load_cached_cves(conn: sqlite3.Connection, cpe: str) -> list[dict]:
    rows = conn.execute(
        "SELECT cve_id, severity FROM cpe_cve_cache WHERE cpe = ?", (cpe,)
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_nvd_by_cpe(conn: sqlite3.Connection, cpe: str) -> list[dict]:
    """Return list of {cve_id, severity} matching the CPE.

    Uses local cache first; falls back to NVD API if stale or absent.
    """
    if _is_cache_fresh(conn, cpe):
        cached = _load_cached_cves(conn, cpe)
        if cached:
            logger.debug("CPE cache hit: %s (%d CVEs)", cpe, len(cached))
            return cached

    logger.info("Querying NVD for CPE: %s", cpe)
    try:
        params: dict = {"cpeName": cpe, "resultsPerPage": 100}
        nvd_key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": nvd_key} if nvd_key else {}
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        time.sleep(NVD_DELAY)

        results = []
        for vuln in data.get("vulnerabilities", []):
            cve_obj = vuln.get("cve", {})
            cve_id  = cve_obj.get("id", "")
            if not cve_id:
                continue
            # Extract base severity
            metrics = cve_obj.get("metrics", {})
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    severity = entries[0].get("cvssData", {}).get("baseSeverity")
                    break
            results.append({"cve_id": cve_id, "severity": severity})

        _cache_cpe_cves(conn, cpe, results)
        return results

    except requests.exceptions.RequestException as exc:
        logger.warning("NVD CPE lookup failed for %s: %s", cpe, exc)
        # Return whatever is in cache even if stale
        return _load_cached_cves(conn, cpe)


# ── OSV package-based lookup ──────────────────────────────────────────────────

def fetch_osv_by_package(product: str, ecosystem: str = "") -> list[str]:
    """Return CVE IDs from OSV.dev for a given package name.

    ecosystem examples: PyPI, npm, Maven, Go, RubyGems, NuGet, Packagist, crates.io
    Leave empty to search across all ecosystems.
    """
    payload: dict = {"package": {"name": product}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        resp = requests.post(OSV_API, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        cve_ids = []
        for vuln in data.get("vulns", []):
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_ids.append(alias)
        return list(set(cve_ids))
    except requests.exceptions.RequestException as exc:
        logger.warning("OSV lookup failed for %s: %s", product, exc)
        return []


# ── Domain breach-notification check (HIBP) ──────────────────────────────────

def check_domain_breach(domain: str) -> dict:
    """Opt-in breach-notification check using HIBP Domain API.

    Requires HIBP_API_KEY environment variable.
    Only call for your OWN domain — never for third-party targets.
    Uses HIBP's aggregated breach-notification service (lawful, no raw stolen data).
    """
    api_key = os.getenv("HIBP_API_KEY", "")
    if not api_key:
        return {
            "domain":  domain,
            "status":  "stub",
            "message": "Set HIBP_API_KEY env var to enable domain breach-notification checks.",
            "breaches": [],
        }

    url = HIBP_DOMAIN_API.format(domain=domain)
    try:
        resp = requests.get(
            url,
            headers={
                "hibp-api-key": api_key,
                "user-agent": "VRA-ThreatExposure/1.0",
            },
            timeout=10,
        )
        if resp.status_code == 404:
            return {"domain": domain, "status": "clean", "breaches": []}
        resp.raise_for_status()
        breaches = resp.json()  # list of breach objects
        return {
            "domain":    domain,
            "status":    "breached" if breaches else "clean",
            "count":     len(breaches),
            "breaches":  breaches,
        }
    except requests.exceptions.RequestException as exc:
        logger.warning("HIBP domain check failed for %s: %s", domain, exc)
        return {"domain": domain, "status": "error", "message": str(exc), "breaches": []}


# ── OS-level KEV scan (for assets without software entries) ───────────────────

# Maps lower-case OS keywords → (kev_vendor_fragment, kev_product_fragment)
# Checked against enrichment.db cve_context(kev_vendor, kev_product)
_OS_KEV_MAP: list[tuple[str, str, str]] = [
    # (os_keyword, vendor_fragment, product_fragment)
    # Windows Server → broad Windows match (KEV stores "Windows" not "Windows Server 2022")
    ("windows server", "microsoft", "windows"),
    ("windows 11",     "microsoft", "windows"),
    ("windows 10",     "microsoft", "windows"),
    # Linux variants → Linux Kernel (KEV vendor="Linux", product="Kernel")
    ("ubuntu",              "linux",     "kernel"),
    ("debian",              "linux",     "kernel"),
    ("rhel",                "linux",     "kernel"),
    ("red hat enterprise",  "linux",     "kernel"),
    ("centos",              "linux",     "kernel"),
    ("almalinux",           "linux",     "kernel"),
    ("fedora",              "linux",     "kernel"),
    ("amazon linux",        "linux",     "kernel"),
    # macOS
    ("macos",               "apple",     "macos"),
    ("mac os",              "apple",     "macos"),
    # FreeBSD
    ("freebsd",             "freebsd",   "freebsd"),
    # VMware
    ("esxi",                "vmware",    "esxi"),
    # Network OS
    ("pan-os",              "palo alto", "pan-os"),
    ("fortios",             "fortinet",  "fortios"),
    ("ios xe",              "cisco",     "ios"),
    ("nx-os",               "cisco",     "ios"),
    ("junos",               "juniper",   "junos"),
    # ChromeOS
    ("chromeos",            "google",    "chrome"),
]

_OS_ALERT_LIMIT = 10   # max KEV alerts per asset via OS-scan (avoid noise)


def _scan_os_against_kev(
    conn: sqlite3.Connection,
    enrich: sqlite3.Connection,
    asset_id: Optional[str] = None,
) -> tuple[int, int]:
    """Scan assets' os_version against KEV catalog entries.

    Returns (new_alerts, updated_alerts).
    """
    from api.repositories import threat_alerts_repo

    # Pull assets that have an os_version (optionally filtered)
    if asset_id:
        rows = conn.execute(
            "SELECT asset_id, hostname, os_version FROM assets WHERE asset_id=? AND os_version IS NOT NULL",
            (asset_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT asset_id, hostname, os_version FROM assets WHERE os_version IS NOT NULL"
        ).fetchall()

    new_a = 0; upd_a = 0

    for asset_row in rows:
        aid     = asset_row["asset_id"]
        os_ver  = (asset_row["os_version"] or "").lower()

        cve_hits: list[dict] = []
        for os_kw, vendor_frag, product_frag in _OS_KEV_MAP:
            if os_kw not in os_ver:
                continue
            # Look up KEV entries matching this OS
            kev_rows = enrich.execute(
                """SELECT cve_id, epss_score, epss_percentile
                   FROM cve_context
                   WHERE kev_flag = 1
                     AND (LOWER(kev_vendor)  LIKE ? OR LOWER(kev_product) LIKE ?)
                   LIMIT ?""",
                (f"%{vendor_frag}%", f"%{product_frag}%", _OS_ALERT_LIMIT),
            ).fetchall()
            for r in kev_rows:
                cve_hits.append({
                    "cve_id":     r["cve_id"],
                    "epss_score": float(r["epss_score"] or 0.0),
                })
            break   # first matching OS keyword wins

        for hit in cve_hits[:_OS_ALERT_LIMIT]:
            try:
                result = threat_alerts_repo.upsert_alert(
                    conn,
                    asset_id        = aid,
                    cve_id          = hit["cve_id"],
                    source          = "kev_os_scan",
                    severity        = "CRITICAL",
                    epss_score      = hit["epss_score"],
                    is_kev          = True,
                    matched_cpe     = None,
                    matched_product = asset_row["os_version"],
                    matched_version = None,
                    alert_type      = "kev_match",
                )
                if result["created_at"] == result["updated_at"]:
                    new_a += 1
                else:
                    upd_a += 1
            except Exception as exc:
                logger.warning("OS-KEV alert upsert failed %s/%s: %s", aid, hit["cve_id"], exc)

    return new_a, upd_a


# ── Main matching orchestrator ────────────────────────────────────────────────

def run_threat_matching(
    conn: sqlite3.Connection,
    asset_id: Optional[str] = None,
    use_osv: bool = True,
    use_nvd: bool = True,
) -> dict:
    """Match asset software against NVD/OSV; generate threat_alerts rows.

    Args:
        conn:      platform.db connection (has asset_software, threat_alerts, cpe_cve_cache)
        asset_id:  limit to one asset if provided; None = scan all
        use_osv:   also query OSV.dev by product name (slower but catches more)
        use_nvd:   query NVD CPE match API (requires well-formed CPEs)

    Returns summary dict with counts.
    """
    from api.repositories import asset_software_repo, threat_alerts_repo

    if asset_id:
        sw_list = asset_software_repo.get_by_asset(conn, asset_id)
        # Attach hostname for logging
        for sw in sw_list:
            sw["asset_id"] = asset_id
    else:
        sw_list = asset_software_repo.get_all(conn)

    enrich = _enrich_conn()

    new_alerts    = 0
    updated_alerts = 0
    errors        = 0

    # Deduplicate: don't call NVD twice for the same CPE in one run
    cpe_cache: dict[str, list[dict]] = {}

    for sw in sw_list:
        aid     = sw["asset_id"]
        product = sw.get("product", "")
        version = sw.get("version", "")
        cpe     = sw.get("cpe", "")

        cve_candidates: list[dict] = []   # [{"cve_id": ..., "severity": ..., "source": ...}]

        # ── NVD CPE match ─────────────────────────────────────────────────────
        if use_nvd and cpe:
            if cpe not in cpe_cache:
                cpe_cache[cpe] = fetch_nvd_by_cpe(conn, cpe)
            for entry in cpe_cache[cpe]:
                cve_candidates.append({**entry, "source": "nvd", "matched_cpe": cpe})

        # ── OSV package match ─────────────────────────────────────────────────
        if use_osv and product:
            osv_cves = fetch_osv_by_package(product)
            for cve_id in osv_cves:
                if not any(c["cve_id"] == cve_id for c in cve_candidates):
                    cve_candidates.append({
                        "cve_id": cve_id, "severity": None,
                        "source": "osv", "matched_cpe": cpe or None,
                    })

        # ── Enrich each candidate + write alert ───────────────────────────────
        for candidate in cve_candidates:
            cve_id = candidate["cve_id"]
            try:
                ctx = _get_cve_context(enrich, cve_id)
                is_kev     = bool(ctx.get("kev_flag", 0))
                epss_score = float(ctx.get("epss_score") or 0.0)

                # Determine alert type (KEV > high-EPSS > plain CPE match)
                if is_kev:
                    alert_type = "kev_match"
                    severity   = "CRITICAL"
                elif epss_score >= HIGH_EPSS_THRESHOLD:
                    alert_type = "high_epss"
                    severity   = candidate.get("severity") or "HIGH"
                else:
                    alert_type = "cpe_match"
                    severity   = candidate.get("severity") or "MEDIUM"

                result = threat_alerts_repo.upsert_alert(
                    conn,
                    asset_id        = aid,
                    cve_id          = cve_id,
                    source          = candidate.get("source", "nvd"),
                    severity        = severity,
                    epss_score      = epss_score,
                    is_kev          = is_kev,
                    matched_cpe     = candidate.get("matched_cpe"),
                    matched_product = product,
                    matched_version = version,
                    alert_type      = alert_type,
                )
                # Distinguish new vs updated by created_at == updated_at
                if result["created_at"] == result["updated_at"]:
                    new_alerts += 1
                else:
                    updated_alerts += 1

            except Exception as exc:
                logger.error("Error processing %s / %s: %s", aid, cve_id, exc)
                errors += 1

    # ── OS-level KEV scan (catches assets with os_version but no software) ────
    os_new, os_upd = _scan_os_against_kev(conn, enrich, asset_id)
    new_alerts     += os_new
    updated_alerts += os_upd

    enrich.close()

    # Unique assets covered: software-bearing + OS-scanned
    sw_asset_ids  = {sw["asset_id"] for sw in sw_list}
    if asset_id:
        os_asset_ids = {asset_id}
    else:
        os_asset_ids = {
            r["asset_id"] for r in conn.execute(
                "SELECT asset_id FROM assets WHERE os_version IS NOT NULL"
            ).fetchall()
        }

    return {
        "assets_scanned":   len(sw_asset_ids | os_asset_ids),
        "software_entries": len(sw_list),
        "new_alerts":       new_alerts,
        "updated_alerts":   updated_alerts,
        "errors":           errors,
    }
