"""Upload service — file persistence, DB records, and background pipeline execution."""

import hashlib
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import UploadFile

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent.parent
UPLOAD_DIR = ROOT / os.getenv("UPLOAD_DIR", "data/uploads")


def safe_json_loads(v, default=None):
    if default is None:
        default = {}
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


# ── File I/O ──────────────────────────────────────────────────────────────────

async def save_upload_file(
    file: UploadFile,
    upload_id: str,
) -> tuple[Path, str, int]:
    """Save the uploaded file to disk. Returns (saved_path, sha256_hex, size_bytes)."""
    dest_dir = UPLOAD_DIR / upload_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    safe_name = Path(file.filename).name if file.filename else "upload.bin"
    dest_path = dest_dir / safe_name

    hasher = hashlib.sha256()
    size   = 0

    with open(dest_path, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)  # 1 MB chunks
            if not chunk:
                break
            hasher.update(chunk)
            out.write(chunk)
            size += len(chunk)

    return dest_path, hasher.hexdigest(), size


# ── DB record helpers ─────────────────────────────────────────────────────────

def create_upload_record(
    conn: sqlite3.Connection,
    upload_id: str,
    filename: str,
    original_filename: str,
    sha256: str,
    scanner_type: str,
    file_size: int,
    uploaded_by: str,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO uploads
               (id, filename, original_filename, sha256, scanner_type,
                file_size, uploaded_by, uploaded_at, status, pipeline_triggered)
           VALUES (?,?,?,?,?,?,?,?,'queued',0)""",
        (upload_id, filename, original_filename, sha256, scanner_type, file_size, uploaded_by, now),
    )
    conn.commit()

    return {
        "id":                upload_id,
        "filename":          filename,
        "original_filename": original_filename,
        "sha256":            sha256,
        "scanner_type":      scanner_type,
        "file_size":         file_size,
        "uploaded_by":       uploaded_by,
        "uploaded_at":       now,
        "status":            "queued",
        "pipeline_triggered": 0,
    }


def update_upload_status(
    conn: sqlite3.Connection,
    upload_id: str,
    status: str,
    stats_json: dict | None = None,
    error_message: str | None = None,
) -> None:
    params: list = [status]
    set_parts = ["status = ?"]

    if stats_json is not None:
        set_parts.append("stats_json = ?")
        params.append(json.dumps(stats_json))
    if error_message is not None:
        set_parts.append("error_message = ?")
        params.append(error_message)

    params.append(upload_id)
    conn.execute(
        f"UPDATE uploads SET {', '.join(set_parts)} WHERE id = ?",
        params,
    )
    conn.commit()


# ── Auto-detection helper ─────────────────────────────────────────────────────

def _detect_scanner_type(file_path: Path) -> str:
    """Attempt to detect scanner type from file extension and content."""
    suffix = file_path.suffix.lower()
    if suffix == ".xml":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(2048)
            if "NessusClientData" in head or "nessus" in head.lower():
                return "nessus"
            if "openvas" in head.lower() or "gvm" in head.lower():
                return "openvas"
        except Exception:
            pass
        return "nessus"  # default XML → nessus
    return "csv_generic"


# ── Background pipeline ───────────────────────────────────────────────────────

def run_upload_pipeline(
    upload_id: str,
    file_path: str,
    scanner_type: str,
    db_path: str,
) -> None:
    """
    Full upload processing pipeline.  Runs in a FastAPI BackgroundTask.

    Steps:
      1. Update status → parsing
      2. Parse file with appropriate adapter
      3. Merge with asset inventory (if present)
      4. Enrich: KEV + EPSS lookups from cache (no network calls)
      5. Risk scoring
      6. Build remediation jobs and upsert
      7. Compute diff stats
      8. Update upload record → done / failed
    """
    import sqlite3 as _sqlite3

    def _get_conn() -> _sqlite3.Connection:
        _conn = _sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        _conn.row_factory = _sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.execute("PRAGMA synchronous=NORMAL;")
        _conn.execute("PRAGMA foreign_keys=ON;")
        return _conn

    conn = _get_conn()

    try:
        # ── Step 1: mark as parsing ──────────────────────────────────────────
        update_upload_status(conn, upload_id, "parsing")

        fpath = Path(file_path)
        effective_scanner = scanner_type
        if effective_scanner == "auto":
            effective_scanner = _detect_scanner_type(fpath)

        # ── Step 2: load asset inventory FROM SQLITE (then fallback to CSV) ──
        import pandas as pd

        asset_df = _load_assets_from_db(conn)
        if asset_df is None or asset_df.empty:
            csv_path = ROOT / "data" / "input" / "asset_inventory.csv"
            if csv_path.exists():
                try:
                    asset_df = pd.read_csv(csv_path, dtype=str).fillna("")
                except Exception as exc:
                    logger.warning("upload_pipeline: could not load asset CSV — %s", exc)

        update_upload_status(conn, upload_id, "ingesting")
        df_raw = _parse_file(fpath, effective_scanner, asset_inventory=asset_df)

        # ── Step 3: merge asset metadata onto findings ───────────────────────
        if asset_df is not None and not asset_df.empty:
            asset_cols = [c for c in ("business_owner", "business_unit", "criticality",
                                      "environment", "internet_exposed") if c in asset_df.columns]
            join_keys = []
            if "asset_id" in df_raw.columns and "asset_id" in asset_df.columns:
                join_keys.append("asset_id")
            if "hostname" in df_raw.columns and "hostname" in asset_df.columns:
                join_keys.append("hostname")

            if asset_cols and join_keys:
                # Try asset_id first, then hostname, take whichever gives non-null values
                merged = df_raw.copy()
                for key in join_keys:
                    if key not in asset_df.columns:
                        continue
                    rhs_cols = [key] + [c for c in asset_cols if c in asset_df.columns]
                    tmp = merged.merge(
                        asset_df[rhs_cols].drop_duplicates(subset=[key]),
                        on=key, how="left", suffixes=("", f"_{key}"),
                    )
                    for col in asset_cols:
                        suf = f"{col}_{key}"
                        if suf in tmp.columns:
                            if col in tmp.columns:
                                tmp[col] = tmp[col].where(tmp[col].astype(str).str.len() > 0, tmp[suf])
                            else:
                                tmp[col] = tmp[suf]
                            tmp.drop(columns=[suf], inplace=True, errors="ignore")
                    merged = tmp
                df_raw = merged

        # ── Step 4: enrichment from local cache ──────────────────────────────
        update_upload_status(conn, upload_id, "enriching")
        # First: auto-fetch EPSS for any CVE we don't already have
        _auto_fetch_epss_for_new_cves(df_raw)
        df_enriched = _enrich_from_cache(df_raw)

        # ── Step 5: risk scoring ─────────────────────────────────────────────
        update_upload_status(conn, upload_id, "scoring")
        df_scored = _apply_scoring(df_enriched)

        # ── Step 6: build jobs and upsert ────────────────────────────────────
        update_upload_status(conn, upload_id, "building_jobs")
        new_jobs, updated_jobs = _upsert_jobs_from_df(conn, df_scored)

        # ── Step 7: compute diff stats ───────────────────────────────────────
        total_cves    = int(df_scored["cve_id"].str.startswith("CVE-", na=False).sum())
        total_assets  = int(df_scored["asset_id"].nunique()) if "asset_id" in df_scored.columns else 0

        stats = {
            "new_jobs":                new_jobs,
            "updated_jobs":            updated_jobs,
            "total_cve_count":         total_cves,
            "total_asset_count":       total_assets,
            "scanner_type":            effective_scanner,
        }

        update_upload_status(conn, upload_id, "done", stats_json=stats)
        logger.info("upload_pipeline: upload %s done — %s", upload_id, stats)

    except Exception as exc:
        logger.error("upload_pipeline: upload %s FAILED — %s", upload_id, exc, exc_info=True)
        try:
            update_upload_status(conn, upload_id, "failed", error_message=str(exc))
        except Exception:
            pass
    finally:
        conn.close()


# ── Internal pipeline helpers ─────────────────────────────────────────────────

def _parse_file(file_path: Path, scanner_type: str, asset_inventory=None):
    """Parse file using the appropriate adapter. Returns normalised DataFrame."""
    import pandas as pd

    if scanner_type == "nessus":
        from ingestion.adapters.nessus import NessusAdapter
        return NessusAdapter().parse(file_path)
    if scanner_type == "openvas":
        from ingestion.adapters.openvas import OpenVASAdapter
        return OpenVASAdapter().parse(file_path)
    if scanner_type == "csv_generic":
        from ingestion.adapters.csv_generic import CSVGenericAdapter
        return CSVGenericAdapter().parse(file_path, asset_inventory=asset_inventory)

    # Fallback: try CSV generic
    try:
        from ingestion.adapters.csv_generic import CSVGenericAdapter
        return CSVGenericAdapter().parse(file_path, asset_inventory=asset_inventory)
    except Exception:
        return pd.read_csv(file_path, dtype=str).fillna("")


def _load_assets_from_db(conn):
    """Load asset inventory from the main SQLite DB as a DataFrame."""
    import pandas as pd
    try:
        rows = conn.execute(
            "SELECT asset_id, hostname, ip_address, business_owner, business_unit, "
            "criticality, environment, internet_exposed FROM assets"
        ).fetchall()
        if not rows:
            return None
        records = [dict(r) for r in rows]
        for r in records:
            r["internet_exposed"] = "true" if r.get("internet_exposed") else "false"
        df = pd.DataFrame(records).fillna("")
        return df
    except Exception as exc:
        logger.warning("Could not load assets from DB: %s", exc)
        return None


def _auto_fetch_epss_for_new_cves(df) -> None:
    """For each CVE in df that has no EPSS in the cache, fetch it from FIRST.

    Non-blocking on failure — never raises. Configurable via ENRICH_AUTO_FETCH_EPSS
    env var (default true).
    """
    import os
    if os.getenv("ENRICH_AUTO_FETCH_EPSS", "true").lower() not in ("1", "true", "yes"):
        return
    if "cve_id" not in df.columns:
        return

    try:
        cve_ids = [c for c in df["cve_id"].dropna().unique()
                   if isinstance(c, str) and c.startswith("CVE-")]
        if not cve_ids:
            return

        # Filter out CVEs already cached (fresh)
        cache_db = ROOT / "data" / "cache" / "enrichment.db"
        to_fetch = cve_ids
        if cache_db.exists():
            import sqlite3 as _sq
            cache_conn = _sq.connect(str(cache_db), timeout=10)
            cache_conn.row_factory = _sq.Row
            try:
                placeholders = ",".join("?" * len(cve_ids))
                rows = cache_conn.execute(
                    f"SELECT cve_id FROM cve_context WHERE epss_score IS NOT NULL "
                    f"AND cve_id IN ({placeholders})",
                    cve_ids,
                ).fetchall()
                already = {r["cve_id"] for r in rows}
                to_fetch = [c for c in cve_ids if c not in already]
            finally:
                cache_conn.close()

        if not to_fetch:
            logger.info("EPSS auto-fetch: all %d CVEs already cached.", len(cve_ids))
            return

        logger.info("EPSS auto-fetch: %d new CVEs to enrich.", len(to_fetch))
        from enrichment.epss_ingest import enrich_epss
        enrich_epss(to_fetch)
    except Exception as exc:
        logger.warning("EPSS auto-fetch failed (non-fatal): %s", exc)


def _enrich_from_cache(df):
    """Apply KEV and EPSS enrichment from the local SQLite cache — no network calls.

    Reads from data/cache/enrichment.db (populated by enrichment/kev_ingest.py
    and enrichment/epss_ingest.py). Both feeds share table cve_context.
    """
    import pandas as pd

    cache_db = ROOT / "data" / "cache" / "enrichment.db"
    if not cache_db.exists():
        logger.info("Cache enrichment skipped: %s does not exist (run kev_ingest first).", cache_db)
        return df

    try:
        import sqlite3 as _sq
        cache_conn = _sq.connect(str(cache_db), check_same_thread=False, timeout=10)
        cache_conn.row_factory = _sq.Row

        if "cve_id" in df.columns:
            try:
                rows = cache_conn.execute(
                    "SELECT cve_id, kev_flag, epss_score FROM cve_context"
                ).fetchall()
                if rows:
                    ctx_df = pd.DataFrame([dict(r) for r in rows])
                    df = df.merge(ctx_df, on="cve_id", how="left", suffixes=("", "_ctx"))
                    # Coalesce
                    for col, default in (("kev_flag", 0), ("epss_score", 0.0)):
                        ctx_col = f"{col}_ctx"
                        if ctx_col in df.columns:
                            df[col] = df[ctx_col].fillna(df.get(col, default))
                            df.drop(columns=[ctx_col], inplace=True)
                        elif col not in df.columns:
                            df[col] = default
                    df["kev_flag"] = pd.to_numeric(df["kev_flag"], errors="coerce").fillna(0).astype(int)
                    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce").fillna(0.0)
                    logger.info("Cache enrichment: %d rows from cve_context (KEV+EPSS).", len(ctx_df))
            except Exception as exc:
                logger.warning("cve_context lookup failed: %s", exc)

        cache_conn.close()
    except Exception as exc:
        logger.warning("Cache enrichment failed: %s", exc)

    return df


def _apply_scoring(df):
    """Run the risk scoring engine."""
    try:
        import yaml
        from enrichment.score_engine import apply_risk_scoring

        policy_path = ROOT / "config" / "policy.yaml"
        if policy_path.exists():
            with open(policy_path) as fh:
                policy = yaml.safe_load(fh)
            return apply_risk_scoring(df, policy)
    except Exception as exc:
        logger.warning("Risk scoring skipped: %s", exc)

    return df


def _upsert_jobs_from_df(conn, df) -> tuple[int, int]:
    """Build remediation jobs from scored DataFrame and upsert them. Returns (new, updated)."""
    import sqlite3 as _sq

    try:
        import yaml
        from remediation.build_remediation_jobs import build_remediation_jobs

        policy_path = ROOT / "config" / "policy.yaml"
        policy: dict = {}
        if policy_path.exists():
            with open(policy_path) as fh:
                policy = yaml.safe_load(fh)

        jobs_df = build_remediation_jobs(df, policy)
        if jobs_df.empty:
            return 0, 0

        from api.repositories.jobs_repo import get_job_by_fingerprint, upsert_job

        new_count = updated_count = 0
        for _, row in jobs_df.iterrows():
            job_data = {k: (None if str(v) in ("", "nan", "NaN") else v) for k, v in row.items()}
            fp = job_data.get("job_fingerprint")
            if fp and get_job_by_fingerprint(conn, fp):
                updated_count += 1
            else:
                new_count += 1
            upsert_job(conn, job_data)

        return new_count, updated_count

    except Exception as exc:
        logger.error("Job upsert failed: %s", exc, exc_info=True)
        raise
