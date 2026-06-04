"""Database migrations — idempotent table creation, ALTER TABLE patches, and CSV seeding."""

import csv
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Use bcrypt directly (passlib 1.7.4 + bcrypt 4.x have a version-detection bug).
def _hash_password(plain: str) -> str:  # noqa: E302
    import bcrypt
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent.parent


# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_json_loads(v, default=None):
    if default is None:
        default = []
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cursor = conn.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cursor.fetchall()]
    return column in cols


# ── Table creation ────────────────────────────────────────────────────────────

def _create_tables(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id        TEXT PRIMARY KEY,
            hostname        TEXT,
            ip_address      TEXT,
            business_owner  TEXT,
            business_unit   TEXT,
            criticality     TEXT,
            environment     TEXT,
            internet_exposed INTEGER DEFAULT 0,
            created_at      TEXT,
            updated_at      TEXT,
            -- P4a fleet fields (added via ALTER TABLE if missing)
            os_version      TEXT,
            site            TEXT,
            owning_team     TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id               TEXT PRIMARY KEY,
            job_fingerprint      TEXT UNIQUE,
            asset_ids            TEXT,
            cve_list             TEXT,
            main_product         TEXT,
            plugin_family        TEXT,
            max_risk_level       TEXT,
            risk_score_max       REAL,
            business_owner       TEXT,
            business_unit        TEXT,
            environment          TEXT,
            kev_present          INTEGER DEFAULT 0,
            kev_cves             TEXT,
            affected_asset_count INTEGER,
            cve_count            INTEGER,
            score_breakdown      TEXT,
            sla_days             INTEGER,
            created_at           TEXT,
            due_date             TEXT,
            status               TEXT DEFAULT 'TO_DO',
            triage_decision      TEXT,
            assigned_team        TEXT,
            closed_at            TEXT,
            fixed_at             TEXT,
            updated_at           TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS job_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id      TEXT REFERENCES jobs(job_id),
            event_type  TEXT,
            old_status  TEXT,
            new_status  TEXT,
            changed_by  TEXT,
            comment     TEXT,
            created_at  TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS llm_advice (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id              TEXT REFERENCES jobs(job_id),
            cve_hash            TEXT,
            product             TEXT,
            recommendation_json TEXT,
            model_name          TEXT,
            prompt_tokens       INTEGER,
            response_tokens     INTEGER,
            latency_ms          INTEGER,
            feedback            INTEGER DEFAULT 0,
            created_at          TEXT,
            -- AI layer extension (2025-05-24)
            interaction_type    TEXT    DEFAULT 'recommendation',
            question            TEXT,
            citations_json      TEXT,
            disposition         TEXT,
            feedback_note       TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ticket_links (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id     TEXT REFERENCES jobs(job_id),
            provider   TEXT,
            ticket_id  TEXT,
            ticket_url TEXT,
            created_at TEXT,
            synced_at  TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id                  TEXT PRIMARY KEY,
            filename            TEXT,
            original_filename   TEXT,
            sha256              TEXT,
            scanner_type        TEXT,
            file_size           INTEGER,
            uploaded_by         TEXT,
            uploaded_at         TEXT,
            status              TEXT DEFAULT 'queued',
            stats_json          TEXT,
            error_message       TEXT,
            pipeline_triggered  INTEGER DEFAULT 0
        )
    """)

    # ── RBAC: users ───────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL CHECK(role IN (
                              'admin', 'analyst', 'remediation_owner',
                              'risk_owner', 'auditor')),
            active        INTEGER DEFAULT 1,
            created_at    TEXT
        )
    """)

    # ── P4a: software inventory ───────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_software (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id    TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
            product     TEXT NOT NULL,
            version     TEXT,
            vendor      TEXT,
            cpe         TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uidx_asset_software
        ON asset_software(asset_id, product, version)
    """)

    # ── P4b: threat alerts + CPE-CVE match cache ──────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id        TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
            cve_id          TEXT NOT NULL,
            source          TEXT NOT NULL DEFAULT 'nvd',
            severity        TEXT,
            epss_score      REAL DEFAULT 0,
            is_kev          INTEGER DEFAULT 0,
            matched_cpe     TEXT,
            matched_product TEXT,
            matched_version TEXT,
            alert_type      TEXT NOT NULL
                                CHECK(alert_type IN ('cpe_match','kev_match','high_epss')),
            status          TEXT NOT NULL DEFAULT 'open'
                                CHECK(status IN ('open','dismissed','resolved')),
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uidx_threat_alert
        ON threat_alerts(asset_id, cve_id)
    """)
    # Performance indexes — used by every list/filter/sort query
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ta_status          ON threat_alerts(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ta_status_kev      ON threat_alerts(status, is_kev)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ta_status_epss     ON threat_alerts(status, epss_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ta_alert_type      ON threat_alerts(alert_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ta_asset           ON threat_alerts(asset_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created_at    ON jobs(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status        ON jobs(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_risk          ON jobs(max_risk_level)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS cpe_cve_cache (
            cpe         TEXT NOT NULL,
            cve_id      TEXT NOT NULL,
            severity    TEXT,
            cached_at   TEXT NOT NULL,
            PRIMARY KEY (cpe, cve_id)
        )
    """)

    # ── P2: risk acceptances ──────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS risk_acceptances (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id                TEXT NOT NULL REFERENCES jobs(job_id),
            accepted_by           TEXT NOT NULL,
            justification         TEXT NOT NULL,
            compensating_controls TEXT,
            expiry_date           TEXT,
            review_trigger        TEXT,
            status                TEXT NOT NULL DEFAULT 'active'
                                      CHECK(status IN ('active', 'expired', 'superseded')),
            created_at            TEXT NOT NULL
        )
    """)

    # ── P2: workaround records ────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS workaround_records (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id              TEXT NOT NULL REFERENCES jobs(job_id),
            control_description TEXT NOT NULL,
            followup_date       TEXT,
            recorded_by         TEXT NOT NULL,
            created_at          TEXT NOT NULL
        )
    """)

    # ── Compliance control mapping ────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS control_catalog (
            control_id    TEXT PRIMARY KEY,
            framework     TEXT NOT NULL,
            name          TEXT NOT NULL,
            description   TEXT,
            objective     TEXT,
            vra_features  TEXT,
            deep_links    TEXT,
            is_supporting INTEGER DEFAULT 0,
            loaded_at     TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS job_controls (
            job_id      TEXT NOT NULL REFERENCES jobs(job_id)            ON DELETE CASCADE,
            control_id  TEXT NOT NULL REFERENCES control_catalog(control_id) ON DELETE CASCADE,
            tagged_by   TEXT,
            tagged_at   TEXT NOT NULL,
            PRIMARY KEY (job_id, control_id)
        )
    """)

    # ── Findings audit table (ingest_method tracking) ────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id              TEXT PRIMARY KEY,
            upload_id       TEXT REFERENCES uploads(id),
            cve_id          TEXT,
            hostname        TEXT,
            component       TEXT,
            severity        TEXT,
            ingest_method   TEXT NOT NULL DEFAULT 'structured',
            state           TEXT NOT NULL DEFAULT 'NEW',
            created_at      TEXT NOT NULL
        )
    """)

    # ── Service graph (Prompt #8) ─────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            owner_id    TEXT,
            description TEXT,
            created_at  TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS asset_services (
            asset_id    TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
            service_id  TEXT NOT NULL REFERENCES services(id)    ON DELETE CASCADE,
            PRIMARY KEY (asset_id, service_id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS service_dependencies (
            parent_service_id  TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
            child_service_id   TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
            dep_type           TEXT DEFAULT 'depends_on',
            PRIMARY KEY (parent_service_id, child_service_id)
        )
    """)

    # ── Auto-triage agent output ──────────────────────────────────────────────
    # One row per finding (latest wins via INSERT OR REPLACE).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auto_triage (
            finding_id     TEXT PRIMARY KEY REFERENCES findings(id),
            triage_class   TEXT NOT NULL CHECK (triage_class IN (
                               'likely_false_positive',
                               'likely_valid',
                               'needs_investigation')),
            confidence     REAL NOT NULL,
            justification  TEXT NOT NULL,
            model_version  TEXT NOT NULL,
            created_at     TEXT NOT NULL
        )
    """)

    # ── Finding lifecycle events (audit trail for triage agent) ───────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            actor       TEXT NOT NULL DEFAULT 'system',
            detail      TEXT,
            created_at  TEXT NOT NULL
        )
    """)

    # ── Chat with Finding (feat/chat-with-finding) ────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id           TEXT PRIMARY KEY,
            job_id       TEXT NOT NULL REFERENCES jobs(job_id),
            started_by   TEXT NOT NULL,
            started_at   TEXT NOT NULL,
            title        TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversation_turns (
            id                  TEXT PRIMARY KEY,
            conversation_id     TEXT NOT NULL REFERENCES conversations(id),
            role                TEXT NOT NULL CHECK (role IN ('user','assistant','partial')),
            content             TEXT NOT NULL,
            retrieved_docs_json TEXT,
            created_at          TEXT NOT NULL
        )
    """)

    # ── Alert → Job promotion link ────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_jobs (
            alert_id    INTEGER NOT NULL REFERENCES threat_alerts(id) ON DELETE CASCADE,
            job_id      TEXT    NOT NULL REFERENCES jobs(job_id)       ON DELETE CASCADE,
            created_at  TEXT    NOT NULL,
            PRIMARY KEY (alert_id, job_id)
        )
    """)

    # ── Prompt #9: executive PDF reports ─────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS exec_reports (
            id              TEXT PRIMARY KEY,
            created_at      TEXT NOT NULL,
            created_by      TEXT NOT NULL,
            period_start    TEXT NOT NULL,
            period_end      TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            summary_text    TEXT,
            summary_source  TEXT,
            pdf_path        TEXT,
            error_message   TEXT,
            metadata_json   TEXT
        )
    """)

    conn.commit()


# ── ALTER TABLE patches ───────────────────────────────────────────────────────

def _alter_tables(conn: sqlite3.Connection) -> None:
    """Add columns that may be missing from tables created by older schema versions."""
    jobs_patches = [
        ("score_breakdown",  "TEXT"),
        ("job_fingerprint",  "TEXT"),
        ("triage_decision",  "TEXT"),
        ("assigned_team",    "TEXT"),
        ("closed_at",        "TEXT"),
        ("fixed_at",         "TEXT"),
        ("updated_at",       "TEXT"),
        # P2: SLA pause tracking + lifecycle free-text note
        ("sla_paused_at",    "TEXT"),
        ("sla_paused_days",  "INTEGER DEFAULT 0"),
        ("lifecycle_note",   "TEXT"),
        # custom SLA override (days)
        ("sla_override_days", "INTEGER"),
    ]

    for col_name, col_type in jobs_patches:
        if not _column_exists(conn, "jobs", col_name):
            try:
                conn.execute(f"ALTER TABLE jobs ADD COLUMN {col_name} {col_type}")
                conn.commit()
                logger.info("migrate: added jobs.%s", col_name)
            except sqlite3.OperationalError as exc:
                logger.warning("migrate: could not add jobs.%s — %s", col_name, exc)

    # P4a: new fleet columns on assets
    assets_patches = [
        ("os_version",  "TEXT"),
        ("site",        "TEXT"),
        ("owning_team", "TEXT"),
        # asset type + platform for cascade dropdowns
        ("asset_type",  "TEXT"),
        ("platform",    "TEXT"),
    ]
    for col_name, col_type in assets_patches:
        if not _column_exists(conn, "assets", col_name):
            try:
                conn.execute(f"ALTER TABLE assets ADD COLUMN {col_name} {col_type}")
                conn.commit()
                logger.info("migrate: added assets.%s", col_name)
            except sqlite3.OperationalError as exc:
                logger.warning("migrate: could not add assets.%s — %s", col_name, exc)

    # LLM ingest — parser_used on uploads
    uploads_patches = [
        ("parser_used", "TEXT DEFAULT 'structured'"),
    ]
    for col_name, col_type in uploads_patches:
        if not _column_exists(conn, "uploads", col_name):
            try:
                conn.execute(f"ALTER TABLE uploads ADD COLUMN {col_name} {col_type}")
                conn.commit()
                logger.info("migrate: added uploads.%s", col_name)
            except sqlite3.OperationalError as exc:
                logger.warning("migrate: could not add uploads.%s — %s", col_name, exc)

    # LLM ingest + auto-triage — new columns on findings
    findings_patches = [
        ("ingest_method", "TEXT NOT NULL DEFAULT 'structured'"),
        ("state",         "TEXT NOT NULL DEFAULT 'NEW'"),
    ]
    for col_name, col_type in findings_patches:
        try:
            if not _column_exists(conn, "findings", col_name):
                conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}"
                )
                conn.commit()
                logger.info("migrate: added findings.%s", col_name)
        except sqlite3.OperationalError as exc:
            logger.warning("migrate: could not patch findings.%s — %s", col_name, exc)

    # AI layer extension — new columns on llm_advice
    llm_advice_patches = [
        ("interaction_type", "TEXT DEFAULT 'recommendation'"),
        ("question",         "TEXT"),
        ("citations_json",   "TEXT"),
        ("disposition",      "TEXT"),
        ("feedback_note",    "TEXT"),
    ]
    for col_name, col_type in llm_advice_patches:
        if not _column_exists(conn, "llm_advice", col_name):
            try:
                conn.execute(
                    f"ALTER TABLE llm_advice ADD COLUMN {col_name} {col_type}"
                )
                conn.commit()
                logger.info("migrate: added llm_advice.%s", col_name)
            except sqlite3.OperationalError as exc:
                logger.warning(
                    "migrate: could not add llm_advice.%s — %s", col_name, exc
                )


# ── CSV seeding ───────────────────────────────────────────────────────────────

def _seed_jobs(conn: sqlite3.Connection) -> int:
    csv_path = ROOT / "data" / "output" / "remediation_jobs.csv"
    if not csv_path.exists():
        return 0

    row_count = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    if row_count > 0:
        return 0

    count = 0
    now = datetime.now(timezone.utc).isoformat()

    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                job = {k: (v if v != "" else None) for k, v in row.items()}

                # Ensure required key exists
                if not job.get("job_id"):
                    job["job_id"] = str(uuid.uuid4())

                # Numeric coercions
                for f in ("sla_days", "affected_asset_count", "cve_count"):
                    if job.get(f) is not None:
                        try:
                            job[f] = int(float(job[f]))
                        except (ValueError, TypeError):
                            job[f] = None

                if job.get("risk_score_max") is not None:
                    try:
                        job["risk_score_max"] = float(job["risk_score_max"])
                    except (ValueError, TypeError):
                        job["risk_score_max"] = None

                if job.get("kev_present") is not None:
                    try:
                        job["kev_present"] = int(float(job["kev_present"]))
                    except (ValueError, TypeError):
                        job["kev_present"] = 0

                job.setdefault("status", "TO_DO")
                job.setdefault("created_at", now)
                job.setdefault("updated_at", now)

                cols = [
                    "job_id", "job_fingerprint", "asset_ids", "cve_list", "main_product",
                    "plugin_family", "max_risk_level", "risk_score_max", "business_owner",
                    "business_unit", "environment", "kev_present", "kev_cves",
                    "affected_asset_count", "cve_count", "score_breakdown", "sla_days",
                    "created_at", "due_date", "status", "triage_decision", "assigned_team",
                    "closed_at", "fixed_at", "updated_at",
                    "sla_paused_at", "sla_paused_days", "lifecycle_note",
                ]
                present = {c: job.get(c) for c in cols}
                col_list = ", ".join(present.keys())
                placeholders = ", ".join("?" * len(present))
                conn.execute(
                    f"INSERT OR IGNORE INTO jobs ({col_list}) VALUES ({placeholders})",
                    list(present.values()),
                )
                count += 1

        conn.commit()
        logger.info("migrate: seeded %d jobs from %s", count, csv_path)
    except Exception as exc:
        logger.error("migrate: job seeding failed — %s", exc)

    return count


def _seed_assets(conn: sqlite3.Connection) -> int:
    csv_path = ROOT / "data" / "input" / "asset_inventory.csv"
    if not csv_path.exists():
        return 0

    row_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    if row_count > 0:
        return 0

    count = 0
    now = datetime.now(timezone.utc).isoformat()

    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                asset_id = (
                    row.get("asset_id")
                    or row.get("hostname")
                    or f"ASSET-{count}"
                )
                internet_exposed = int(
                    str(row.get("internet_exposed", "0")).strip().lower()
                    in ("1", "true", "yes", "y")
                )
                conn.execute(
                    """INSERT OR IGNORE INTO assets
                       (asset_id, hostname, ip_address, business_owner, business_unit,
                        criticality, environment, internet_exposed, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        asset_id,
                        row.get("hostname", ""),
                        row.get("ip_address", row.get("ip", "")),
                        row.get("business_owner", ""),
                        row.get("business_unit", ""),
                        row.get("criticality", ""),
                        row.get("environment", ""),
                        internet_exposed,
                        row.get("created_at", now),
                        now,
                    ),
                )
                count += 1

        conn.commit()
        logger.info("migrate: seeded %d assets from %s", count, csv_path)
    except Exception as exc:
        logger.error("migrate: asset seeding failed — %s", exc)

    return count


# ── User seeding ──────────────────────────────────────────────────────────────

# Demo credentials — one per role.  Change passwords before any real deployment.
_DEMO_USERS = [
    ("admin",             "Admin1234!",      "admin"),
    ("analyst",           "Analyst1234!",    "analyst"),
    ("remediation_owner", "RemOwner1234!",   "remediation_owner"),
    ("risk_owner",        "RiskOwner1234!",  "risk_owner"),
    ("auditor",           "Auditor1234!",    "auditor"),
]


def _seed_users(conn: sqlite3.Connection) -> int:
    """Insert demo users if the table is empty. Skips individual rows that already exist."""
    existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing > 0:
        return 0

    now = datetime.now(timezone.utc).isoformat()
    count = 0
    try:
        for username, plain_password, role in _DEMO_USERS:
            password_hash = _hash_password(plain_password)
            conn.execute(
                """INSERT OR IGNORE INTO users (username, password_hash, role, active, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (username, password_hash, role, now),
            )
            count += 1
        conn.commit()
        logger.info("migrate: seeded %d demo users.", count)
    except Exception as exc:
        logger.error("migrate: user seeding failed — %s", exc)
    return count


# ── Public entry point ────────────────────────────────────────────────────────

def run_migrations(conn: sqlite3.Connection) -> None:
    """Run all migrations in order. Safe to call multiple times.

    Set env var  VRA_SKIP_SEED=true  to skip job and asset CSV seeding while
    still creating all tables and seeding the demo user accounts.  Used by the
    demo instance (start_demo.bat) so the DB starts completely empty.
    """
    import os
    skip_seed = os.getenv("VRA_SKIP_SEED", "false").lower() == "true"
    logger.info("migrate: starting… (skip_seed=%s)", skip_seed)

    _create_tables(conn)
    _alter_tables(conn)

    if not skip_seed:
        try:
            _seed_jobs(conn)
        except Exception as exc:
            logger.warning("migrate: job seeding skipped — %s", exc)

        try:
            _seed_assets(conn)
        except Exception as exc:
            logger.warning("migrate: asset seeding skipped — %s", exc)

    # Always seed the user accounts so the demo instance can log in.
    try:
        _seed_users(conn)
    except Exception as exc:
        logger.warning("migrate: user seeding skipped — %s", exc)

    logger.info("migrate: done.")
