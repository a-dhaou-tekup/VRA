"""Executive PDF report service — Prompt #9.

Pipeline:
    gather_state()  →  generate_summary()  →  render_pdf()  →  produce_report()

The LLM call uses temperature 0.2 for light prose variability.
On LLM failure the service falls back to a deterministic f-string summary
and marks summary_source = 'template' in the DB record.

PDF is built with fpdf2 (pure Python, no GTK/system libs needed on Windows).
KPI trend charts are rendered by matplotlib in memory and embedded as PNG images.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests
import yaml

logger = logging.getLogger(__name__)

# ── Latin-1 safety ────────────────────────────────────────────────────────────
# fpdf2's built-in Helvetica/Times/Courier are Latin-1 only.
# Swap common Unicode punctuation to safe ASCII before any text enters the PDF.
_UNICODE_MAP = str.maketrans({
    "—": "-",    # em dash  —
    "–": "-",    # en dash  –
    "…": "...",  # ellipsis …
    "→": "->",   # arrow    →
    "‘": "'",    # left single quote
    "’": "'",    # right single quote
    "“": '"',    # left double quote
    "”": '"',    # right double quote
    "·": "*",    # middle dot
})


def _s(text: object) -> str:
    """Convert to str and replace characters outside Latin-1 with ASCII fallbacks."""
    t = str(text) if text is not None else ""
    t = t.translate(_UNICODE_MAP)
    # Remaining non-Latin-1 chars → '?'
    return t.encode("latin-1", errors="replace").decode("latin-1")


_CONFIG_PATH = (
    Path(__file__).parent.parent.parent.parent.parent / "config" / "policy.yaml"
)
_REPORTS_DIR = (
    Path(__file__).parent.parent.parent.parent.parent / "data" / "reports"
)
_DB_PATH: Optional[Path] = None  # set by configure()


def configure(db_path: Path) -> None:
    global _DB_PATH
    _DB_PATH = db_path
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _load_config() -> dict:
    with open(_CONFIG_PATH, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg["rag"]


# ── 1. gather_state ───────────────────────────────────────────────────────────

def gather_state(period_days: int, conn: sqlite3.Connection) -> dict:
    """Pull current KPIs, top-10 riskiest open findings, and 4-week weekly trend."""
    now = datetime.now(timezone.utc)
    period_start = now - timedelta(days=period_days)

    # ── Current KPI snapshot ─────────────────────────────────────────────────
    total_jobs = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]

    by_risk: dict[str, int] = {}
    for row in conn.execute(
        "SELECT max_risk_level, COUNT(*) AS cnt FROM jobs GROUP BY max_risk_level"
    ):
        by_risk[row["max_risk_level"] or "UNKNOWN"] = row["cnt"]

    open_jobs = conn.execute(
        "SELECT COUNT(*) FROM jobs WHERE status NOT IN ('DONE','CLOSED')"
    ).fetchone()[0]

    kev_jobs = conn.execute(
        "SELECT COUNT(*) FROM jobs WHERE kev_present = 1"
    ).fetchone()[0]

    overdue = conn.execute(
        """SELECT COUNT(*) FROM jobs
           WHERE status NOT IN ('DONE','CLOSED')
             AND due_date IS NOT NULL AND due_date < ?""",
        (now.isoformat(),),
    ).fetchone()[0]

    sla_compliance = (
        round((open_jobs - overdue) / open_jobs * 100, 1) if open_jobs else 100.0
    )

    # MTTR — average calendar days for jobs closed in the period
    mttr_row = conn.execute(
        """SELECT AVG(julianday(closed_at) - julianday(created_at)) AS avg_days
           FROM jobs
           WHERE status IN ('DONE','CLOSED')
             AND closed_at IS NOT NULL AND closed_at >= ?""",
        (period_start.isoformat(),),
    ).fetchone()
    mttr_days = round(mttr_row["avg_days"] or 0.0, 1)

    new_in_period = conn.execute(
        "SELECT COUNT(*) FROM jobs WHERE created_at >= ?",
        (period_start.isoformat(),),
    ).fetchone()[0]

    closed_in_period = conn.execute(
        """SELECT COUNT(*) FROM jobs
           WHERE status IN ('DONE','CLOSED') AND closed_at >= ?""",
        (period_start.isoformat(),),
    ).fetchone()[0]

    # ── Top-10 riskiest open jobs (findings proxy) ────────────────────────────
    top_findings: list[dict] = []
    for row in conn.execute(
        """SELECT job_id, cve_list, main_product, max_risk_level,
                  risk_score_max, business_unit, kev_present, due_date, asset_ids
           FROM jobs
           WHERE status NOT IN ('DONE','CLOSED')
           ORDER BY risk_score_max DESC NULLS LAST
           LIMIT 10"""
    ):
        try:
            cves = json.loads(row["cve_list"] or "[]")
        except Exception:
            cves = [row["cve_list"]] if row["cve_list"] else []

        try:
            assets = json.loads(row["asset_ids"] or "[]")
        except Exception:
            assets = []

        top_findings.append(
            {
                "job_id":        row["job_id"][:8] + "...",
                "cves":          cves[:3],
                "product":       row["main_product"] or "Unknown",
                "risk_level":    row["max_risk_level"] or "UNKNOWN",
                "risk_score":    round(row["risk_score_max"] or 0, 1),
                "business_unit": row["business_unit"] or "-",
                "kev":           bool(row["kev_present"]),
                "due_date":      (row["due_date"] or "")[:10],
                "asset_count":   len(assets),
            }
        )

    # ── 4-week weekly trend ───────────────────────────────────────────────────
    weekly_trend: list[dict] = []
    for week_back in range(3, -1, -1):
        wk_start = (now - timedelta(weeks=week_back + 1)).isoformat()
        wk_end   = (now - timedelta(weeks=week_back)).isoformat()
        wk_label = (now - timedelta(weeks=week_back)).strftime("W%V")

        row = conn.execute(
            """SELECT
                   COUNT(*) AS new_jobs,
                   COUNT(CASE WHEN max_risk_level='CRITICAL' THEN 1 END) AS critical,
                   COUNT(CASE WHEN max_risk_level='HIGH'     THEN 1 END) AS high,
                   COUNT(CASE WHEN status IN ('DONE','CLOSED') THEN 1 END) AS closed
               FROM jobs WHERE created_at BETWEEN ? AND ?""",
            (wk_start, wk_end),
        ).fetchone()

        overdue_wk = conn.execute(
            """SELECT COUNT(*) FROM jobs
               WHERE created_at BETWEEN ? AND ?
                 AND due_date IS NOT NULL AND due_date < ?""",
            (wk_start, wk_end, wk_end),
        ).fetchone()[0]
        nj = row["new_jobs"]
        sla_wk = round((nj - overdue_wk) / nj * 100, 1) if nj else 100.0

        weekly_trend.append(
            {
                "week":     wk_label,
                "new_jobs": row["new_jobs"],
                "critical": row["critical"],
                "high":     row["high"],
                "closed":   row["closed"],
                "sla_pct":  sla_wk,
            }
        )

    return {
        "generated_at":       now.isoformat(),
        "period_days":        period_days,
        "period_start":       period_start.date().isoformat(),
        "period_end":         now.date().isoformat(),
        "total_jobs":         total_jobs,
        "open_jobs":          open_jobs,
        "overdue_jobs":       overdue,
        "kev_jobs":           kev_jobs,
        "sla_compliance_pct": sla_compliance,
        "mttr_days":          mttr_days,
        "new_jobs_period":    new_in_period,
        "closed_jobs_period": closed_in_period,
        "critical_open":      by_risk.get("CRITICAL", 0),
        "high_open":          by_risk.get("HIGH", 0),
        "medium_open":        by_risk.get("MEDIUM", 0),
        "low_open":           by_risk.get("LOW", 0),
        "top_findings":       top_findings,
        "weekly_trend":       weekly_trend,
    }


# ── 2. generate_summary ───────────────────────────────────────────────────────

def _template_summary(s: dict) -> str:
    """Deterministic fallback when LLM is unavailable."""
    top3 = s["top_findings"][:3]
    top3_str = "; ".join(
        f"{', '.join(f['cves'][:2]) or 'unknown CVE'} affecting {f['product']} "
        f"({f['risk_level']}, score {f['risk_score']})"
        for f in top3
    ) or "no open findings"

    return (
        f"During the {s['period_days']}-day reporting period ending {s['period_end']}, "
        f"the organisation managed {s['open_jobs']} active remediation jobs out of "
        f"{s['total_jobs']} total. SLA compliance stood at {s['sla_compliance_pct']}%, "
        f"with {s['overdue_jobs']} jobs past their deadline. "
        f"{s['kev_jobs']} jobs involve vulnerabilities on the CISA Known Exploited "
        f"Vulnerabilities catalogue, requiring immediate prioritisation. "
        f"Mean time to remediate completed items this period was {s['mttr_days']} days.\n\n"
        f"{s['new_jobs_period']} new remediation jobs were opened this period and "
        f"{s['closed_jobs_period']} were resolved. "
        f"The critical and high-severity backlog stands at {s['critical_open']} critical "
        f"and {s['high_open']} high-risk items. "
        f"The three most urgent open findings are: {top3_str}. "
        f"Immediate leadership attention is requested on the {s['critical_open']} "
        f"critical items to maintain SLA commitments and minimise breach risk."
    )


def generate_summary(state: dict) -> tuple[str, str]:
    """Call the local LLM for a prose executive summary.

    Returns (summary_text, source) where source is 'llm' or 'template'.
    """
    try:
        config = _load_config()
    except Exception as exc:
        logger.warning("exec_report: cannot load config — %s", exc)
        return _template_summary(state), "template"

    s = state
    top3 = s["top_findings"][:3]
    top3_lines = "\n".join(
        f"  • {', '.join(f['cves'][:2]) or 'unknown'} | {f['product']} | "
        f"Risk: {f['risk_level']} (score {f['risk_score']}) | KEV: {f['kev']}"
        for f in top3
    )

    kpi_block = (
        f"Period: {s['period_start']} to {s['period_end']} ({s['period_days']} days)\n"
        f"Total remediation jobs: {s['total_jobs']}\n"
        f"Open jobs: {s['open_jobs']}\n"
        f"Overdue (past SLA): {s['overdue_jobs']}\n"
        f"SLA compliance: {s['sla_compliance_pct']}%\n"
        f"MTTR (closed this period): {s['mttr_days']} days\n"
        f"KEV-listed jobs: {s['kev_jobs']}\n"
        f"New jobs opened this period: {s['new_jobs_period']}\n"
        f"Jobs closed this period: {s['closed_jobs_period']}\n"
        f"Critical open: {s['critical_open']} | High: {s['high_open']} | "
        f"Medium: {s['medium_open']} | Low: {s['low_open']}\n"
        f"Top 3 urgent findings:\n{top3_lines}"
    )

    system_prompt = (
        "You are a CISO-level security analyst writing an executive summary for "
        "a non-technical leadership audience. "
        "Write exactly two paragraphs of plain English prose (no bullet points, no headers). "
        "Paragraph 1: overall security posture and SLA performance this period. "
        "Paragraph 2: the three most important open findings and recommended leadership action. "
        "Keep total length under 350 words. "
        "IMPORTANT: Every numeric claim MUST cite the exact value from the data provided. "
        "Do not invent numbers."
    )
    user_message = (
        "Here is the current security posture data. Write the executive summary now.\n\n"
        + kpi_block
    )

    url = f"{config['ollama_url']}/api/chat"
    payload = {
        "model":   config["model"],
        "stream":  False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ],
        "options": {
            "temperature": 0.2,
            "num_predict": 600,  # ~350 words with some headroom
        },
    }
    timeout_sec = int(
        config.get("ollama_timeout")
        or os.getenv("OLLAMA_TIMEOUT_SECONDS", "300")
    )

    try:
        resp = requests.post(url, json=payload, timeout=timeout_sec)
        resp.raise_for_status()
        data = resp.json()
        text = data.get("message", {}).get("content", "").strip()
        if not text:
            raise ValueError("Empty response from LLM")
        return text, "llm"
    except Exception as exc:
        logger.warning(
            "exec_report: LLM call failed (%s) — using template fallback", exc
        )
        return _template_summary(state), "template"


# ── 3. render_pdf ─────────────────────────────────────────────────────────────

def _build_trend_charts(state: dict) -> list[bytes]:
    """Generate four KPI trend PNG images using matplotlib (headless)."""
    import matplotlib
    matplotlib.use("Agg")  # headless — no display required
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker

    trend = state["weekly_trend"]
    labels = [w["week"] for w in trend]

    chart_specs = [
        {
            "title":  "New Remediation Jobs / Week",
            "values": [w["new_jobs"] for w in trend],
            "ylabel": "Jobs",
            "style":  "-o",
            "color":  "#555555",
        },
        {
            "title":  "SLA Compliance % / Week",
            "values": [w["sla_pct"] for w in trend],
            "ylabel": "%",
            "style":  "--s",
            "color":  "#333333",
        },
        {
            "title":  "Critical + High Open / Week",
            "values": [w["critical"] + w["high"] for w in trend],
            "ylabel": "Jobs",
            "style":  "-.^",
            "color":  "#222222",
        },
        {
            "title":  "Jobs Closed / Week",
            "values": [w["closed"] for w in trend],
            "ylabel": "Jobs",
            "style":  ":D",
            "color":  "#444444",
        },
    ]

    images: list[bytes] = []
    for spec in chart_specs:
        fig, ax = plt.subplots(figsize=(3.2, 1.8))
        ax.plot(
            labels,
            spec["values"],
            spec["style"],
            color=spec["color"],
            linewidth=1.5,
            markersize=5,
        )
        ax.set_title(spec["title"], fontsize=7, pad=4)
        ax.set_ylabel(spec["ylabel"], fontsize=6)
        ax.tick_params(axis="both", labelsize=6)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.grid(True, linestyle=":", linewidth=0.5, alpha=0.6)
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout(pad=0.4)

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        images.append(buf.read())

    return images


def render_pdf(state: dict, summary: str, report_id: str) -> bytes:
    """Render the executive report PDF with fpdf2."""
    from fpdf import FPDF

    AMBER   = (245, 166, 35)
    DARK    = (15,  17,  24)
    MUTED   = (100, 105, 130)
    WHITE   = (255, 255, 255)
    LIGHT_BG = (245, 246, 250)

    s = state

    # ── Build chart images ────────────────────────────────────────────────────
    try:
        chart_images = _build_trend_charts(state)
    except Exception as exc:
        logger.warning("exec_report: chart generation failed — %s", exc)
        chart_images = []

    # ── PDF setup ─────────────────────────────────────────────────────────────
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(18, 18, 18)

    # ── Page 1: Cover ─────────────────────────────────────────────────────────
    pdf.add_page()

    # Dark cover banner
    pdf.set_fill_color(*DARK)
    pdf.rect(0, 0, 210, 80, style="F")

    pdf.set_y(14)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*AMBER)
    pdf.cell(0, 10, "VRA", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 6, "Vulnerability Remediation Assistant", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 9, "Executive Security Summary", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(88)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 6, _s(f"Period: {s['period_start']}  to  {s['period_end']}"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 5, _s(f"Report ID: {report_id}"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _s(f"Generated: {s['period_end']}"), align="C", new_x="LMARGIN", new_y="NEXT")

    # KPI snapshot table on cover
    pdf.ln(12)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 6, "KEY PERFORMANCE INDICATORS", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    kpis = [
        ("Total Remediation Jobs",   str(s["total_jobs"])),
        ("Open Jobs",                str(s["open_jobs"])),
        ("Overdue (SLA breach)",     str(s["overdue_jobs"])),
        ("SLA Compliance",           f"{s['sla_compliance_pct']}%"),
        ("MTTR (period)",            f"{s['mttr_days']} days"),
        ("KEV-listed Jobs",          str(s["kev_jobs"])),
        ("Critical Open",            str(s["critical_open"])),
        ("High Open",                str(s["high_open"])),
        ("New Jobs (period)",        str(s["new_jobs_period"])),
        ("Closed Jobs (period)",     str(s["closed_jobs_period"])),
    ]

    # Each row = [label | value | label | value]
    # epw = 174 mm  →  label 52 + value 35 + label 52 + value 35 = 174 ✓
    LBL_W = 52
    VAL_W = 35
    ROW_H = 7

    for i, (label, value) in enumerate(kpis):
        # Alternate row background every logical row (pair of two KPIs)
        bg = LIGHT_BG if (i // 2) % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)

        # Label cell
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(LBL_W, ROW_H, _s(label), fill=True, border=0)

        # Value cell
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*DARK)
        if i % 2 == 1:
            # Right column — advance to next line after the value
            pdf.cell(VAL_W, ROW_H, _s(value), fill=True, border=0,
                     new_x="LMARGIN", new_y="NEXT")
        else:
            # Left column — stay on the same line so right pair can follow
            pdf.cell(VAL_W, ROW_H, _s(value), fill=True, border=0,
                     new_x="RIGHT", new_y="TOP")

    # ── Page 2: Executive Summary ─────────────────────────────────────────────
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*AMBER)
    pdf.set_line_width(0.5)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*DARK)
    pdf.multi_cell(0, 5.5, _s(summary), align="J")

    # ── Page 3: KPI Trend Charts ──────────────────────────────────────────────
    if chart_images:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 8, "KPI Trends (Last 4 Weeks)", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(*AMBER)
        pdf.line(18, pdf.get_y(), 192, pdf.get_y())
        pdf.ln(4)

        chart_w = 83   # mm
        chart_h = 48   # mm
        positions = [(18, pdf.get_y()), (111, pdf.get_y()),
                     (18, pdf.get_y() + chart_h + 8),
                     (111, pdf.get_y() + chart_h + 8)]

        for idx, img_bytes in enumerate(chart_images[:4]):
            x, y = positions[idx]
            tmp = io.BytesIO(img_bytes)
            pdf.image(tmp, x=x, y=y, w=chart_w, h=chart_h)

    # ── Page 4: Top-10 Findings ───────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "Top Open Findings - Ranked by Risk Score", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*AMBER)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(3)

    # Table header
    cols = [
        ("#",         8),
        ("CVE(s)",   38),
        ("Product",  38),
        ("Risk",     18),
        ("Score",    16),
        ("Unit",     27),
        ("KEV",       9),
    ]
    pdf.set_fill_color(*DARK)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 7.5)
    for col, w in cols:
        pdf.cell(w, 6, col, fill=True, border=0)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(*DARK)
    for i, f in enumerate(s["top_findings"][:10]):
        bg = LIGHT_BG if i % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)
        cve_str = ", ".join(f["cves"][:2]) or "-"
        row_vals = [
            (_s(str(i + 1)),              8),
            (_s(cve_str),                38),
            (_s(f["product"][:22]),       38),
            (_s(f["risk_level"]),         18),
            (_s(str(f["risk_score"])),    16),
            (_s(f["business_unit"][:18]), 27),
            ("YES" if f["kev"] else "no", 9),
        ]
        for val, w in row_vals:
            pdf.cell(w, 5.5, val, fill=True, border=0)
        pdf.ln()

    pdf.ln(2)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 4, "Exploit-step details omitted from this report - analyst console only.")

    # ── Page 5: Glossary ─────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "Glossary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*AMBER)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.ln(4)

    glossary = [
        ("CVE",   "Common Vulnerabilities and Exposures - a standardised identifier"
                  " for a publicly disclosed security vulnerability (e.g. CVE-2024-3400)."),
        ("CVSS",  "Common Vulnerability Scoring System - a 0-10 numeric severity score"
                  " that quantifies the characteristics of a vulnerability."),
        ("KEV",   "CISA Known Exploited Vulnerabilities catalogue - a list of CVEs that"
                  " have been actively exploited in the wild, maintained by the US"
                  " Cybersecurity and Infrastructure Security Agency."),
        ("EPSS",  "Exploit Prediction Scoring System - a machine-learning probability"
                  " (0-1) that a CVE will be exploited in the next 30 days, issued by FIRST."),
        ("MTTR",  "Mean Time To Remediate - the average number of calendar days between"
                  " a job being opened and being marked resolved or closed."),
        ("SLA",   "Service Level Agreement - a policy commitment that specifies the"
                  " maximum number of days allowed to remediate a finding of a given"
                  " severity before it is considered overdue."),
        ("RBAC",  "Role-Based Access Control - a security model that restricts system"
                  " access based on a user's assigned role (Administrator, Analyst,"
                  " Risk Owner, Auditor)."),
        ("RAG",   "Retrieval-Augmented Generation - an AI technique that retrieves"
                  " relevant advisory documents from a knowledge base before generating"
                  " a recommendation, grounding the output in real evidence."),
    ]

    for term, definition in glossary:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*DARK)
        pdf.cell(22, 6, _s(term))
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(40, 40, 60)
        pdf.multi_cell(0, 6, _s(definition), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    return bytes(pdf.output())


# ── 4. produce_report ─────────────────────────────────────────────────────────

def produce_report(report_id: str, period_days: int, actor_id: str, db_path: Path) -> None:
    """Orchestrate gather → LLM → PDF → persist. Runs in a background thread.

    The exec_reports row must already exist (status='pending') when this is called.
    On completion the row is updated to status='done' or 'failed'.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row

    def _fail(msg: str) -> None:
        conn.execute(
            "UPDATE exec_reports SET status=?, error_message=? WHERE id=?",
            ("failed", msg, report_id),
        )
        conn.commit()
        conn.close()
        logger.error("exec_report[%s] FAILED: %s", report_id, msg)

    try:
        # 1. gather
        logger.info("exec_report[%s] gathering state (period=%d d)…", report_id, period_days)
        state = gather_state(period_days, conn)

        # 2. LLM summary
        logger.info("exec_report[%s] generating LLM summary…", report_id)
        summary_text, summary_source = generate_summary(state)

        # 3. render PDF
        logger.info("exec_report[%s] rendering PDF…", report_id)
        pdf_bytes = render_pdf(state, summary_text, report_id)

        # 4. write to disk
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        pdf_path = _REPORTS_DIR / f"{report_id}.pdf"
        pdf_path.write_bytes(pdf_bytes)

        # 5. persist
        conn.execute(
            """UPDATE exec_reports
               SET status=?, summary_text=?, summary_source=?,
                   pdf_path=?, metadata_json=?
               WHERE id=?""",
            (
                "done",
                summary_text,
                summary_source,
                str(pdf_path),
                json.dumps(state),
                report_id,
            ),
        )
        conn.commit()
        logger.info(
            "exec_report[%s] done (%s, %d bytes, source=%s)",
            report_id, pdf_path.name, len(pdf_bytes), summary_source,
        )

    except Exception as exc:
        logger.exception("exec_report[%s] unexpected error", report_id)
        _fail(str(exc))
        return

    conn.close()
