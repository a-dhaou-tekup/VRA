"""Generic CSV scanner adapter.

Accepts any CSV that contains (or can be mapped to) at minimum:
    cve_id, hostname, cvss_base_score, severity

Column name normalisation is driven by config/scanner_mappings.yaml.
The adapter selects the mapping that renames the **most** columns
(best-match), so more specific formats (e.g. tenable_sc) win over
generic ones when their columns overlap.

Post-normalisation fallbacks
----------------------------
- cve_id missing but plugin_name present → extract first CVE-YYYY-NNNN
  from the plugin_name string (Tenable SecurityCenter format).
- cvss_base_score missing but vpr present → treat VPR (0–10) as CVSS proxy.
- hostname missing but hostname_netbios / ip_address present → derive.
- severity not in {critical,high,medium,low,info,none} → normalise to 'info'.
"""
from __future__ import annotations

import re
import uuid
import logging
from pathlib import Path
from typing import Optional

import pandas as pd
import yaml

from .base import ScannerAdapter

logger = logging.getLogger(__name__)

MAPPINGS_PATH = Path(__file__).parent.parent.parent.parent / "config" / "scanner_mappings.yaml"

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


class CSVGenericAdapter(ScannerAdapter):
    name = "csv_generic"

    REQUIRED = {"cve_id", "hostname", "cvss_base_score", "severity"}

    def parse(self, file_path: Path, asset_inventory: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        logger.info("Parsing generic CSV: %s", file_path)
        df = pd.read_csv(file_path, dtype=str).fillna("")

        # ── Column normalisation via scanner_mappings.yaml ────────────────────
        if MAPPINGS_PATH.exists():
            with open(MAPPINGS_PATH) as f:
                mappings = yaml.safe_load(f) or {}

            # Pick the mapping that renames the most columns (best-match wins).
            best_rename: dict[str, str] = {}
            for scanner, col_map in mappings.items():
                if not isinstance(col_map, dict):
                    continue
                rename = {k: v for k, v in col_map.items() if k in df.columns}
                if len(rename) > len(best_rename):
                    best_rename = rename

            if best_rename:
                df = df.rename(columns=best_rename)
                logger.debug("CSVGenericAdapter: applied mapping with %d renames", len(best_rename))

        # ── Post-mapping fallbacks ────────────────────────────────────────────

        # 1. cve_id: extract from plugin_name if present (Tenable SC format)
        if "cve_id" not in df.columns or df["cve_id"].eq("").all():
            if "plugin_name" in df.columns:
                def _extract_cve(text: str) -> str:
                    m = _CVE_RE.search(text)
                    return m.group(0).upper() if m else ""
                df["cve_id"] = df["plugin_name"].apply(_extract_cve)
                n_extracted = df["cve_id"].ne("").sum()
                logger.info("CSVGenericAdapter: extracted %d CVE IDs from plugin_name", n_extracted)

        # 2. hostname: fall back to hostname_netbios then ip_address
        if "hostname" not in df.columns or df["hostname"].eq("").all():
            for fallback_col in ("hostname_netbios", "ip_address"):
                if fallback_col in df.columns and df[fallback_col].ne("").any():
                    df["hostname"] = df["hostname"].where(
                        df.get("hostname", pd.Series("", index=df.index)).ne(""),
                        df[fallback_col],
                    ) if "hostname" in df.columns else df[fallback_col]
                    logger.info("CSVGenericAdapter: hostname derived from %s", fallback_col)
                    break

        # 3. cvss_base_score: fall back to VPR column
        if "cvss_base_score" not in df.columns or df["cvss_base_score"].eq("").all():
            if "vpr" in df.columns:
                df["cvss_base_score"] = df["vpr"]
                logger.info("CSVGenericAdapter: cvss_base_score derived from VPR")

        # 4. Drop helper column
        df.drop(columns=["hostname_netbios", "vpr"], errors="ignore", inplace=True)

        # ── Require the four minimum columns ─────────────────────────────────
        missing = self.REQUIRED - set(df.columns)
        if missing:
            raise ValueError(
                f"CSV is missing required columns: {missing}. "
                f"Available columns: {list(df.columns)}"
            )

        # ── Type normalisation ────────────────────────────────────────────────
        df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce").fillna(0.0)
        df["severity"]        = df["severity"].apply(self.normalise_severity)
        df["cve_id"]          = df["cve_id"].apply(self.clean_cve_id)
        df["scanner_source"]  = "csv_generic"

        # Drop rows with no usable CVE ID (avoids polluting jobs with empty entries)
        n_before = len(df)
        df = df[df["cve_id"].str.startswith("CVE-", na=False)].reset_index(drop=True)
        n_dropped = n_before - len(df)
        if n_dropped:
            logger.info("CSVGenericAdapter: dropped %d rows with no valid CVE ID", n_dropped)

        # ── Standard column padding ───────────────────────────────────────────
        if "ip_address" not in df.columns:
            df["ip_address"] = df["hostname"]
        if "asset_id" not in df.columns:
            df["asset_id"] = df.apply(
                lambda r: self._lookup_asset_id(r["hostname"], r["ip_address"], asset_inventory),
                axis=1,
            )
        for col in ("plugin_id", "plugin_name", "plugin_family", "vuln_title", "first_seen", "last_seen"):
            if col not in df.columns:
                df[col] = ""

        logger.info("CSV generic: parsed %d findings from %s", len(df), file_path.name)
        return df

    @staticmethod
    def _lookup_asset_id(hostname: str, ip: str, inventory: Optional[pd.DataFrame]) -> str:
        if inventory is not None and not inventory.empty:
            mask = (inventory["hostname"] == hostname) | (inventory["ip_address"] == ip)
            match = inventory[mask]
            if not match.empty:
                return str(match.iloc[0]["asset_id"])
        return f"asset-{uuid.uuid5(uuid.NAMESPACE_DNS, hostname or ip)}"
