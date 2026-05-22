"""Generic CSV scanner adapter.

Accepts any CSV that contains at minimum: cve_id, hostname, cvss_base_score, severity.
Extra columns are passed through unchanged.
"""
from __future__ import annotations

import uuid
import logging
from pathlib import Path
from typing import Optional
import pandas as pd
import yaml

from .base import ScannerAdapter

logger = logging.getLogger(__name__)

MAPPINGS_PATH = Path(__file__).parent.parent.parent.parent / "config" / "scanner_mappings.yaml"


class CSVGenericAdapter(ScannerAdapter):
    name = "csv_generic"

    REQUIRED = {"cve_id", "hostname", "cvss_base_score", "severity"}

    def parse(self, file_path: Path, asset_inventory: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        logger.info("Parsing generic CSV: %s", file_path)
        df = pd.read_csv(file_path, dtype=str).fillna("")

        # Try to auto-map column names via scanner_mappings.yaml
        if MAPPINGS_PATH.exists():
            with open(MAPPINGS_PATH) as f:
                mappings = yaml.safe_load(f) or {}
            # Try nessus CSV column names
            for scanner, col_map in mappings.items():
                rename = {k: v for k, v in col_map.items() if k in df.columns}
                if rename:
                    df = df.rename(columns=rename)
                    break

        missing = self.REQUIRED - set(df.columns)
        if missing:
            raise ValueError(f"CSV is missing required columns: {missing}. "
                             f"Available columns: {list(df.columns)}")

        df["cvss_base_score"] = pd.to_numeric(df["cvss_base_score"], errors="coerce").fillna(0.0)
        df["severity"] = df["severity"].apply(self.normalise_severity)
        df["cve_id"] = df["cve_id"].apply(self.clean_cve_id)
        df["scanner_source"] = "csv_generic"

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
