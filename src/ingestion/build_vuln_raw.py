"""build_vuln_raw.py — Module 1 entry point.

Merges scanner findings with asset inventory into a single vuln_raw.csv.
Auto-detects file format (Nessus XML, OpenVAS XML, CSV).
"""
from __future__ import annotations

import csv
import logging
import sys
from pathlib import Path

import pandas as pd

from adapters.nessus import NessusAdapter
from adapters.openvas import OpenVASAdapter
from adapters.csv_generic import CSVGenericAdapter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent
INPUT_DIR = ROOT / "data" / "input"
OUTPUT_DIR = ROOT / "data" / "output"
ASSET_INVENTORY_PATH = INPUT_DIR / "asset_inventory.csv"

VULN_RAW_OUTPUT = OUTPUT_DIR / "vuln_raw.csv"

FINAL_COLUMNS = [
    "asset_id", "hostname", "ip_address",
    "business_owner", "business_unit", "criticality", "environment", "internet_exposed",
    "cve_id", "cvss_base_score", "severity", "plugin_id", "plugin_name", "plugin_family",
    "vuln_title", "first_seen", "last_seen", "scanner_source",
]


def load_asset_inventory() -> pd.DataFrame:
    if not ASSET_INVENTORY_PATH.exists():
        logger.warning("Asset inventory not found at %s — asset metadata will be empty.", ASSET_INVENTORY_PATH)
        return pd.DataFrame()
    df = pd.read_csv(ASSET_INVENTORY_PATH, dtype=str).fillna("")
    logger.info("Loaded %d assets from inventory.", len(df))
    return df


def detect_adapter(path: Path):
    suffix = path.suffix.lower()
    if suffix in (".nessus", ".xml"):
        # Peek at the root tag to distinguish Nessus vs OpenVAS
        try:
            import xml.etree.ElementTree as ET
            root = ET.parse(path).getroot()
            if root.tag == "NessusClientData_v2" or "NessusClient" in root.tag:
                return NessusAdapter()
            if root.tag in ("report", "get_reports_response", "results"):
                return OpenVASAdapter()
        except Exception:
            pass
        return NessusAdapter()  # default for .nessus files
    if suffix == ".csv":
        return CSVGenericAdapter()
    raise ValueError(f"Cannot determine scanner adapter for: {path}")


def ingest_all_scanner_files(inventory: pd.DataFrame) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []

    scanner_files = list(INPUT_DIR.glob("*.nessus")) + \
                    list(INPUT_DIR.glob("*.xml")) + \
                    list(INPUT_DIR.glob("*findings*.csv")) + \
                    list(INPUT_DIR.glob("*scan*.csv"))

    if not scanner_files:
        logger.error("No scanner files found in %s", INPUT_DIR)
        sys.exit(1)

    for path in scanner_files:
        if path.name == "asset_inventory.csv":
            continue
        try:
            adapter = detect_adapter(path)
            df = adapter.parse(path, inventory)
            if not df.empty:
                frames.append(df)
                logger.info("Ingested %d rows from %s (%s)", len(df), path.name, adapter.name)
        except Exception as e:
            logger.error("Failed to parse %s: %s", path.name, e)

    if not frames:
        logger.error("No findings produced by any scanner file.")
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)
    logger.info("Total raw findings before dedup: %d", len(combined))

    # Deduplicate: same asset + CVE + plugin = one row (keep last)
    combined = combined.drop_duplicates(
        subset=["asset_id", "cve_id", "plugin_id"], keep="last"
    ).reset_index(drop=True)
    logger.info("After dedup: %d findings", len(combined))
    return combined


def merge_with_inventory(findings: pd.DataFrame, inventory: pd.DataFrame) -> pd.DataFrame:
    if inventory.empty:
        for col in ("business_owner", "business_unit", "criticality", "environment", "internet_exposed"):
            if col not in findings.columns:
                findings[col] = ""
        return findings

    merged = findings.merge(
        inventory[["asset_id", "business_owner", "business_unit",
                   "criticality", "environment", "internet_exposed"]],
        on="asset_id", how="left",
    )
    merged = merged.fillna("")
    return merged


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    inventory = load_asset_inventory()
    findings = ingest_all_scanner_files(inventory)
    merged = merge_with_inventory(findings, inventory)

    # Ensure all final columns exist
    for col in FINAL_COLUMNS:
        if col not in merged.columns:
            merged[col] = ""

    output = merged[FINAL_COLUMNS]
    output.to_csv(VULN_RAW_OUTPUT, index=False, quoting=csv.QUOTE_ALL)
    logger.info("vuln_raw.csv written: %d rows → %s", len(output), VULN_RAW_OUTPUT)


if __name__ == "__main__":
    main()
