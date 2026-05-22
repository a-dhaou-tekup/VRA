"""Base scanner adapter interface.

Every scanner adapter (Nessus, OpenVAS, CSV generic) must implement this protocol
so Module 1 can treat them interchangeably.
"""
from __future__ import annotations

import abc
import pandas as pd
from pathlib import Path
from typing import Optional


class ScannerAdapter(abc.ABC):
    """Abstract base class for all scanner parsers."""

    name: str = "base"

    @abc.abstractmethod
    def parse(self, file_path: Path, asset_inventory: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        """Parse a scanner export file and return a normalised DataFrame.

        The returned DataFrame must contain at minimum:
            asset_id, hostname, ip_address, cve_id, cvss_base_score,
            severity, plugin_name, vuln_title, first_seen, last_seen,
            scanner_source, plugin_family
        """

    @staticmethod
    def normalise_severity(raw: str) -> str:
        """Map scanner-specific severity strings to canonical CRITICAL/HIGH/MEDIUM/LOW/INFO."""
        mapping = {
            "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO", "informational": "INFO",
            "none": "INFO", "": "INFO",
            "4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO",
        }
        return mapping.get(str(raw).lower().strip(), "MEDIUM")

    @staticmethod
    def clean_cve_id(raw: str) -> str:
        """Ensure CVE ID is in canonical CVE-YYYY-NNNNN format; return empty string if invalid."""
        import re
        if not raw:
            return ""
        raw = raw.strip().upper()
        if re.match(r"^CVE-\d{4}-\d{4,}$", raw):
            return raw
        return ""
