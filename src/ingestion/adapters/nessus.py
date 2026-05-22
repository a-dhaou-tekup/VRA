"""Nessus XML (.nessus) scanner adapter.

Parses the proprietary Nessus XML format exported from Tenable Nessus
Professional or Nessus Essentials.
"""
from __future__ import annotations

import re
import uuid
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
import pandas as pd

from .base import ScannerAdapter

logger = logging.getLogger(__name__)


class NessusAdapter(ScannerAdapter):
    name = "nessus"

    # Plugin IDs that carry CVE data
    CVE_ATTRIB = "cve"

    def parse(self, file_path: Path, asset_inventory: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        logger.info("Parsing Nessus file: %s", file_path)
        tree = ET.parse(file_path)
        root = tree.getroot()

        rows: list[dict] = []

        for report_host in root.iter("ReportHost"):
            hostname = report_host.get("name", "")
            ip_address = self._tag_value(report_host, "host-ip") or hostname

            asset_id = self._lookup_asset_id(hostname, ip_address, asset_inventory)

            for item in report_host.iter("ReportItem"):
                plugin_id = item.get("pluginID", "")
                plugin_name = item.get("pluginName", "")
                plugin_family = item.get("pluginFamily", "")
                severity_num = item.get("severity", "0")
                vuln_title = self._tag_text(item, "synopsis") or plugin_name

                # Extract CVEs (comma-separated in attribute or child elements)
                cve_raw = item.get("cve", "") or ""
                if not cve_raw:
                    cve_elements = item.findall("cve")
                    cve_raw = ",".join(e.text or "" for e in cve_elements)

                # Extract CVSS v3 first, fall back to v2
                cvss = self._float_or(item, "cvss3_base_score") or \
                       self._float_or(item, "cvss_base_score") or 0.0

                first_seen = self._tag_text(item, "plugin_publication_date") or ""
                last_seen = self._tag_text(item, "plugin_modification_date") or ""

                for cve in self._split_cves(cve_raw):
                    if not cve:
                        continue
                    rows.append({
                        "asset_id": asset_id,
                        "hostname": hostname,
                        "ip_address": ip_address,
                        "cve_id": self.clean_cve_id(cve),
                        "cvss_base_score": cvss,
                        "severity": self.normalise_severity(severity_num),
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name,
                        "plugin_family": plugin_family,
                        "vuln_title": vuln_title,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "scanner_source": "nessus",
                    })

                # Include items without a CVE (plugin findings)
                if not self._split_cves(cve_raw):
                    rows.append({
                        "asset_id": asset_id,
                        "hostname": hostname,
                        "ip_address": ip_address,
                        "cve_id": "",
                        "cvss_base_score": cvss,
                        "severity": self.normalise_severity(severity_num),
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name,
                        "plugin_family": plugin_family,
                        "vuln_title": vuln_title,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "scanner_source": "nessus",
                    })

        df = pd.DataFrame(rows)
        logger.info("Nessus: parsed %d findings from %s", len(df), file_path.name)
        return df

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _tag_value(element: ET.Element, tag: str) -> str:
        child = element.find(f"HostProperties/tag[@name='{tag}']")
        return (child.text or "").strip() if child is not None else ""

    @staticmethod
    def _tag_text(element: ET.Element, tag: str) -> str:
        child = element.find(tag)
        return (child.text or "").strip() if child is not None else ""

    @staticmethod
    def _float_or(element: ET.Element, tag: str) -> Optional[float]:
        child = element.find(tag)
        if child is not None and child.text:
            try:
                return float(child.text.strip())
            except ValueError:
                pass
        return None

    @staticmethod
    def _split_cves(raw: str) -> list[str]:
        return [c.strip() for c in re.split(r"[,\s]+", raw) if c.strip()]

    @staticmethod
    def _lookup_asset_id(hostname: str, ip: str, inventory: Optional[pd.DataFrame]) -> str:
        if inventory is not None and not inventory.empty:
            mask = (inventory["hostname"] == hostname) | (inventory["ip_address"] == ip)
            match = inventory[mask]
            if not match.empty:
                return str(match.iloc[0]["asset_id"])
        return f"asset-{uuid.uuid5(uuid.NAMESPACE_DNS, hostname or ip)}"
