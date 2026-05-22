"""OpenVAS / Greenbone XML report adapter.

Parses the XML format exported by OpenVAS / Greenbone Community Edition.
"""
from __future__ import annotations

import uuid
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
import pandas as pd

from .base import ScannerAdapter

logger = logging.getLogger(__name__)


class OpenVASAdapter(ScannerAdapter):
    name = "openvas"

    def parse(self, file_path: Path, asset_inventory: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        logger.info("Parsing OpenVAS file: %s", file_path)
        tree = ET.parse(file_path)
        root = tree.getroot()

        rows: list[dict] = []

        # Support both <report> root and <get_reports_response> wrapper
        reports = root.findall(".//result")
        if not reports:
            logger.warning("No <result> elements found in %s", file_path.name)
            return pd.DataFrame()

        for result in reports:
            host_el = result.find("host")
            ip_address = (host_el.text or "").strip() if host_el is not None else ""
            hostname_el = result.find("host/hostname")
            hostname = (hostname_el.text or "").strip() if hostname_el is not None else ip_address

            asset_id = self._lookup_asset_id(hostname, ip_address, asset_inventory)

            nvt = result.find("nvt")
            plugin_id = nvt.get("oid", "") if nvt is not None else ""
            plugin_name = self._text(nvt, "name") if nvt is not None else ""
            plugin_family = self._text(nvt, "family") if nvt is not None else ""
            vuln_title = self._text(result, "name") or plugin_name

            severity_str = self._text(result, "threat") or self._text(result, "severity") or "0"
            try:
                cvss = float(severity_str)
                severity = self._cvss_to_level(cvss)
            except ValueError:
                cvss = 0.0
                severity = self.normalise_severity(severity_str)

            # CVE references
            cves: list[str] = []
            for ref in result.findall(".//ref[@type='cve']"):
                cve = self.clean_cve_id(ref.get("id", ""))
                if cve:
                    cves.append(cve)

            # Also look inside nvt/refs
            if nvt is not None:
                for ref in nvt.findall(".//ref[@type='cve']"):
                    cve = self.clean_cve_id(ref.get("id", ""))
                    if cve and cve not in cves:
                        cves.append(cve)

            creation_time = self._text(result, "creation_time") or ""
            modification_time = self._text(result, "modification_time") or ""

            if cves:
                for cve in cves:
                    rows.append(self._row(asset_id, hostname, ip_address, cve, cvss,
                                          severity, plugin_id, plugin_name, plugin_family,
                                          vuln_title, creation_time, modification_time))
            else:
                rows.append(self._row(asset_id, hostname, ip_address, "", cvss,
                                      severity, plugin_id, plugin_name, plugin_family,
                                      vuln_title, creation_time, modification_time))

        df = pd.DataFrame(rows)
        logger.info("OpenVAS: parsed %d findings from %s", len(df), file_path.name)
        return df

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _text(element: Optional[ET.Element], tag: str) -> str:
        if element is None:
            return ""
        child = element.find(tag)
        return (child.text or "").strip() if child is not None else ""

    @staticmethod
    def _cvss_to_level(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"

    @staticmethod
    def _lookup_asset_id(hostname: str, ip: str, inventory: Optional[pd.DataFrame]) -> str:
        if inventory is not None and not inventory.empty:
            mask = (inventory["hostname"] == hostname) | (inventory["ip_address"] == ip)
            match = inventory[mask]
            if not match.empty:
                return str(match.iloc[0]["asset_id"])
        return f"asset-{uuid.uuid5(uuid.NAMESPACE_DNS, hostname or ip)}"

    @staticmethod
    def _row(asset_id, hostname, ip_address, cve_id, cvss, severity,
             plugin_id, plugin_name, plugin_family, vuln_title,
             first_seen, last_seen) -> dict:
        return {
            "asset_id": asset_id, "hostname": hostname, "ip_address": ip_address,
            "cve_id": cve_id, "cvss_base_score": cvss, "severity": severity,
            "plugin_id": plugin_id, "plugin_name": plugin_name,
            "plugin_family": plugin_family, "vuln_title": vuln_title,
            "first_seen": first_seen, "last_seen": last_seen,
            "scanner_source": "openvas",
        }
