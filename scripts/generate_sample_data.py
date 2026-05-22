"""Generate realistic sample data for VRA demonstration.

Creates:
  data/input/asset_inventory.csv   — 20 synthetic assets
  data/input/sample_nessus.nessus  — Nessus XML with 80 findings
  data/input/sample_openvas.xml    — OpenVAS XML with 40 findings

Uses real CVE IDs from 2023-2024. Seeded with random.seed(42) for reproducibility.
Run with: python scripts/generate_sample_data.py
"""

import csv
import random
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

random.seed(42)

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "input"

# Real, high-profile CVEs used to generate findings
CVE_DATA = [
    {
        "cve": "CVE-2024-6387",
        "cvss": 8.1,
        "name": "OpenSSH regreSSHion Remote Code Execution",
        "product": "OpenSSH",
        "plugin_family": "General",
        "risk_factor": "High",
        "description": (
            "A signal handler race condition in OpenSSH's server (sshd) on glibc-based "
            "Linux systems allows unauthenticated remote code execution as root."
        ),
        "solution": "Upgrade OpenSSH to version 9.8p1 or later.",
    },
    {
        "cve": "CVE-2024-1709",
        "cvss": 10.0,
        "name": "ConnectWise ScreenConnect Authentication Bypass",
        "product": "ConnectWise ScreenConnect",
        "plugin_family": "Web Servers",
        "risk_factor": "Critical",
        "description": (
            "An authentication bypass vulnerability in ConnectWise ScreenConnect "
            "allows unauthenticated remote code execution via the setup wizard."
        ),
        "solution": "Update ConnectWise ScreenConnect to version 23.9.8 or later.",
    },
    {
        "cve": "CVE-2023-44487",
        "cvss": 7.5,
        "name": "HTTP/2 Rapid Reset Attack (DoS)",
        "product": "Various HTTP/2 Servers",
        "plugin_family": "Web Servers",
        "risk_factor": "High",
        "description": (
            "The HTTP/2 Rapid Reset Attack exploits stream cancellation to cause a "
            "denial of service against servers that implement the HTTP/2 protocol."
        ),
        "solution": "Apply vendor-specific patches for the HTTP/2 implementation in use.",
    },
    {
        "cve": "CVE-2024-3400",
        "cvss": 10.0,
        "name": "PAN-OS Command Injection in GlobalProtect",
        "product": "Palo Alto Networks PAN-OS",
        "plugin_family": "Firewalls",
        "risk_factor": "Critical",
        "description": (
            "A command injection vulnerability in the GlobalProtect feature of "
            "Palo Alto Networks PAN-OS allows unauthenticated remote code execution as root."
        ),
        "solution": "Apply hotfixes from Palo Alto Networks security advisory PAN-SA-2024-0006.",
    },
    {
        "cve": "CVE-2023-23397",
        "cvss": 9.8,
        "name": "Microsoft Outlook NTLM Hash Leak",
        "product": "Microsoft Outlook",
        "plugin_family": "Windows",
        "risk_factor": "Critical",
        "description": (
            "An attacker can send a specially crafted email to cause Outlook to leak "
            "NTLM credentials to an attacker-controlled server without any user interaction."
        ),
        "solution": "Apply Microsoft security update KB5002231 or later.",
    },
    {
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "name": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "product": "Apache Log4j",
        "plugin_family": "Java",
        "risk_factor": "Critical",
        "description": (
            "A JNDI injection vulnerability in Apache Log4j2 allows unauthenticated "
            "remote code execution when user-controlled input is logged."
        ),
        "solution": "Upgrade Apache Log4j to version 2.17.1 or later.",
    },
    {
        "cve": "CVE-2022-30190",
        "cvss": 7.8,
        "name": "Microsoft Windows MSDT Remote Code Execution (Follina)",
        "product": "Microsoft Windows",
        "plugin_family": "Windows",
        "risk_factor": "High",
        "description": (
            "A remote code execution vulnerability exists in the Microsoft Support "
            "Diagnostic Tool (MSDT) when called from a Microsoft Office application "
            "via the ms-msdt URL protocol."
        ),
        "solution": "Apply Microsoft security update KB5014699 or disable the MSDT URL protocol.",
    },
    {
        "cve": "CVE-2024-21762",
        "cvss": 9.6,
        "name": "Fortinet FortiOS SSL-VPN Out-of-Bound Write RCE",
        "product": "Fortinet FortiOS",
        "plugin_family": "Firewalls",
        "risk_factor": "Critical",
        "description": (
            "An out-of-bound write vulnerability in FortiOS and FortiProxy SSL-VPN may "
            "allow unauthenticated remote code execution via specially crafted HTTP requests."
        ),
        "solution": "Upgrade FortiOS to 7.4.3, 7.2.7, 7.0.14, or 6.4.15 or later.",
    },
    {
        "cve": "CVE-2023-20198",
        "cvss": 10.0,
        "name": "Cisco IOS XE Web UI Privilege Escalation",
        "product": "Cisco IOS XE",
        "plugin_family": "Cisco",
        "risk_factor": "Critical",
        "description": (
            "A vulnerability in the web UI feature of Cisco IOS XE allows an "
            "unauthenticated remote attacker to create an account with privilege level 15 access."
        ),
        "solution": "Apply Cisco IOS XE software fixes or disable the HTTP server feature.",
    },
    {
        "cve": "CVE-2024-0204",
        "cvss": 9.8,
        "name": "Fortra GoAnywhere MFT Authentication Bypass",
        "product": "Fortra GoAnywhere MFT",
        "plugin_family": "Web Servers",
        "risk_factor": "Critical",
        "description": (
            "An authentication bypass vulnerability in Fortra GoAnywhere MFT allows "
            "unauthenticated users to create admin accounts via the administration portal."
        ),
        "solution": "Upgrade GoAnywhere MFT to version 7.4.1 or later.",
    },
]

BUSINESS_UNITS = ["Engineering", "Finance", "HR", "IT"]
ENVIRONMENTS = ["production", "staging", "dev"]

HOSTNAME_PREFIXES = {
    "Engineering": ["web", "app", "api", "build", "ci"],
    "Finance": ["fin", "erp", "acct", "pay", "audit"],
    "HR": ["hr", "payroll", "onboard", "ldap", "sso"],
    "IT": ["dc", "dns", "smtp", "ntp", "monitor"],
}

# Weighted criticality pool: 30% low, 40% medium, 20% high, 10% critical
_CRITICALITY_POOL = ["low"] * 30 + ["medium"] * 40 + ["high"] * 20 + ["critical"] * 10


def generate_asset_inventory(n: int = 20) -> list[dict]:
    """Return *n* synthetic asset dicts."""
    assets = []
    for i in range(n):
        bu = random.choice(BUSINESS_UNITS)
        prefix = random.choice(HOSTNAME_PREFIXES[bu])
        env = random.choice(ENVIRONMENTS)
        criticality = random.choice(_CRITICALITY_POOL)
        internet_exposed = (
            True if criticality == "critical" else random.random() < 0.30
        )
        assets.append(
            {
                "asset_id": str(uuid.uuid4()),
                "hostname": f"{prefix}-{env[:4]}-{i + 1:02d}",
                "ip_address": (
                    f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
                ),
                "business_unit": bu,
                "business_owner": f"{bu.lower()}-team@company.example",
                "criticality": criticality,
                "internet_exposed": str(internet_exposed).lower(),
                "environment": env,
            }
        )
    return assets


def generate_nessus_xml(assets: list[dict], n_findings: int = 80) -> None:
    """Write a valid NessusClientData_v2 XML file with *n_findings* findings."""
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name="VRA_Sample_Scan")

    severity_map = {"Critical": "4", "High": "3", "Medium": "2", "Low": "1"}
    ports = [22, 80, 443, 445, 3389, 8080]
    services = ["ssh", "www", "https", "smb", "rdp", "http-proxy"]
    os_choices = ["Linux 5.15", "Windows Server 2019", "Ubuntu 22.04"]

    # Distribute findings evenly across assets
    findings_per_asset = max(1, n_findings // len(assets))
    total_written = 0

    for asset in assets:
        if total_written >= n_findings:
            break

        host_elem = ET.SubElement(report, "ReportHost", name=asset["hostname"])
        props = ET.SubElement(host_elem, "HostProperties")

        tag = ET.SubElement(props, "tag", name="host-ip")
        tag.text = asset["ip_address"]
        tag = ET.SubElement(props, "tag", name="host-fqdn")
        tag.text = f"{asset['hostname']}.corp.example.com"
        tag = ET.SubElement(props, "tag", name="operating-system")
        tag.text = random.choice(os_choices)

        remaining = n_findings - total_written
        n_for_host = min(findings_per_asset, remaining)

        for _ in range(n_for_host):
            cve_info = random.choice(CVE_DATA)
            ri = ET.SubElement(
                host_elem,
                "ReportItem",
                port=str(random.choice(ports)),
                svc_name=random.choice(services),
                protocol="tcp",
                severity=severity_map.get(cve_info["risk_factor"], "2"),
                pluginID=str(random.randint(100000, 199999)),
                pluginName=cve_info["name"],
                pluginFamily=cve_info["plugin_family"],
            )
            ET.SubElement(ri, "synopsis").text = cve_info["name"]
            ET.SubElement(ri, "description").text = cve_info["description"]
            ET.SubElement(ri, "solution").text = cve_info["solution"]
            ET.SubElement(ri, "risk_factor").text = cve_info["risk_factor"]
            ET.SubElement(ri, "cve").text = cve_info["cve"]
            ET.SubElement(ri, "cvss3_base_score").text = str(cve_info["cvss"])
            ET.SubElement(ri, "cvss_base_score").text = str(cve_info["cvss"])
            ET.SubElement(ri, "plugin_output").text = (
                f"Detected {cve_info['product']} version affected by {cve_info['cve']}."
            )

        total_written += n_for_host

    output_path = OUTPUT_DIR / "sample_nessus.nessus"
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="  ")
    except AttributeError:
        pass  # ET.indent requires Python 3.9+
    tree.write(str(output_path), encoding="utf-8", xml_declaration=True)
    print(f"  Wrote {output_path} ({total_written} findings)")


def generate_openvas_xml(assets: list[dict], n_findings: int = 40) -> None:
    """Write a valid OpenVAS GXR XML file with *n_findings* results."""
    root = ET.Element("report")
    results_elem = ET.SubElement(root, "results")

    threat_map = {
        "Critical": "High",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
    }

    for _ in range(n_findings):
        asset = random.choice(assets)
        cve_info = random.choice(CVE_DATA)

        result = ET.SubElement(results_elem, "result", id=str(uuid.uuid4()))
        ET.SubElement(result, "name").text = cve_info["name"]

        host_elem = ET.SubElement(result, "host")
        ET.SubElement(host_elem, "ip").text = asset["ip_address"]
        ET.SubElement(host_elem, "hostname").text = (
            f"{asset['hostname']}.corp.example.com"
        )

        ET.SubElement(result, "port").text = (
            f"{random.choice([22, 80, 443, 445, 8080])}/tcp"
        )

        nvt = ET.SubElement(
            result,
            "nvt",
            oid=f"1.3.6.1.4.1.25623.1.{random.randint(100000, 999999)}",
        )
        ET.SubElement(nvt, "name").text = cve_info["name"]
        ET.SubElement(nvt, "cve").text = cve_info["cve"]
        ET.SubElement(nvt, "cvss_base").text = str(cve_info["cvss"])
        ET.SubElement(nvt, "tags").text = (
            f"solution={cve_info['solution']}|summary={cve_info['description']}"
        )

        ET.SubElement(result, "threat").text = threat_map.get(
            cve_info["risk_factor"], "Medium"
        )
        ET.SubElement(result, "severity").text = str(cve_info["cvss"])
        ET.SubElement(result, "description").text = cve_info["description"]

    output_path = OUTPUT_DIR / "sample_openvas.xml"
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="  ")
    except AttributeError:
        pass  # ET.indent requires Python 3.9+
    tree.write(str(output_path), encoding="utf-8", xml_declaration=True)
    print(f"  Wrote {output_path} ({n_findings} findings)")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating sample data...")

    assets = generate_asset_inventory(20)

    csv_path = OUTPUT_DIR / "asset_inventory.csv"
    fieldnames = [
        "asset_id",
        "hostname",
        "ip_address",
        "business_unit",
        "business_owner",
        "criticality",
        "internet_exposed",
        "environment",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(assets)
    print(f"  Wrote {csv_path} ({len(assets)} assets)")

    generate_nessus_xml(assets, n_findings=80)
    generate_openvas_xml(assets, n_findings=40)

    print(f"\n✅ Sample data generated in {OUTPUT_DIR}")
    print(f"   • asset_inventory.csv  — {len(assets)} assets")
    print("   • sample_nessus.nessus — 80 findings")
    print("   • sample_openvas.xml   — 40 findings")


if __name__ == "__main__":
    main()
