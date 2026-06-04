#!/usr/bin/env python3
"""seed_software_inventory.py — fill asset_software for all 74 platform.db assets.

Each asset receives:
  • OS-layer packages (openssl, curl, sudo, glibc, openssh, kernel …)
  • Role-specific packages inferred from hostname
  • Deliberately realistic versions — some vulnerable — so threat matching
    produces meaningful KEV / high-EPSS alerts.

Usage
-----
    python scripts/seed_software_inventory.py          # platform.db
    python scripts/seed_software_inventory.py demo     # demo.db
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT        = Path(__file__).parent.parent
PLATFORM_DB = ROOT / "data" / "cache" / "platform.db"
DEMO_DB     = ROOT / "data" / "cache" / "demo.db"
NOW         = datetime.now(timezone.utc).isoformat()

# ── Software libraries ────────────────────────────────────────────────────────
# Each entry: (product, version, vendor, cpe_or_None)

# ── Linux common ─────────────────────────────────────────────────────────────
LINUX_BASE = [
    ("openssl",       "1.1.1k",  "OpenSSL",       "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"),
    ("curl",          "7.68.0",  "curl",          "cpe:2.3:a:haxx:curl:7.68.0:*:*:*:*:*:*:*"),
    ("sudo",          "1.8.31",  "sudo",          "cpe:2.3:a:sudo_project:sudo:1.8.31:*:*:*:*:*:*:*"),
    ("glibc",         "2.35",    "GNU",           "cpe:2.3:a:gnu:glibc:2.35:*:*:*:*:*:*:*"),
    ("openssh-server","8.9p1",   "OpenBSD",       "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"),
    ("bash",          "5.1.16",  "GNU",           None),
    ("tar",           "1.34",    "GNU",           None),
    ("python3",       "3.10.12", "Python",        None),
]

LINUX_BASE_NEWER = [
    ("openssl",       "3.0.8",   "OpenSSL",       "cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*"),
    ("curl",          "7.88.1",  "curl",          "cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*"),
    ("sudo",          "1.9.13",  "sudo",          None),
    ("glibc",         "2.37",    "GNU",           None),
    ("openssh-server","9.3p1",   "OpenBSD",       None),
    ("bash",          "5.2.15",  "GNU",           None),
    ("python3",       "3.11.4",  "Python",        None),
]

RHEL9_BASE = [
    ("openssl",       "3.0.7",   "OpenSSL",       "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"),
    ("curl",          "7.76.1",  "curl",          "cpe:2.3:a:haxx:curl:7.76.1:*:*:*:*:*:*:*"),
    ("sudo",          "1.9.5p2", "sudo",          None),
    ("glibc",         "2.34",    "GNU",           "cpe:2.3:a:gnu:glibc:2.34:*:*:*:*:*:*:*"),
    ("openssh-server","8.7p1",   "OpenBSD",       None),
    ("bash",          "5.1.8",   "GNU",           None),
    ("python3",       "3.9.16",  "Python",        None),
]

# ── Windows common ────────────────────────────────────────────────────────────
WIN_BASE = [
    ("Windows",              "Server 2022 21H2", "Microsoft", "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"),
    ("openssl",              "1.1.1t",           "OpenSSL",   "cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*"),
    ("curl",                 "8.0.1",            "curl",      None),
    ("Microsoft Visual C++", "14.36.32532",      "Microsoft", None),
]

WIN10_BASE = [
    ("Windows 10",    "22H2 19045",  "Microsoft", "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:*:*"),
    ("Microsoft Edge","115.0.1901",  "Microsoft", None),
    ("openssl",       "1.1.1t",      "OpenSSL",   None),
    ("curl",          "8.1.2",       "curl",      None),
]

WIN11_BASE = [
    ("Windows 11",    "22H2 22621",  "Microsoft", "cpe:2.3:o:microsoft:windows_11_22h2:-:*:*:*:*:*:*:*"),
    ("Microsoft Edge","115.0.1901",  "Microsoft", None),
    ("openssl",       "1.1.1t",      "OpenSSL",   None),
    ("curl",          "8.1.2",       "curl",      None),
]

WIN_OFFICE_2019 = [
    ("Microsoft Office", "2019 16.0.10399", "Microsoft", "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"),
    ("Microsoft Outlook","2019 16.0.14326", "Microsoft", "cpe:2.3:a:microsoft:outlook:2019:*:*:*:*:*:*:*"),
    ("Microsoft Word",   "2019 16.0.14326", "Microsoft", None),
    ("Microsoft Excel",  "2019 16.0.14326", "Microsoft", None),
]

MACOS_BASE = [
    ("macOS",         "14.0",    "Apple",   "cpe:2.3:o:apple:macos:14.0:*:*:*:*:*:*:*"),
    ("openssl",       "3.1.2",   "OpenSSL", None),
    ("curl",          "8.1.2",   "curl",    None),
    ("bash",          "3.2.57",  "GNU",     None),
    ("python3",       "3.11.5",  "Python",  None),
]

# ── Role-specific ─────────────────────────────────────────────────────────────
NGINX = [
    ("nginx",         "1.24.0",  "nginx Inc", "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"),
    ("certbot",       "2.6.0",   "EFF",       None),
]

NGINX_OLD = [
    ("nginx",         "1.18.0",  "nginx Inc", "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"),
]

APACHE = [
    ("Apache HTTP Server", "2.4.49", "Apache", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
]

JAVA_SPRING = [
    ("log4j-core",    "2.14.1",  "Apache",  "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
    ("log4j-api",     "2.14.1",  "Apache",  None),
    ("spring-webmvc", "5.3.17",  "VMware",  "cpe:2.3:a:pivotal_software:spring_framework:5.3.17:*:*:*:*:*:*:*"),
    ("spring-core",   "5.3.17",  "VMware",  None),
    ("spring-boot",   "2.6.6",   "VMware",  None),
    ("tomcat",        "9.0.60",  "Apache",  "cpe:2.3:a:apache:tomcat:9.0.60:*:*:*:*:*:*:*"),
    ("commons-text",  "1.9.0",   "Apache",  "cpe:2.3:a:apache:commons_text:1.9:*:*:*:*:*:*:*"),
    ("jackson-databind","2.13.2","FasterXML",None),
]

JAVA_API_NEWER = [
    ("log4j-core",    "2.17.2",  "Apache",  None),   # patched
    ("spring-boot",   "3.1.2",   "VMware",  None),
    ("spring-webmvc", "6.0.11",  "VMware",  None),
    ("tomcat",        "10.1.12", "Apache",  None),
]

PYTHON_API = [
    ("FastAPI",       "0.111.0", "Sebastián Ramírez", None),
    ("uvicorn",       "0.30.1",  "Encode",            None),
    ("requests",      "2.31.0",  "PSF",               None),
    ("pydantic",      "2.7.0",   "Pydantic",          None),
]

POSTGRES = [
    ("postgresql",    "14.8",    "PostgreSQL Global Development Group",
     "cpe:2.3:a:postgresql:postgresql:14.8:*:*:*:*:*:*:*"),
    ("pgbouncer",     "1.21.0",  "pgBouncer",  None),
]

MYSQL = [
    ("mysql-server",  "8.0.33",  "Oracle",
     "cpe:2.3:a:oracle:mysql:8.0.33:*:*:*:*:*:*:*"),
]

REDIS = [
    ("redis",         "7.0.12",  "Redis Ltd",
     "cpe:2.3:a:redis:redis:7.0.12:*:*:*:*:*:*:*"),
]

ELASTICSEARCH = [
    ("elasticsearch", "8.9.0",   "Elastic",   None),
    ("kibana",        "8.9.0",   "Elastic",   None),
    ("logstash",      "8.9.0",   "Elastic",   None),
]

K8S = [
    ("kubelet",       "1.27.4",  "CNCF",      None),
    ("kubectl",       "1.27.4",  "CNCF",      None),
    ("containerd",    "1.7.2",   "CNCF",      None),
    ("runc",          "1.1.9",   "CNCF",      None),
    ("helm",          "3.12.3",  "CNCF",      None),
]

FORTIOS = [
    ("FortiOS",        "7.4.2",  "Fortinet",
     "cpe:2.3:o:fortinet:fortios:7.4.2:*:*:*:*:*:*:*"),
    ("FortiGate SSL-VPN", "7.4.2", "Fortinet", None),
]

FORTIOS_OLD = [
    ("FortiOS",        "7.2.4",  "Fortinet",
     "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"),
]

PAN_OS_11 = [
    ("PAN-OS",         "11.0.3", "Palo Alto Networks",
     "cpe:2.3:o:paloaltonetworks:pan-os:11.0.3:*:*:*:*:*:*:*"),
    ("GlobalProtect",  "6.2.0",  "Palo Alto Networks", None),
]

PAN_OS_10 = [
    ("PAN-OS",         "10.2.4", "Palo Alto Networks",
     "cpe:2.3:o:paloaltonetworks:pan-os:10.2.4:*:*:*:*:*:*:*"),
]

CISCO_IOS = [
    ("Cisco IOS XE",   "16.12.7","Cisco",
     "cpe:2.3:o:cisco:ios_xe:16.12.7:*:*:*:*:*:*:*"),
]

CISCO_NXOS = [
    ("Cisco NX-OS",    "9.3.10", "Cisco",     None),
]

OPENLDAP = [
    ("openldap",       "2.6.4",  "OpenLDAP",
     "cpe:2.3:a:openldap:openldap:2.6.4:*:*:*:*:*:*:*"),
    ("sssd",           "2.8.2",  "SSSD",      None),
]

EXCHANGE = [
    ("Microsoft Exchange Server", "2019 CU12", "Microsoft",
     "cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_12:*:*:*:*:*:*"),
    ("Microsoft Outlook",         "2019 16.0.14326", "Microsoft",
     "cpe:2.3:a:microsoft:outlook:2019:*:*:*:*:*:*:*"),
]

SHAREPOINT = [
    ("Microsoft SharePoint Server","2019 16.0.10399","Microsoft",
     "cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*"),
    ("Microsoft .NET Framework",   "4.8",             "Microsoft", None),
]

JENKINS = [
    ("Jenkins",        "2.387.3", "Jenkins",
     "cpe:2.3:a:jenkins:jenkins:2.387.3:*:*:*:*:*:*:*"),
    ("Docker",         "24.0.5",  "Docker",    None),
    ("git",            "2.41.0",  "Git SCM",   None),
]

HAPROXY = [
    ("haproxy",        "2.8.1",   "HAProxy",
     "cpe:2.3:a:haproxy:haproxy:2.8.1:*:*:*:*:*:*:*"),
    ("keepalived",     "2.2.7",   "keepalived",None),
]

NFS_BACKUP = [
    ("rsync",          "3.2.7",   "rsync.net", None),
    ("restic",         "0.16.0",  "restic",    None),
    ("nfs-kernel-server","2:2.6.2","Debian",   None),
]

MONITORING = [
    ("Prometheus",     "2.46.0",  "CNCF",      None),
    ("Grafana",        "10.1.0",  "Grafana",   None),
    ("node_exporter",  "1.6.1",   "Prometheus",None),
    ("alertmanager",   "0.26.0",  "Prometheus",None),
]

PRINT_SPOOLER = [
    ("Windows Print Spooler", "10.0.20348", "Microsoft",
     "cpe:2.3:a:microsoft:windows_print_spooler:*:*:*:*:*:*:*:*"),
]


# ── Role-assignment rules ─────────────────────────────────────────────────────
# (hostname_substring, software_lists)  — checked in order, all matching rules apply

RULES: list[tuple[str, list]] = [
    # ── Web servers ────────────────────────────────────────────────────────────
    ("web-prod-01",   [LINUX_BASE, NGINX]),
    ("web-prod-02",   [LINUX_BASE, NGINX]),
    ("web-prod-03",   [LINUX_BASE_NEWER, NGINX_OLD]),
    ("prod-web-01",   [LINUX_BASE, NGINX]),
    ("prod-web-02",   [LINUX_BASE_NEWER, NGINX]),
    ("staging-web-01",[LINUX_BASE, APACHE]),
    ("cdn-edge-01",   [LINUX_BASE_NEWER, NGINX]),
    ("proxy-prod-01", [LINUX_BASE_NEWER, HAPROXY]),

    # ── API / application servers ──────────────────────────────────────────────
    ("api-prod-01",   [LINUX_BASE, JAVA_SPRING, PYTHON_API]),
    ("api-prod-02",   [LINUX_BASE, JAVA_SPRING]),
    ("prod-api-01",   [LINUX_BASE, JAVA_SPRING]),
    ("prod-api-02",   [LINUX_BASE, JAVA_SPRING]),
    ("prod-api-gw-01",[LINUX_BASE, HAPROXY, NGINX]),
    ("app-prod-01",   [WIN_BASE, WIN_OFFICE_2019]),
    ("app-prod-02",   [WIN_BASE, WIN_OFFICE_2019]),
    ("app-dev-01",    [LINUX_BASE_NEWER, JAVA_API_NEWER]),
    ("app-dev-02",    [LINUX_BASE_NEWER, JAVA_API_NEWER]),
    ("app-srv-prod-01",[LINUX_BASE, JAVA_SPRING, PYTHON_API]),

    # ── Databases ─────────────────────────────────────────────────────────────
    ("db-prod-01",    [WIN_BASE, MYSQL, PRINT_SPOOLER]),
    ("db-prod-02",    [WIN_BASE, MYSQL, PRINT_SPOOLER]),
    ("db-staging-01", [WIN_BASE, MYSQL]),
    ("db-staging-02", [RHEL9_BASE, POSTGRES]),
    ("prod-db-primary-01",[LINUX_BASE, POSTGRES]),
    ("prod-db-replica-01",[LINUX_BASE, POSTGRES]),

    # ── Cache ──────────────────────────────────────────────────────────────────
    ("prod-redis-01", [LINUX_BASE_NEWER, REDIS]),

    # ── Search / logging / SIEM ────────────────────────────────────────────────
    ("prod-elk-01",   [LINUX_BASE_NEWER, ELASTICSEARCH]),
    ("log-prod-01",   [RHEL9_BASE, ELASTICSEARCH]),
    ("siem-prod-01",  [
        ("Wazuh", "4.5.2", "Wazuh", None),
        ("elasticsearch","8.9.0","Elastic",None),
    ]),

    # ── Kubernetes ─────────────────────────────────────────────────────────────
    ("k8s-master-01",   [LINUX_BASE_NEWER, K8S]),
    ("k8s-node-01",     [LINUX_BASE, K8S]),
    ("k8s-node-02",     [LINUX_BASE, K8S]),
    ("k8s-node-03",     [LINUX_BASE, K8S]),
    ("prod-k8s-master-01",[LINUX_BASE, K8S]),
    ("prod-k8s-worker-01",[LINUX_BASE, K8S]),
    ("prod-k8s-worker-02",[LINUX_BASE, K8S]),

    # ── Directory / LDAP ──────────────────────────────────────────────────────
    ("prod-ldap-01",  [LINUX_BASE, OPENLDAP]),
    ("jump-prod-01",  [RHEL9_BASE, OPENLDAP]),

    # ── Mail / collaboration ───────────────────────────────────────────────────
    ("mail-prod-01",  [WIN_BASE, EXCHANGE]),
    ("mail-srv-01",   [WIN_BASE, EXCHANGE]),
    ("sharepoint-01", [WIN_BASE, SHAREPOINT, PRINT_SPOOLER]),

    # ── Firewalls / VPN ────────────────────────────────────────────────────────
    ("fortigate-fw-01",[FORTIOS]),
    ("fw-dc-lyon-01",  [FORTIOS_OLD]),
    ("fw-dc-paris-01", [PAN_OS_11]),
    ("fw-dc-paris-02", [PAN_OS_11]),
    ("vpn-gw-01",      [PAN_OS_11]),
    ("vpn-gw-prod-01", [PAN_OS_11]),
    ("vpn-prod-01",    [PAN_OS_10]),

    # ── Switches ──────────────────────────────────────────────────────────────
    ("sw-core-01",    [CISCO_IOS]),
    ("sw-core-02",    [CISCO_IOS]),
    ("sw-access-01",  [CISCO_NXOS]),

    # ── CI / CD ────────────────────────────────────────────────────────────────
    ("ci-runner-01",  [LINUX_BASE_NEWER, JENKINS]),
    ("ci-runner-02",  [LINUX_BASE_NEWER, JENKINS]),

    # ── Monitoring ─────────────────────────────────────────────────────────────
    ("mon-prod-01",   [RHEL9_BASE, MONITORING]),

    # ── NAS / backup ──────────────────────────────────────────────────────────
    ("nas-prod-01",   [NFS_BACKUP]),
    ("backup-prod-01",[WIN_BASE, NFS_BACKUP]),

    # ── Developer workstations ─────────────────────────────────────────────────
    ("app-dev-01",    [LINUX_BASE_NEWER]),   # already matched above
    ("vm-dev-01",     [LINUX_BASE_NEWER, PYTHON_API]),
    ("vm-staging-01", [LINUX_BASE_NEWER, PYTHON_API]),
    ("vm-staging-02", [RHEL9_BASE]),
    ("vm-test-01",    [LINUX_BASE_NEWER]),
    ("vm-test-02",    [WIN_BASE]),
    ("linux0002",     [RHEL9_BASE, JAVA_SPRING]),

    # ── Finance workstations ──────────────────────────────────────────────────
    ("workstation-fin-01",[WIN11_BASE, WIN_OFFICE_2019, PRINT_SPOOLER]),
    ("workstation-fin-02",[WIN11_BASE, WIN_OFFICE_2019]),
    ("ws-finance-01",    [WIN11_BASE, WIN_OFFICE_2019]),
    ("ws-finance-02",    [WIN10_BASE, WIN_OFFICE_2019]),
    ("ws-hr-01",         [WIN11_BASE, WIN_OFFICE_2019]),
    ("ws-legal-01",      [WIN11_BASE, WIN_OFFICE_2019]),
    ("ws-mktg-01",       [MACOS_BASE, [
        ("Microsoft Office for Mac","16.76","Microsoft",None),
        ("Google Chrome","116.0.5845","Google",None),
    ]]),

    # ── Laptops ────────────────────────────────────────────────────────────────
    ("LAPTOP_CISO",        [WIN_BASE, WIN_OFFICE_2019]),
    ("laptop-kbouaziz",    [WIN11_BASE, WIN_OFFICE_2019]),
    ("laptop-ldupont",     [WIN11_BASE, WIN_OFFICE_2019]),
    ("laptop-lfernandez",  [MACOS_BASE]),
    ("laptop-smartin",     [WIN11_BASE, WIN_OFFICE_2019]),
    ("laptop-yamrani",     [LINUX_BASE_NEWER, PYTHON_API]),
]


def seed(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    assets = {
        r["hostname"]: r["asset_id"]
        for r in conn.execute("SELECT asset_id, hostname FROM assets").fetchall()
        if r["hostname"]
    }
    print(f"  Assets found: {len(assets)}")

    ins = 0; dup = 0; unmatched: list[str] = []

    # Build a per-hostname → flat software list
    assigned: dict[str, list[tuple]] = {}

    for hostname, asset_id in assets.items():
        sw_rows: list[tuple] = []
        hn_low = hostname.lower()

        for pattern, lists in RULES:
            if pattern.lower() in hn_low:
                for sw_list in lists:
                    if isinstance(sw_list, list):
                        for item in sw_list:
                            if isinstance(item, tuple):
                                sw_rows.append(item)
                            elif isinstance(item, list):
                                sw_rows.extend(item)

        # Deduplicate within the same asset (product+version key)
        seen: set[tuple] = set()
        unique: list[tuple] = []
        for row in sw_rows:
            key = (row[0], row[1])
            if key not in seen:
                seen.add(key)
                unique.append(row)

        assigned[hostname] = unique
        if not unique:
            unmatched.append(hostname)

    # Insert
    for hostname, sw_list in assigned.items():
        asset_id = assets[hostname]
        for product, version, vendor, cpe in sw_list:
            try:
                conn.execute(
                    """INSERT INTO asset_software
                           (asset_id, product, version, vendor, cpe, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(asset_id, product, version) DO UPDATE SET
                           vendor = excluded.vendor,
                           cpe    = excluded.cpe""",
                    (asset_id, product, version or "", vendor, cpe, NOW),
                )
                ins += 1
            except Exception as exc:
                print(f"    WARN {hostname}/{product}: {exc}")

    conn.commit()

    total = conn.execute("SELECT COUNT(*) FROM asset_software").fetchone()[0]
    conn.close()

    print(f"  Rows inserted/updated: {ins}")
    print(f"  Total software entries: {total}")
    if unmatched:
        print(f"  Unmatched assets ({len(unmatched)}): {', '.join(unmatched)}")
    else:
        print("  All assets matched.")


def main() -> None:
    target  = sys.argv[1] if len(sys.argv) > 1 else "dev"
    db_path = DEMO_DB if target == "demo" else PLATFORM_DB

    if not db_path.exists():
        print(f"\nERROR: {db_path} not found. Start the API once to run migrations.\n")
        sys.exit(1)

    print(f"\nSeeding software inventory into: {db_path}\n")
    seed(db_path)
    print("\nDone. Run POST /api/threat-alerts/match (force_reset=true) to re-run matching.\n")


if __name__ == "__main__":
    main()
