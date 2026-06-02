"""Few-shot examples and system prompt for the LLM ingest parser.

Edit this file to improve extraction quality without touching parser logic.
FEW_SHOT_EXAMPLES is a list of {role, content} dicts ready to be spliced
into the Ollama messages array before the real user turn.
"""

SYSTEM_PROMPT = (
    "You are a security data extraction engine.\n"
    "Extract vulnerability findings from the given text and return ONLY valid JSON.\n"
    "Do not include markdown fences, explanations, or any text outside the JSON.\n"
    "\n"
    'Return a JSON object with a single key "findings" containing an array.\n'
    "Each finding must have exactly these fields:\n"
    "  - cve_id: string or null  (format CVE-YYYY-NNNNN if present, else null)\n"
    "  - severity: string        (one of: critical, high, medium, low, info)\n"
    "  - component: string       (software name, package, or service affected)\n"
    "  - component_version: string or null  (version number if present, else null)\n"
    "  - affected_host: string   (hostname or IP address of the affected system)\n"
    "  - port: integer or null   (network port if mentioned, else null)\n"
    "  - raw_description: string (one-sentence description of the vulnerability)\n"
    "\n"
    "Rules:\n"
    "  - If one block mentions multiple CVEs for the same host/component, emit one finding per CVE.\n"
    "  - Normalize severity to lowercase (critical/high/medium/low/info).\n"
    "  - If no CVE ID is present use null — do NOT invent one.\n"
    "  - If host information is absent, use 'unknown'.\n"
    "  - Respond with valid JSON only. Match the schema exactly."
)

# Each consecutive pair is a user-input + expected-output shot.
# These are spliced verbatim into the messages array before the real query.
FEW_SHOT_EXAMPLES = [
    # ── Example 1: Nessus-style plugin row ──────────────────────────────────────
    {
        "role": "user",
        "content": (
            "Extract vulnerability findings from this text:\n\n"
            "Plugin ID: 59275\n"
            "Plugin Name: MS17-010 — Microsoft Windows SMBv1 Multiple Vulnerabilities (EternalBlue)\n"
            "Host: 192.168.1.101\n"
            "Port: 445 / tcp\n"
            "CVE: CVE-2017-0144\n"
            "Risk: Critical\n"
            "CVSS Base Score: 9.3\n"
            "Description: The remote Windows host has SMBv1 enabled and is missing "
            "security patches for vulnerabilities exploited by EternalBlue / WannaCry."
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"findings": ['
            '{"cve_id": "CVE-2017-0144", "severity": "critical", '
            '"component": "Microsoft Windows SMBv1", "component_version": null, '
            '"affected_host": "192.168.1.101", "port": 445, '
            '"raw_description": "SMBv1 is enabled and unpatched; exploitable by EternalBlue/WannaCry."}'
            "]}"
        ),
    },
    # ── Example 2: informal vendor-email export ──────────────────────────────────
    {
        "role": "user",
        "content": (
            "Extract vulnerability findings from this text:\n\n"
            "From: security-alerts@vendor.com\n"
            "Subject: Critical Patch Advisory\n\n"
            "Dear Team,\n\n"
            "Server web-prod-03 running Apache Log4j 2.14.1 is affected by "
            "CVE-2021-44228 (Log4Shell), a critical remote code execution flaw (CVSS 10.0). "
            "The same host also runs OpenSSL 1.0.2k affected by CVE-2022-0778 "
            "(high severity, TLS DoS) on port 443.\n\n"
            "Please patch immediately."
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"findings": ['
            '{"cve_id": "CVE-2021-44228", "severity": "critical", '
            '"component": "Apache Log4j", "component_version": "2.14.1", '
            '"affected_host": "web-prod-03", "port": null, '
            '"raw_description": "Critical RCE in Log4j 2.14.1 (Log4Shell), CVSS 10.0."}, '
            '{"cve_id": "CVE-2022-0778", "severity": "high", '
            '"component": "OpenSSL", "component_version": "1.0.2k", '
            '"affected_host": "web-prod-03", "port": 443, '
            '"raw_description": "TLS denial-of-service vulnerability in OpenSSL 1.0.2k."}'
            "]}"
        ),
    },
    # ── Example 3: PDF-style text dump (vulnerability assessment report) ─────────
    {
        "role": "user",
        "content": (
            "Extract vulnerability findings from this text:\n\n"
            "VULNERABILITY ASSESSMENT REPORT\n"
            "Target: db-server-12 (10.0.0.55)\n\n"
            "1. MySQL 5.7.32 — Unpatched (High)\n"
            "   CVE: CVE-2020-14812, CVE-2020-14765\n"
            "   Port: 3306\n"
            "   Description: Multiple MySQL vulnerabilities allow unauthenticated "
            "remote attackers to crash the server.\n\n"
            "2. PHP 7.3.27 — Use After Free (Medium)\n"
            "   CVE: CVE-2021-21702\n"
            "   Port: 80\n"
            "   Description: Use-after-free in SOAP extension may cause crashes "
            "or memory disclosure.\n\n"
            "3. SSH banner disclosure on port 22 — Informational (no CVE)."
        ),
    },
    {
        "role": "assistant",
        "content": (
            '{"findings": ['
            '{"cve_id": "CVE-2020-14812", "severity": "high", '
            '"component": "MySQL", "component_version": "5.7.32", '
            '"affected_host": "db-server-12", "port": 3306, '
            '"raw_description": "MySQL DoS: unauthenticated remote crash."}, '
            '{"cve_id": "CVE-2020-14765", "severity": "high", '
            '"component": "MySQL", "component_version": "5.7.32", '
            '"affected_host": "db-server-12", "port": 3306, '
            '"raw_description": "MySQL DoS: unauthenticated remote crash."}, '
            '{"cve_id": "CVE-2021-21702", "severity": "medium", '
            '"component": "PHP", "component_version": "7.3.27", '
            '"affected_host": "db-server-12", "port": 80, '
            '"raw_description": "Use-after-free in PHP SOAP extension."}, '
            '{"cve_id": null, "severity": "info", '
            '"component": "OpenSSH", "component_version": null, '
            '"affected_host": "db-server-12", "port": 22, '
            '"raw_description": "SSH version banner disclosure — informational."}'
            "]}"
        ),
    },
]
