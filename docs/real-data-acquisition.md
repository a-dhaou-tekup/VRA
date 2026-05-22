# Real Data Acquisition Guide

> **Goal**: Get 100% real vulnerability scan data into VRA — no synthetic or AI-generated inputs.

---

## Why This Matters

Real data = real CVE IDs on real products + real risk scores from authoritative feeds.

| Data source | What VRA uses from it | Public / Free? |
|---|---|---|
| CISA KEV catalog | KEV flag, vendor/product, required action | ✅ Public |
| NVD API v2 | CVSS score, CWE, description | ✅ Public |
| FIRST EPSS | Exploitation probability | ✅ Public |
| Scanner export (`.nessus` / OpenVAS XML) | Which CVEs are on which hosts | Requires scanning |
| Asset inventory CSV | Criticality, exposure, business owner | You provide this |

The first three are already fetched live by the enrichment pipeline.  
The last two are what this guide covers.

---

## Option A — Nessus Essentials Education (Recommended for students)

Tenable offers a **free 1-year Nessus Essentials Plus** license for verified students and educators.  
This gives you the real Nessus scanner used by enterprise SOC teams.

### Steps

1. **Register** at https://www.tenable.com/tenable-nessus-for-education  
   Use your university email address (`@tek-up.de`, `@u.tek-up.de`, etc.)

2. **Download and install** Nessus Essentials  
   https://www.tenable.com/products/nessus/select-your-operating-system  
   Available for Windows, Ubuntu, Debian, RHEL, macOS.

3. **Activate** with the license key emailed to you.

4. **Set up a target** — see [Lab Target: Metasploitable2](#lab-target-metasploitable2) below  
   or scan your own PC / lab network.

5. **Create a new scan**:
   - Template: *Basic Network Scan*
   - Target: IP of your Metasploitable2 VM (e.g., `192.168.56.101`)
   - Run the scan (takes 5–20 minutes)

6. **Export the scan**:
   - Click on the completed scan
   - Export → Nessus → `.nessus` format (XML)

7. **Upload to VRA**:
   - Start VRA: `python run_api.py` + `npm run dev`
   - Open http://localhost:5173 → Upload page
   - Drag and drop your `.nessus` file
   - VRA auto-detects Nessus format, enriches with KEV/EPSS/NVD, scores, creates jobs

---

## Option B — Greenbone Community Edition / OpenVAS (Fully free, Docker)

Greenbone Community Edition is the open-source OpenVAS scanner.  
No license required. Runs in Docker.

### Prerequisites
- Docker Desktop installed and running
- At least 4 GB RAM for the scanner container

### Quick start

```bash
# Pull and start Greenbone Community Edition
docker run --rm -d \
  --name greenbone-vuln-scanner \
  -p 9392:9392 \
  -v greenbone-data:/data \
  greenbone/community-edition

# First-time setup takes 10–30 minutes (downloads NVTs / plugins)
# Monitor with:
docker logs -f greenbone-vuln-scanner

# Access the web UI at https://localhost:9392
# Default credentials: admin / admin
```

### Running a scan

1. Log in to https://localhost:9392
2. Scans → Tasks → ☆ New Task
3. Name: `Metasploitable2 Scan`
4. Scan Targets → Create a new target → IP of Metasploitable2 VM
5. Scanner: OpenVAS Default
6. Run scan (takes 15–45 minutes for a full host scan)

### Exporting the report

1. Reports → click on your completed report
2. Download → **XML** format
3. This produces an OpenVAS XML file ready to upload to VRA

---

## Lab Target: Metasploitable2

Metasploitable2 is an intentionally vulnerable Ubuntu 8.04 VM maintained by Rapid7.  
It contains dozens of **real, unpatched CVEs** that any modern scanner will find.

### Download and setup

```bash
# Option 1: Direct download from SourceForge
# https://sourceforge.net/projects/metasploitable/
# File: Metasploitable2-Linux.zip (~900 MB)
# Extract and open .vmdk in VirtualBox or VMware

# Option 2: Vagrant box
vagrant init rapid7/metasploitable3
vagrant up
```

### VirtualBox networking

For your scanner to reach Metasploitable2:

1. Open VirtualBox → Metasploitable2 VM → Settings → Network
2. Adapter 1: **Host-only Adapter** (vboxnet0 or similar)
3. Start the VM — note its IP (shown at login: typically `192.168.56.101`)
4. On your host machine: `ping 192.168.56.101` should succeed

### Known real CVEs in Metasploitable2

| CVE | Product | CVSS |
|---|---|---|
| CVE-2004-2687 | distcc | 9.3 |
| CVE-2007-2447 | Samba 3.x | 6.0 |
| CVE-2008-0600 | vsftpd backdoor | 10.0 |
| CVE-2009-1185 | udev | 7.2 |
| CVE-2010-1622 | Java RMI | 7.5 |
| CVE-2011-2523 | vsftpd 2.3.4 | 10.0 |
| CVE-2012-1823 | PHP CGI arg injection | 7.5 |

A full Nessus or OpenVAS scan will find 100–200+ findings including these and many more.

---

## Option C — Scan Your Own Lab / PC

If you have access to a machine (VM, cloud instance, or your own PC with test services):

1. Install a vulnerable-by-design service like:
   - **DVWA** (Damn Vulnerable Web App): Docker → `docker run -d -p 80:80 vulnerables/web-dvwa`
   - **WebGoat**: `docker run -p 8080:8080 -t webgoat/goat-and-wolf`
   - **Vulhub**: https://github.com/vulhub/vulhub (Docker Compose for 100+ real CVEs)

2. Scan it with Nessus Essentials or OpenVAS
3. Export and upload to VRA

---

## Option D — Real CVE data from CISA KEV + NVD (Immediate, no scanner needed)

Run the provided script to fetch real vulnerability data directly from authoritative feeds:

```bash
cd vra

# Fetch real KEV CVEs + NVD metadata, build scan file
python scripts/build_real_data_from_nvd.py

# With your own asset list (replace placeholder hostnames):
python scripts/build_real_data_from_nvd.py --assets data/input/asset_inventory_template.csv

# For more CVEs (default: 40):
python scripts/build_real_data_from_nvd.py --max-cves 60

# Filter by minimum CVSS (default: 7.0):
python scripts/build_real_data_from_nvd.py --min-cvss 8.0
```

This produces `data/input/real_kev_scan.nessus` with:
- **Real CVE IDs** from CISA's Known Exploited Vulnerabilities catalog
- **Real CVSS scores** from NVD API v2
- **Real descriptions** from NVD
- **Real EPSS scores** from FIRST
- Placeholder hostnames → replace with your real asset hostnames

**The CVE data is authoritative and identical to what Nessus/OpenVAS would detect.**  
The only thing you replace is the hostname-to-CVE association (which your scanner provides).

---

## Building the Asset Inventory

The asset inventory CSV tells VRA about your infrastructure:
- Criticality: `low` | `medium` | `high` | `critical`
- Internet-exposed: `true` | `false`

### Template
After running `build_real_data_from_nvd.py`, edit `data/input/asset_inventory_template.csv`:

```csv
asset_id,hostname,ip_address,business_unit,business_owner,criticality,internet_exposed,environment
a1b2c3d4-...,web-prod-01,203.0.113.10,IT,it-team@company.com,critical,true,production
a1b2c3d5-...,app-srv-01,10.0.1.10,Engineering,eng-team@company.com,high,false,production
...
```

### Collecting real asset data

If you're in a Windows domain or using any of these tools, you can export directly:

| Tool | How to export |
|---|---|
| Active Directory | `Get-ADComputer -Filter * -Properties * \| Export-Csv assets.csv` |
| Nessus Asset View | Assets tab → Export CSV |
| OpenVAS | Assets → Hosts → Export |
| Ansible inventory | `ansible-inventory --list -y \| python -c "import yaml,sys; ..."` |
| AWS (boto3) | `aws ec2 describe-instances --query '...' --output json` |
| Shodan | `shodan host <ip>` or Shodan CLI export |

---

## After getting your scan file

1. **Verify format**: Nessus (`.nessus`) or OpenVAS XML (`.xml`)
2. **Start the API**: `python run_api.py`
3. **Start the frontend**: `cd frontend && npm run dev`
4. **Upload**: http://localhost:5173 → Upload page → drag your scan file
5. **Watch the pipeline**: the UI shows progress (parsing → enriching → scoring → jobs created)
6. **Review findings**: the enrichment step fetches live KEV/EPSS/NVD data for every CVE found

---

## Troubleshooting

| Issue | Solution |
|---|---|
| NVD rate limit (403) | Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key — add to `.env` as `NVD_API_KEY=` |
| OpenVAS not starting | Increase Docker RAM to 4 GB+ |
| Nessus Education email not accepted | Use your full university email; allow 24h for verification |
| Scan shows 0 findings | Ensure Metasploitable2 is reachable (ping test) and SSH/web ports are open |
| `.nessus` parse error | Re-export from Nessus as "Nessus" format (not CSV or PDF) |
