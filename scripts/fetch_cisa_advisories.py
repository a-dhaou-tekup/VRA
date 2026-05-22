"""Fetch CISA KEV catalogue and write individual text files to data/rag_corpus/cisa_kev_notes/.

Idempotent — skips existing files. Safe to run weekly.
Run with: python scripts/fetch_cisa_advisories.py
"""

import json
import logging
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "rag_corpus" / "cisa_kev_notes"


def fetch_kev_catalogue() -> list[dict]:
    """Download the CISA KEV JSON and return the vulnerabilities list."""
    logger.info("Downloading CISA KEV catalogue from %s", KEV_URL)
    with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    vulns = data.get("vulnerabilities", [])
    logger.info("Downloaded %d KEV entries", len(vulns))
    return vulns


def write_vuln_file(vuln: dict, output_dir: Path) -> bool:
    """Write a single vulnerability to a text file. Returns True if written, False if skipped."""
    cve_id = vuln.get("cveID", "UNKNOWN")
    filepath = output_dir / f"{cve_id}.txt"
    if filepath.exists():
        return False

    content = (
        f"CVE ID: {cve_id}\n"
        f"Vendor: {vuln.get('vendorProject', 'N/A')}\n"
        f"Product: {vuln.get('product', 'N/A')}\n"
        f"Vulnerability Name: {vuln.get('vulnerabilityName', 'N/A')}\n"
        f"Date Added: {vuln.get('dateAdded', 'N/A')}\n"
        f"Required Action: {vuln.get('requiredAction', 'N/A')}\n"
        f"Due Date: {vuln.get('dueDate', 'N/A')}\n"
        f"Short Description: {vuln.get('shortDescription', 'N/A')}\n"
    )
    filepath.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    vulns = fetch_kev_catalogue()

    written = 0
    skipped = 0
    for i, vuln in enumerate(vulns, start=1):
        if write_vuln_file(vuln, OUTPUT_DIR):
            written += 1
        else:
            skipped += 1
        if i % 100 == 0:
            logger.info(
                "Progress: %d/%d (written=%d, skipped=%d)", i, len(vulns), written, skipped
            )

    logger.info(
        "Done. Written: %d new files, skipped: %d existing files.", written, skipped
    )
    print(
        f"✅ CISA KEV: {written} new files written, {skipped} skipped · Output: {OUTPUT_DIR}"
    )
    return written


if __name__ == "__main__":
    main()
