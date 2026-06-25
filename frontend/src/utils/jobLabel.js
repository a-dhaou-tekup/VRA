/**
 * Compute a human-readable job title:
 *   {product} — {hostname} — {first_cve} [+N more]
 *
 * Falls back gracefully when fields are missing:
 *   "Microsoft SharePoint Server — sharepoint-01 — CVE-2019-0604"
 *   "Apache Log4j2 — prod-api-01 — CVE-2021-44228 +1 more"
 *   "PAN-OS — CVE-2024-3400"   (no hostname available)
 */
export function jobLabel(job) {
  if (!job) return ''

  const product = job.main_product || job.product_name || 'Unknown'

  // First hostname from the enriched asset_hostnames array (added by backend)
  let hostPart = ''
  const hostnames = job.asset_hostnames
  if (Array.isArray(hostnames) && hostnames.length > 0) {
    hostPart = hostnames[0].hostname || ''
    if (hostnames.length > 1) hostPart += ` +${hostnames.length - 1}`
  }

  // First CVE (+ count if multiple)
  let cvePart = ''
  const cveRaw = job.cve_list ?? job.cves
  if (cveRaw) {
    try {
      const parsed = typeof cveRaw === 'string' ? JSON.parse(cveRaw) : cveRaw
      const arr = Array.isArray(parsed)
        ? parsed
        : String(cveRaw).split(',').map(s => s.trim()).filter(Boolean)
      if (arr.length > 0) {
        cvePart = arr[0]
        if (arr.length > 1) cvePart += ` +${arr.length - 1} more`
      }
    } catch {
      cvePart = String(cveRaw).split(',')[0].trim()
    }
  }

  const parts = [product, hostPart, cvePart].filter(Boolean)
  return parts.join(' — ')
}
