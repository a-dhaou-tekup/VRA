/**
 * Compute the human-readable job label:
 *   [first_asset_id_8chars]_[risk_score]_[first_cve]_[DD/MM/YYYY]
 *
 * Falls back gracefully when fields are missing.
 */
export function jobLabel(job) {
  if (!job) return ''

  // ── First asset ID (first 8 chars) ────────────────────────────────────────
  let assetPart = 'ASSET'
  const assetIds = job.asset_ids
  if (assetIds) {
    try {
      const parsed = typeof assetIds === 'string' ? JSON.parse(assetIds) : assetIds
      const first  = Array.isArray(parsed) ? parsed[0] : String(assetIds).split(',')[0].trim()
      if (first) assetPart = String(first).slice(0, 8).toUpperCase()
    } catch {
      assetPart = String(assetIds).split(',')[0].trim().slice(0, 8).toUpperCase()
    }
  }

  // ── Risk / CVSS score ──────────────────────────────────────────────────────
  const score = job.risk_score_max ?? job.max_cvss_score ?? job.cvss_score ?? '?'
  const scorePart = score !== '?' ? Number(score).toFixed(1) : '?'

  // ── First CVE ──────────────────────────────────────────────────────────────
  let cvePart = 'N/A'
  const cveRaw = job.cve_list ?? job.cves
  if (cveRaw) {
    try {
      const parsed = typeof cveRaw === 'string' ? JSON.parse(cveRaw) : cveRaw
      const first  = Array.isArray(parsed) ? parsed[0] : String(cveRaw).split(',')[0].trim()
      if (first) cvePart = String(first).trim()
    } catch {
      cvePart = String(cveRaw).split(',')[0].trim() || 'N/A'
    }
  }

  // ── Date (DD/MM/YYYY) ──────────────────────────────────────────────────────
  let datePart = '??/??/????'
  const raw = job.job_created_at ?? job.created_at
  if (raw) {
    const d = new Date(raw)
    if (!isNaN(d.getTime())) {
      const dd   = String(d.getDate()).padStart(2, '0')
      const mm   = String(d.getMonth() + 1).padStart(2, '0')
      const yyyy = d.getFullYear()
      datePart = `${dd}/${mm}/${yyyy}`
    }
  }

  return `${assetPart}_${scorePart}_${cvePart}_${datePart}`
}
