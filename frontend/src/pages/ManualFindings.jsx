import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { submitManualFindings, fetchManualExample, fetchUpload } from '../api/client'

const SEVERITIES = ['critical', 'high', 'medium', 'low']

const EMPTY_ROW = {
  cve_id: '',
  hostname: '',
  ip_address: '',
  cvss_base_score: '',
  severity: 'high',
  vuln_title: '',
  plugin_family: '',
}

export default function ManualFindings() {
  const navigate = useNavigate()
  const [rows, setRows] = useState([{ ...EMPTY_ROW }])
  const [uploadedBy, setUploadedBy] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [uploadId, setUploadId] = useState(null)
  const [pipelineStatus, setPipelineStatus] = useState(null)
  const [pipelineStats, setPipelineStats] = useState(null)

  const setRow = (i, patch) => {
    setRows((curr) => curr.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  }
  const addRow = () => setRows((r) => [...r, { ...EMPTY_ROW }])
  const removeRow = (i) => setRows((r) => r.filter((_, idx) => idx !== i))

  const loadExample = async () => {
    const r = await fetchManualExample()
    const ex = r.data?.data?.findings ?? []
    setRows(ex.map((f) => ({
      cve_id:           f.cve_id,
      hostname:         f.hostname,
      ip_address:       f.ip_address || '',
      cvss_base_score:  String(f.cvss_base_score ?? ''),
      severity:         f.severity,
      vuln_title:       f.vuln_title || '',
      plugin_family:    f.plugin_family || '',
    })))
  }

  const validateRow = (r) => {
    if (!r.cve_id || !/^CVE-\d{4}-\d{4,}$/i.test(r.cve_id.trim())) {
      return `cve_id must match CVE-YYYY-NNNN (got "${r.cve_id}")`
    }
    if (!r.hostname) return 'hostname required'
    const cvss = parseFloat(r.cvss_base_score)
    if (r.cvss_base_score && (isNaN(cvss) || cvss < 0 || cvss > 10)) {
      return 'cvss_base_score must be 0-10'
    }
    return null
  }

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    setPipelineStatus(null)
    setUploadId(null)

    const validRows = []
    for (let i = 0; i < rows.length; i++) {
      const err = validateRow(rows[i])
      if (err) {
        setError(`Row ${i + 1}: ${err}`)
        return
      }
      validRows.push({
        cve_id:          rows[i].cve_id.trim().toUpperCase(),
        hostname:        rows[i].hostname.trim(),
        ip_address:      rows[i].ip_address.trim(),
        cvss_base_score: parseFloat(rows[i].cvss_base_score) || 0.0,
        severity:        rows[i].severity,
        vuln_title:      rows[i].vuln_title.trim(),
        plugin_family:   rows[i].plugin_family.trim(),
      })
    }

    setSubmitting(true)
    try {
      const r = await submitManualFindings({
        findings:    validRows,
        uploaded_by: uploadedBy || 'manual-entry',
      })
      const id = r.data?.data?.id
      setUploadId(id)
      // Poll for pipeline completion
      const pollId = setInterval(async () => {
        try {
          const u = await fetchUpload(id)
          const rec = u.data?.data
          setPipelineStatus(rec?.status)
          if (rec?.status === 'done' || rec?.status === 'failed') {
            clearInterval(pollId)
            setPipelineStats(rec?.stats_json)
          }
        } catch {
          /* keep polling */
        }
      }, 1500)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="p-10 max-w-[1400px] mx-auto">
      <div className="mb-8">
        <div className="mono-label text-[var(--amber)] mb-2">MANUAL ENTRY</div>
        <h1 className="font-syne text-3xl font-bold text-white">Add Findings by Hand</h1>
        <p className="text-sm text-[var(--muted)] mt-2 max-w-3xl">
          Use this when you have CVE intelligence but no scanner export. Each finding is
          routed through the same pipeline as uploaded files: enriched with CISA KEV,
          FIRST EPSS, and NVD data, then risk-scored and grouped into jobs.
        </p>
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded bg-[rgba(224,82,82,0.1)] border border-[rgba(224,82,82,0.3)] text-sm text-[var(--red)]">
          {error}
        </div>
      )}

      {uploadId && (
        <div className="mb-6 p-4 rounded bg-[var(--surface)] border border-[var(--border)]">
          <div className="mono-label mb-2">Submission: {uploadId.slice(0, 8)}…</div>
          <div className="text-sm text-white">
            Pipeline status: <span className="text-[var(--amber)] font-mono">{pipelineStatus || 'pending'}</span>
          </div>
          {pipelineStats && (
            <div className="mt-3 text-xs text-[var(--muted)] font-mono">
              ✓ {pipelineStats.new_jobs} new jobs · {pipelineStats.updated_jobs} updated · {pipelineStats.total_cve_count} CVEs · {pipelineStats.total_asset_count} assets
              <button onClick={() => navigate('/jobs')}
                className="ml-3 text-[var(--amber)] hover:underline">View jobs →</button>
            </div>
          )}
        </div>
      )}

      <form onSubmit={submit}>
        <div className="mb-4 flex items-center gap-3">
          <input
            placeholder="Your name (uploaded_by)"
            value={uploadedBy}
            onChange={(e) => setUploadedBy(e.target.value)}
            className="px-3 py-2 rounded text-sm bg-[var(--surface)] border border-[var(--border)] text-white"
          />
          <button type="button" onClick={loadExample}
            className="px-3 py-2 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-[var(--amber)] hover:bg-[var(--surface-2)]">
            Load real-CVE example
          </button>
          <button type="button" onClick={addRow}
            className="px-3 py-2 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white hover:bg-[var(--surface-2)]">
            + Add row
          </button>
          <div className="ml-auto text-xs text-[var(--muted)]">{rows.length} finding(s)</div>
        </div>

        <div className="rounded border border-[var(--border)] overflow-hidden mb-6">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-[var(--surface-2)] text-[var(--muted)] mono-label">
                <th className="px-3 py-2 text-left w-44">CVE ID *</th>
                <th className="px-3 py-2 text-left">Hostname *</th>
                <th className="px-3 py-2 text-left w-32">IP</th>
                <th className="px-3 py-2 text-left w-20">CVSS</th>
                <th className="px-3 py-2 text-left w-28">Severity</th>
                <th className="px-3 py-2 text-left">Title</th>
                <th className="px-3 py-2 text-left w-32">Family</th>
                <th className="px-3 py-2 w-8"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-t border-[var(--border)]">
                  <td className="px-2 py-1">
                    <input value={r.cve_id} onChange={(e) => setRow(i, { cve_id: e.target.value })}
                      placeholder="CVE-2024-3400"
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white font-mono" />
                  </td>
                  <td className="px-2 py-1">
                    <input value={r.hostname} onChange={(e) => setRow(i, { hostname: e.target.value })}
                      placeholder="web-prod-01"
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white font-mono" />
                  </td>
                  <td className="px-2 py-1">
                    <input value={r.ip_address} onChange={(e) => setRow(i, { ip_address: e.target.value })}
                      placeholder="10.0.0.5"
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white font-mono" />
                  </td>
                  <td className="px-2 py-1">
                    <input value={r.cvss_base_score} onChange={(e) => setRow(i, { cvss_base_score: e.target.value })}
                      placeholder="9.8" type="number" step="0.1" min="0" max="10"
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white font-mono" />
                  </td>
                  <td className="px-2 py-1">
                    <select value={r.severity} onChange={(e) => setRow(i, { severity: e.target.value })}
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white">
                      {SEVERITIES.map((s) => (<option key={s} value={s}>{s}</option>))}
                    </select>
                  </td>
                  <td className="px-2 py-1">
                    <input value={r.vuln_title} onChange={(e) => setRow(i, { vuln_title: e.target.value })}
                      placeholder="(optional)"
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white" />
                  </td>
                  <td className="px-2 py-1">
                    <input value={r.plugin_family} onChange={(e) => setRow(i, { plugin_family: e.target.value })}
                      placeholder="Web Servers"
                      className="w-full px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white" />
                  </td>
                  <td className="px-1 py-1 text-center">
                    {rows.length > 1 && (
                      <button type="button" onClick={() => removeRow(i)}
                        className="text-[var(--red)] hover:text-white text-xs">✕</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="px-6 py-2.5 rounded text-sm font-semibold bg-[var(--amber)] text-black hover:bg-[var(--amber-dim)] disabled:opacity-50"
        >
          {submitting ? 'Submitting…' : 'Submit findings to pipeline'}
        </button>

        <p className="mt-6 text-xs text-[var(--muted)] max-w-2xl leading-relaxed">
          <strong className="text-white">Note:</strong> Findings are enriched with live CISA KEV and FIRST EPSS data
          for any CVE in your batch. If a CVE is in the KEV catalog, the resulting job gets a 20-point KEV
          weight in its risk score and a stricter SLA. Hostnames are matched against the Asset Inventory; if
          not found, an asset_id is auto-generated.
        </p>
      </form>
    </div>
  )
}
