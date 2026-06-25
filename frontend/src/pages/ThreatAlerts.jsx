import { useCallback, useEffect, useRef, useState } from 'react'
import {
  fetchThreatAlerts,
  fetchThreatSummary,
  runThreatMatch,
  promoteAlerts,
  updateThreatAlert,
  fetchAllSoftware,
  addAssetSoftware,
  deleteAssetSoftware,
  uploadSoftwareCsv,
  fetchAssets,
} from '../api/client'
import { useAuth } from '../context/AuthContext'
import { SortTh } from '../utils/sortable'

// ─── helpers ───────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  CRITICAL: '#f87171',
  HIGH:     '#fb923c',
  MEDIUM:   '#fbbf24',
  LOW:      '#60a5fa',
}

const ALERT_TYPE_LABELS = {
  kev_match:  { label: 'KEV Match',   color: '#f87171', bg: 'rgba(248,113,113,0.12)' },
  high_epss:  { label: 'High EPSS',   color: '#fb923c', bg: 'rgba(251,146,60,0.12)'  },
  cpe_match:  { label: 'CPE Match',   color: '#60a5fa', bg: 'rgba(96,165,250,0.12)'  },
}

function AlertTypeBadge({ type }) {
  const meta = ALERT_TYPE_LABELS[type] || { label: type, color: 'var(--muted)', bg: 'transparent' }
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
      style={{ color: meta.color, background: meta.bg, border: `1px solid ${meta.color}33` }}
    >
      {meta.label}
    </span>
  )
}

function SeverityBadge({ severity }) {
  const s = (severity || 'UNKNOWN').toUpperCase()
  const color = SEVERITY_COLORS[s] || 'var(--muted)'
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold"
      style={{ color, background: `${color}18`, border: `1px solid ${color}33` }}
    >
      {s}
    </span>
  )
}

function StatCard({ label, value, accent, sub }) {
  return (
    <div
      className="flex flex-col gap-1 p-4 rounded-lg"
      style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
    >
      <div className="mono-label">{label}</div>
      <div className="text-3xl font-bold" style={{ color: accent || 'var(--text)', fontFamily: 'Syne, sans-serif' }}>
        {value ?? '—'}
      </div>
      {sub && <div className="text-xs" style={{ color: 'var(--muted)' }}>{sub}</div>}
    </div>
  )
}

// ─── Shared grouping selector ──────────────────────────────────────────────────

const GROUPING_OPTIONS = [
  { value: 'by_cve',          label: 'By CVE',          desc: 'One job per CVE — best for widespread vulnerabilities' },
  { value: 'by_asset_product', label: 'By Asset × Product', desc: 'One job per (asset, product) — granular patch schedules' },
  { value: 'by_product',      label: 'By Product',      desc: 'One job per product across all assets — vendor-patch batches' },
]

function GroupingSelect({ value, onChange }) {
  return (
    <div>
      <label className="mono-label block mb-1">Grouping strategy</label>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {GROUPING_OPTIONS.map(opt => (
          <label key={opt.value}
            className="flex items-start gap-3 text-sm cursor-pointer px-3 py-2 rounded"
            style={{
              background: value === opt.value ? 'rgba(255,196,13,0.08)' : 'var(--dark)',
              border: `1px solid ${value === opt.value ? 'rgba(255,196,13,0.35)' : 'var(--border)'}`,
              transition: 'all 0.15s',
            }}
          >
            <input type="radio" name="grouping" value={opt.value} checked={value === opt.value}
              onChange={() => onChange(opt.value)} className="accent-yellow-400 mt-0.5 flex-shrink-0" />
            <span>
              <span style={{ color: 'var(--text)', fontWeight: 500 }}>{opt.label}</span>
              <span style={{ color: 'var(--muted)', marginLeft: 6, fontSize: 11 }}>— {opt.desc}</span>
            </span>
          </label>
        ))}
      </div>
    </div>
  )
}

// ─── MatchModal ────────────────────────────────────────────────────────────────

function MatchModal({ onClose, onDone, softwareCount }) {
  const [assetId, setAssetId]           = useState('')
  const [useNvd, setUseNvd]             = useState(true)
  const [useOsv, setUseOsv]             = useState(true)
  const [forceReset, setForceReset]     = useState(false)
  const [autoPromote, setAutoPromote]   = useState(false)
  const [grouping, setGrouping]         = useState('by_cve')
  const [running, setRunning]           = useState(false)
  const [result, setResult]             = useState(null)
  const [error, setError]               = useState('')

  async function submit() {
    setRunning(true); setError(''); setResult(null)
    try {
      const res = await runThreatMatch({
        asset_id:              assetId || null,
        use_nvd:               useNvd,
        use_osv:               useOsv,
        force_reset:           forceReset,
        auto_promote:          autoPromote,
        auto_promote_grouping: grouping,
      })
      setResult(res.data?.data ?? res.data)
      onDone()
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setRunning(false)
    }
  }

  const promo = result?.promotion

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.65)' }}>
      <div className="rounded-xl p-6 w-full shadow-2xl" style={{ background: 'var(--surface)', border: '1px solid var(--border)', maxWidth: 480, maxHeight: '90vh', overflowY: 'auto' }}>
        <h2 className="text-lg font-bold mb-4" style={{ fontFamily: 'Syne, sans-serif', color: 'var(--text)' }}>
          Run Threat Matching
        </h2>

        {softwareCount < 5 && (
          <div className="mb-4 text-sm px-3 py-2 rounded" style={{ background: 'rgba(251,191,36,0.1)', color: '#fbbf24', border: '1px solid #fbbf2444' }}>
            ⚠ Only <strong>{softwareCount}</strong> software {softwareCount === 1 ? 'entry' : 'entries'} in inventory.
            CPE/OSV matching will be limited. OS-level KEV matching still runs for all assets.
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label className="mono-label block mb-1">Hostname or Asset ID (blank = all assets)</label>
            <input
              className="w-full rounded px-3 py-2 text-sm"
              style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)' }}
              placeholder="e.g. prod-api-01 or leave empty for all"
              value={assetId}
              onChange={e => setAssetId(e.target.value)}
            />
          </div>

          <div className="flex flex-wrap gap-6">
            <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
              <input type="checkbox" checked={useNvd} onChange={e => setUseNvd(e.target.checked)} className="accent-yellow-400" />
              Use NVD (CPE match)
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
              <input type="checkbox" checked={useOsv} onChange={e => setUseOsv(e.target.checked)} className="accent-yellow-400" />
              Use OSV (package match)
            </label>
          </div>

          <label className="flex items-start gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
            <input type="checkbox" checked={forceReset} onChange={e => setForceReset(e.target.checked)}
              className="accent-yellow-400 mt-0.5" />
            <span>
              <span className="font-medium">Force re-detect</span>
              <span style={{ color: 'var(--muted)' }}> — clears existing open alerts first so new-alert count is accurate</span>
            </span>
          </label>

          {/* Divider */}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
            <label className="flex items-start gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
              <input type="checkbox" checked={autoPromote} onChange={e => setAutoPromote(e.target.checked)}
                className="accent-yellow-400 mt-0.5" />
              <span>
                <span className="font-medium" style={{ color: '#34d399' }}>Auto-promote to Jobs</span>
                <span style={{ color: 'var(--muted)' }}> — immediately create remediation jobs from all newly-found open alerts</span>
              </span>
            </label>

            {autoPromote && (
              <div className="mt-3 pl-6">
                <GroupingSelect value={grouping} onChange={setGrouping} />
              </div>
            )}
          </div>

          {error && (
            <div className="text-sm px-3 py-2 rounded" style={{ background: 'rgba(248,113,113,0.12)', color: '#f87171', border: '1px solid #f8717144' }}>
              {error}
            </div>
          )}

          {result && (
            <div className="text-sm px-3 py-2 rounded space-y-2" style={{ background: 'rgba(52,211,153,0.08)', border: '1px solid #34d39933' }}>
              {/* Match result */}
              <div style={{ color: '#34d399', fontWeight: 600 }}>
                {result.new_alerts > 0
                  ? `✓ ${result.new_alerts} new threat${result.new_alerts !== 1 ? 's' : ''} detected`
                  : result.updated_alerts > 0
                    ? `↻ ${result.updated_alerts} alerts refreshed`
                    : '✓ No new threats found'}
              </div>
              <div style={{ color: 'var(--muted)', fontSize: 11, fontFamily: '"IBM Plex Mono", monospace' }}>
                {result.assets_scanned} assets · {result.software_entries} sw entries ·{' '}
                {result.new_alerts} new · {result.updated_alerts} refreshed
                {result.errors > 0 && ` · ${result.errors} errors`}
              </div>
              {/* Promotion result */}
              {promo && (
                <div style={{ borderTop: '1px solid #34d39933', paddingTop: 8 }}>
                  <div style={{ color: '#34d399', fontWeight: 600 }}>
                    {promo.jobs_created > 0
                      ? `⬡ ${promo.jobs_created} remediation job${promo.jobs_created !== 1 ? 's' : ''} created`
                      : '⬡ No new jobs (all already existed)'}
                  </div>
                  <div style={{ color: 'var(--muted)', fontSize: 11, fontFamily: '"IBM Plex Mono", monospace' }}>
                    {promo.jobs_created} created · {promo.jobs_skipped} skipped · {promo.alert_ids_promoted?.length ?? 0} alerts linked · grouping: {promo.grouping}
                  </div>
                </div>
              )}
              {result.promotion_error && (
                <div style={{ color: '#fb923c', fontSize: 11 }}>⚠ Promotion error: {result.promotion_error}</div>
              )}
            </div>
          )}
        </div>

        <div className="flex gap-3 mt-6 justify-end">
          <button onClick={onClose} className="px-4 py-2 rounded text-sm"
            style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--muted)', cursor: 'pointer' }}>
            {result ? 'Close' : 'Cancel'}
          </button>
          {result ? (
            <button onClick={() => setResult(null)} className="px-4 py-2 rounded text-sm font-semibold"
              style={{ background: 'var(--surface-2)', color: 'var(--text)', border: '1px solid var(--border)', cursor: 'pointer' }}>
              Run Again
            </button>
          ) : (
            <button onClick={submit} disabled={running} className="px-4 py-2 rounded text-sm font-semibold"
              style={{ background: '#FFC40D', color: '#000', border: 'none', cursor: running ? 'wait' : 'pointer', opacity: running ? 0.7 : 1 }}>
              {running ? (autoPromote ? 'Matching & Promoting…' : 'Running…') : (autoPromote ? 'Match + Promote' : 'Run Match')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── PromoteModal ──────────────────────────────────────────────────────────────

function PromoteModal({ onClose, onDone, openAlertCount }) {
  const [grouping, setGrouping] = useState('by_cve')
  const [running, setRunning]   = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState('')

  async function submit() {
    setRunning(true); setError(''); setResult(null)
    try {
      const res = await promoteAlerts({ grouping })
      setResult(res.data?.data ?? res.data)
      onDone()
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.65)' }}>
      <div className="rounded-xl p-6 w-full shadow-2xl" style={{ background: 'var(--surface)', border: '1px solid var(--border)', maxWidth: 480 }}>
        <h2 className="text-lg font-bold mb-1" style={{ fontFamily: 'Syne, sans-serif', color: 'var(--text)' }}>
          Promote Alerts → Jobs
        </h2>
        <p className="text-sm mb-5" style={{ color: 'var(--muted)' }}>
          Converts <strong style={{ color: 'var(--text)' }}>{openAlertCount} open alert{openAlertCount !== 1 ? 's' : ''}</strong> into
          remediation jobs. Already-promoted alerts are skipped (idempotent).
        </p>

        <div className="space-y-4">
          <GroupingSelect value={grouping} onChange={setGrouping} />

          {error && (
            <div className="text-sm px-3 py-2 rounded" style={{ background: 'rgba(248,113,113,0.12)', color: '#f87171', border: '1px solid #f8717144' }}>
              {error}
            </div>
          )}

          {result && (
            <div className="text-sm px-3 py-2 rounded space-y-1" style={{ background: 'rgba(52,211,153,0.08)', border: '1px solid #34d39933' }}>
              <div style={{ color: '#34d399', fontWeight: 600 }}>
                {result.jobs_created > 0
                  ? `⬡ ${result.jobs_created} job${result.jobs_created !== 1 ? 's' : ''} created`
                  : '⬡ No new jobs — all alerts were already promoted'}
              </div>
              <div style={{ color: 'var(--muted)', fontSize: 11, fontFamily: '"IBM Plex Mono", monospace' }}>
                {result.jobs_created} created · {result.jobs_skipped} skipped ·{' '}
                {result.alert_ids_promoted?.length ?? 0} alerts linked · grouping: {result.grouping}
              </div>
            </div>
          )}
        </div>

        <div className="flex gap-3 mt-6 justify-end">
          <button onClick={onClose} className="px-4 py-2 rounded text-sm"
            style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--muted)', cursor: 'pointer' }}>
            {result ? 'Close' : 'Cancel'}
          </button>
          {result ? (
            <button onClick={() => setResult(null)} className="px-4 py-2 rounded text-sm font-semibold"
              style={{ background: 'var(--surface-2)', color: 'var(--text)', border: '1px solid var(--border)', cursor: 'pointer' }}>
              Run Again
            </button>
          ) : (
            <button onClick={submit} disabled={running || openAlertCount === 0} className="px-4 py-2 rounded text-sm font-semibold"
              style={{ background: '#34d399', color: '#000', border: 'none', cursor: (running || openAlertCount === 0) ? 'not-allowed' : 'pointer', opacity: (running || openAlertCount === 0) ? 0.6 : 1 }}>
              {running ? 'Promoting…' : 'Promote to Jobs'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}


// ─── SoftwarePanel ─────────────────────────────────────────────────────────────

function SoftwarePanel({ canWrite, onCountChange }) {
  const [software, setSoftware]     = useState([])
  const [total, setTotal]           = useState(0)
  const [loading, setLoading]       = useState(true)
  const [uploading, setUploading]   = useState(false)
  const [uploadResult, setUploadResult] = useState(null)
  const [uploadError, setUploadError]   = useState('')
  const [search, setSearch]         = useState('')
  // Manual add form
  const [showForm, setShowForm]     = useState(false)
  const [assets, setAssets]         = useState([])
  const [form, setForm]             = useState({ asset_id: '', product: '', version: '', vendor: '', cpe: '' })
  const [saving, setSaving]         = useState(false)
  const [saveError, setSaveError]   = useState('')
  const fileRef = useRef()

  const load = useCallback(() => {
    setLoading(true)
    fetchAllSoftware({ limit: 200, search: search || undefined })
      .then(r => {
        const rows = r.data?.data ?? []
        setSoftware(rows)
        setTotal(r.data?.total ?? rows.length)
        onCountChange(r.data?.total ?? rows.length)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [search, onCountChange])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    fetchAssets({ limit: 500 }).then(r => setAssets(r.data?.data ?? [])).catch(() => {})
  }, [])

  async function handleCsvUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true); setUploadResult(null); setUploadError('')
    try {
      const res = await uploadSoftwareCsv(file)
      setUploadResult(res.data?.data)
      load()
    } catch (err) {
      setUploadError(err.response?.data?.detail || err.message)
    } finally {
      setUploading(false)
      e.target.value = ''
    }
  }

  async function handleManualAdd(e) {
    e.preventDefault()
    if (!form.asset_id || !form.product) return
    setSaving(true); setSaveError('')
    try {
      await addAssetSoftware(form.asset_id, { product: form.product, version: form.version || null, vendor: form.vendor || null, cpe: form.cpe || null })
      setForm({ asset_id: form.asset_id, product: '', version: '', vendor: '', cpe: '' })
      load()
    } catch (err) {
      setSaveError(err.response?.data?.detail || err.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(sw) {
    try {
      await deleteAssetSoftware(sw.asset_id, sw.id)
      load()
    } catch { /* ignore */ }
  }

  const INPUT = { background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '6px 10px', fontSize: 12, width: '100%' }

  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)', background: 'var(--surface)' }}>
      {/* Header */}
      <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div className="mono-label">Software Inventory</div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
            {total} entries — used by CPE/OSV threat matching
          </div>
        </div>
        {canWrite && (
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => setShowForm(v => !v)}
              style={{ fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer' }}>
              + Add row
            </button>
            <button onClick={() => fileRef.current?.click()} disabled={uploading}
              style={{ fontSize: 12, padding: '6px 12px', borderRadius: 6, border: 'none', background: '#FFC40D', color: '#000', cursor: 'pointer', fontWeight: 600 }}>
              {uploading ? 'Uploading…' : '↑ Upload CSV'}
            </button>
            <input ref={fileRef} type="file" accept=".csv,text/csv" style={{ display: 'none' }} onChange={handleCsvUpload} />
          </div>
        )}
      </div>

      {/* CSV format hint */}
      <div style={{ padding: '8px 20px', background: 'var(--dark)', borderBottom: '1px solid var(--border)', fontSize: 11, color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace' }}>
        CSV format: <span style={{ color: 'var(--amber)' }}>hostname, product, version, vendor, cpe</span>
        &nbsp;(hostname and product required; cpe optional but improves NVD matching)
      </div>

      {/* Upload result */}
      {uploadResult && (
        <div style={{ padding: '8px 20px', background: 'rgba(52,211,153,0.08)', borderBottom: '1px solid #34d39933', fontSize: 12, color: '#34d399' }}>
          ✓ Imported {uploadResult.inserted} entries
          {uploadResult.skipped > 0 && `, ${uploadResult.skipped} skipped`}
          {uploadResult.errors?.length > 0 && (
            <span style={{ color: '#fb923c' }}> · {uploadResult.errors.length} errors: {uploadResult.errors[0]}</span>
          )}
        </div>
      )}
      {uploadError && (
        <div style={{ padding: '8px 20px', background: 'rgba(248,113,113,0.1)', borderBottom: '1px solid #f8717133', fontSize: 12, color: '#f87171' }}>
          ✕ {uploadError}
        </div>
      )}

      {/* Manual add form */}
      {showForm && (
        <form onSubmit={handleManualAdd} style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)', display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'flex-end' }}>
          <div style={{ flex: '1 1 160px' }}>
            <div className="mono-label" style={{ marginBottom: 4 }}>Asset *</div>
            <select value={form.asset_id} onChange={e => setForm(f => ({ ...f, asset_id: e.target.value }))} style={INPUT} required>
              <option value="">— select asset —</option>
              {assets.map(a => <option key={a.asset_id} value={a.asset_id}>{a.hostname}</option>)}
            </select>
          </div>
          <div style={{ flex: '1 1 140px' }}>
            <div className="mono-label" style={{ marginBottom: 4 }}>Product *</div>
            <input style={INPUT} placeholder="e.g. log4j-core" value={form.product} onChange={e => setForm(f => ({ ...f, product: e.target.value }))} required />
          </div>
          <div style={{ flex: '1 1 100px' }}>
            <div className="mono-label" style={{ marginBottom: 4 }}>Version</div>
            <input style={INPUT} placeholder="2.14.1" value={form.version} onChange={e => setForm(f => ({ ...f, version: e.target.value }))} />
          </div>
          <div style={{ flex: '1 1 110px' }}>
            <div className="mono-label" style={{ marginBottom: 4 }}>Vendor</div>
            <input style={INPUT} placeholder="Apache" value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))} />
          </div>
          <div style={{ flex: '2 1 220px' }}>
            <div className="mono-label" style={{ marginBottom: 4 }}>CPE (optional)</div>
            <input style={INPUT} placeholder="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" value={form.cpe} onChange={e => setForm(f => ({ ...f, cpe: e.target.value }))} />
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button type="submit" disabled={saving}
              style={{ padding: '6px 14px', borderRadius: 6, border: 'none', background: '#FFC40D', color: '#000', cursor: 'pointer', fontWeight: 600, fontSize: 12 }}>
              {saving ? 'Saving…' : 'Add'}
            </button>
            <button type="button" onClick={() => { setShowForm(false); setSaveError('') }}
              style={{ padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--dark)', color: 'var(--muted)', cursor: 'pointer', fontSize: 12 }}>
              Cancel
            </button>
          </div>
          {saveError && <div style={{ width: '100%', color: '#f87171', fontSize: 11 }}>{saveError}</div>}
        </form>
      )}

      {/* Search */}
      <div style={{ padding: '8px 20px', borderBottom: '1px solid var(--border)' }}>
        <input style={{ ...INPUT, width: '100%', maxWidth: 360 }}
          placeholder="Search by product, vendor, hostname…"
          value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading…</div>
      ) : software.length === 0 ? (
        <div style={{ padding: '32px 20px', textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
          No software entries yet.
          {canWrite && ' Upload a CSV or click "+ Add row" to get started.'}
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Asset', 'Product', 'Version', 'Vendor', 'CPE', ''].map(h => (
                  <th key={h} style={{ padding: '8px 14px', textAlign: 'left', fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--muted)', fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {software.slice(0, 100).map((sw, i) => (
                <tr key={sw.id} style={{ borderBottom: i < software.length - 1 ? '1px solid var(--border)' : 'none', background: i % 2 === 0 ? 'var(--dark)' : 'transparent' }}>
                  <td style={{ padding: '7px 14px', fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)', whiteSpace: 'nowrap' }}>{sw.hostname}</td>
                  <td style={{ padding: '7px 14px', color: 'var(--text)', fontWeight: 500 }}>{sw.product}</td>
                  <td style={{ padding: '7px 14px', fontFamily: '"IBM Plex Mono", monospace', color: 'var(--muted)' }}>{sw.version || '—'}</td>
                  <td style={{ padding: '7px 14px', color: 'var(--muted)' }}>{sw.vendor || '—'}</td>
                  <td style={{ padding: '7px 14px', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={sw.cpe || ''}>{sw.cpe || '—'}</td>
                  <td style={{ padding: '7px 14px' }}>
                    {canWrite && (
                      <button onClick={() => handleDelete(sw)}
                        style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, border: '1px solid #f8717133', background: 'rgba(248,113,113,0.08)', color: '#f87171', cursor: 'pointer' }}>
                        ✕
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {software.length > 100 && (
            <div style={{ padding: '8px 20px', color: 'var(--muted)', fontSize: 11, textAlign: 'center' }}>
              Showing 100 of {software.length} — use search to filter
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── FilterChipBar ─────────────────────────────────────────────────────────────

const CHIP_DEFS = [
  { key: 'hostname',        label: 'Hostname / IP', type: 'text',          placeholder: 'e.g. prod-dc-01' },
  { key: 'cve_id',          label: 'CVE ID',         type: 'text',          placeholder: 'e.g. CVE-2021-44228' },
  { key: 'severity',        label: 'Severity',       type: 'options',       options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
  { key: 'matched_product', label: 'Software',       type: 'options_search' },
]

const SEV_COLOR = { CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#60a5fa' }

function FilterChipBar({ chips, onChange, onApply, onReset, softwareOptions }) {
  const [openPicker, setOpenPicker]   = useState(null)
  const [inputText, setInputText]     = useState('')
  const barRef = useRef()

  useEffect(() => {
    function outside(e) {
      if (barRef.current && !barRef.current.contains(e.target)) setOpenPicker(null)
    }
    document.addEventListener('mousedown', outside)
    return () => document.removeEventListener('mousedown', outside)
  }, [])

  const activeChips = CHIP_DEFS.filter(d => chips[d.key])
  const hiddenDefs  = CHIP_DEFS.filter(d => !chips[d.key])
  const isDirty     = activeChips.length > 0

  function openPick(key) {
    setInputText(chips[key] || '')
    setOpenPicker(p => p === key ? null : key)
  }

  function confirmText(key) {
    const v = inputText.trim()
    if (v) onChange({ ...chips, [key]: v })
    setOpenPicker(null); setInputText('')
  }

  function selectOpt(key, val) {
    onChange({ ...chips, [key]: val })
    setOpenPicker(null); setInputText('')
  }

  function removeChip(key) { onChange({ ...chips, [key]: '' }) }

  const SEL_BTN = {
    padding: '5px 8px', borderRadius: 4, border: 'none',
    background: 'none', cursor: 'pointer', textAlign: 'left',
    color: 'var(--text)', fontSize: 12, width: '100%',
    transition: 'background 0.1s',
  }

  return (
    <div ref={barRef} style={{ position: 'relative', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6, flex: 1, minWidth: 0 }}>

      {/* ── Active chips ── */}
      {activeChips.map(def => {
        const val   = chips[def.key]
        const color = def.key === 'severity' ? (SEV_COLOR[val] || 'var(--amber)') : 'var(--amber)'
        return (
          <span key={def.key} style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            padding: '3px 10px 3px 8px', borderRadius: 14,
            background: `${color}18`, border: `1px solid ${color}44`,
            color, fontSize: 12, fontFamily: '"IBM Plex Mono", monospace',
            whiteSpace: 'nowrap',
          }}>
            <span style={{ color: 'var(--muted)', fontSize: 10, marginRight: 1 }}>{def.label}:</span>
            {val}
            <button onClick={() => removeChip(def.key)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color, padding: '0 0 0 3px', fontSize: 15, lineHeight: 1, display: 'flex', alignItems: 'center',
            }}>×</button>
          </span>
        )
      })}

      {/* ── Add-filter buttons ── */}
      {hiddenDefs.map(def => {
        const isOpen = openPicker === def.key
        const opts   = def.key === 'matched_product' ? softwareOptions : (def.options || [])
        return (
          <div key={def.key} style={{ position: 'relative' }}>
            <button onClick={() => openPick(def.key)} style={{
              fontSize: 11, padding: '3px 10px', borderRadius: 14,
              border: `1px solid ${isOpen ? 'var(--amber)' : 'var(--border)'}`,
              background: isOpen ? 'rgba(255,196,13,0.08)' : 'var(--dark)',
              color: isOpen ? 'var(--amber)' : 'var(--muted)',
              cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all 0.15s',
            }}>
              + {def.label}
            </button>

            {isOpen && (
              <div style={{
                position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 200,
                background: 'var(--surface)', border: '1px solid var(--border)',
                borderRadius: 8, boxShadow: '0 8px 24px rgba(0,0,0,0.45)',
                minWidth: 210, maxWidth: 290, padding: 10,
              }}>
                {def.type === 'text' && (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <input autoFocus value={inputText}
                      onChange={e => setInputText(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') confirmText(def.key); if (e.key === 'Escape') setOpenPicker(null) }}
                      placeholder={def.placeholder}
                      style={{ flex: 1, background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '5px 8px', fontSize: 12 }}
                    />
                    <button onClick={() => confirmText(def.key)} style={{ padding: '5px 10px', borderRadius: 6, border: 'none', background: '#FFC40D', color: '#000', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>Add</button>
                  </div>
                )}

                {def.type === 'options' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {def.options.map(opt => {
                      const c = SEV_COLOR[opt] || 'var(--text)'
                      return (
                        <button key={opt} onClick={() => selectOpt(def.key, opt)}
                          style={{ ...SEL_BTN, color: c, display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px', borderRadius: 6 }}
                          onMouseEnter={e => e.currentTarget.style.background = `${c}12`}
                          onMouseLeave={e => e.currentTarget.style.background = 'none'}
                        >
                          <span style={{ width: 8, height: 8, borderRadius: '50%', background: c, flexShrink: 0 }} />
                          <span style={{ fontWeight: 500, fontSize: 13 }}>{opt}</span>
                        </button>
                      )
                    })}
                  </div>
                )}

                {def.type === 'options_search' && (
                  <div>
                    <input autoFocus value={inputText}
                      onChange={e => setInputText(e.target.value)}
                      placeholder="Search software…"
                      style={{ width: '100%', background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '5px 8px', fontSize: 12, marginBottom: 6, boxSizing: 'border-box' }}
                    />
                    <div style={{ maxHeight: 170, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
                      {(inputText
                        ? opts.filter(o => o.toLowerCase().includes(inputText.toLowerCase()))
                        : opts
                      ).slice(0, 25).map(opt => (
                        <button key={opt} onClick={() => selectOpt(def.key, opt)}
                          style={SEL_BTN}
                          onMouseEnter={e => e.currentTarget.style.background = 'var(--dark)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'none'}
                        >
                          {opt}
                        </button>
                      ))}
                      {inputText && !opts.some(o => o.toLowerCase().includes(inputText.toLowerCase())) && (
                        <button
                          onClick={() => { onChange({ ...chips, [def.key]: inputText }); setOpenPicker(null); setInputText('') }}
                          style={{ ...SEL_BTN, color: 'var(--amber)', border: '1px dashed var(--border)', borderRadius: 4, padding: '5px 8px' }}
                        >
                          Use "{inputText}"
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}

      {/* ── Apply / Reset ── */}
      {isDirty && (
        <button onClick={onApply} style={{
          marginLeft: 4, fontSize: 12, padding: '4px 14px', borderRadius: 6,
          border: 'none', background: '#FFC40D', color: '#000', cursor: 'pointer', fontWeight: 600,
        }}>
          Apply
        </button>
      )}
      <button onClick={onReset} style={{
        fontSize: 12, padding: '4px 10px', borderRadius: 6,
        border: '1px solid var(--border)', background: 'var(--dark)',
        color: 'var(--muted)', cursor: 'pointer', marginLeft: isDirty ? 0 : 'auto',
      }}>
        Reset
      </button>
    </div>
  )
}


// ─── Pagination ────────────────────────────────────────────────────────────────

function Pagination({ page, totalPages, total, pageSize, onChange }) {
  const [jumpVal, setJumpVal] = useState('')

  function pageNums() {
    if (totalPages <= 7) return Array.from({ length: totalPages }, (_, i) => i)
    const out = [0]
    if (page > 3)              out.push('...')
    const lo = Math.max(1, page - 2)
    const hi = Math.min(totalPages - 2, page + 2)
    for (let i = lo; i <= hi; i++) out.push(i)
    if (page < totalPages - 4) out.push('...')
    out.push(totalPages - 1)
    return out
  }

  function jump(e) {
    e.preventDefault()
    const n = parseInt(jumpVal, 10)
    if (!isNaN(n) && n >= 1 && n <= totalPages) { onChange(n - 1); setJumpVal('') }
  }

  const start = page * pageSize + 1
  const end   = Math.min((page + 1) * pageSize, total)

  const BTN_BASE = { borderRadius: 6, border: '1px solid var(--border)', background: 'var(--surface)', cursor: 'pointer', fontSize: 12, padding: '4px 8px', fontFamily: '"IBM Plex Mono", monospace' }

  return (
    <div className="flex items-center justify-between text-sm" style={{ color: 'var(--muted)' }}>
      <span style={{ fontSize: 12 }}>Showing {start}–{end} of {total}</span>

      <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
        <button onClick={() => onChange(Math.max(0, page - 1))} disabled={page === 0}
          style={{ ...BTN_BASE, padding: '4px 10px', color: page === 0 ? 'var(--muted)' : 'var(--text)', cursor: page === 0 ? 'default' : 'pointer' }}>
          ← Prev
        </button>

        {pageNums().map((p, i) =>
          p === '...'
            ? <span key={`dots-${i}`} style={{ padding: '0 2px', color: 'var(--muted)', fontSize: 12 }}>…</span>
            : <button key={p} onClick={() => onChange(p)} style={{
                ...BTN_BASE, minWidth: 32, textAlign: 'center',
                border: `1px solid ${p === page ? 'var(--amber)' : 'var(--border)'}`,
                background: p === page ? 'rgba(255,196,13,0.1)' : 'var(--surface)',
                color: p === page ? 'var(--amber)' : 'var(--text)',
                cursor: p === page ? 'default' : 'pointer',
              }}>
                {p + 1}
              </button>
        )}

        <button onClick={() => onChange(Math.min(totalPages - 1, page + 1))} disabled={page >= totalPages - 1}
          style={{ ...BTN_BASE, padding: '4px 10px', color: page >= totalPages - 1 ? 'var(--muted)' : 'var(--text)', cursor: page >= totalPages - 1 ? 'default' : 'pointer' }}>
          Next →
        </button>

        <form onSubmit={jump} style={{ display: 'flex', alignItems: 'center', gap: 4, marginLeft: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>Go to</span>
          <input type="number" min={1} max={totalPages} value={jumpVal} onChange={e => setJumpVal(e.target.value)}
            style={{ width: 48, background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: 6, padding: '3px 6px', fontSize: 12, fontFamily: '"IBM Plex Mono", monospace', textAlign: 'center' }}
          />
          <button type="submit" style={{ ...BTN_BASE, color: 'var(--text)', padding: '3px 8px' }}>Go</button>
        </form>
      </div>
    </div>
  )
}


// ─── Main page ─────────────────────────────────────────────────────────────────

export default function ThreatAlerts() {
  const { role } = useAuth()
  const canWrite = ['analyst', 'remediation_owner', 'admin'].includes(role)

  const [alerts, setAlerts]       = useState([])
  const [summary, setSummary]     = useState(null)
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [showMatch,   setShowMatch]   = useState(false)
  const [showPromote, setShowPromote] = useState(false)
  const [softwareCount, setSoftwareCount] = useState(0)

  // Server-side sort — clicking a header re-fetches with the new ORDER BY
  const [alertSortCol, setAlertSortCol] = useState('is_kev')
  const [alertSortDir, setAlertSortDir] = useState('desc')

  function toggleAlertSort(col) {
    if (col === alertSortCol) {
      setAlertSortDir(d => d === 'desc' ? 'asc' : 'desc')
    } else {
      setAlertSortCol(col)
      setAlertSortDir('desc')
    }
    setPage(0)
  }

  // Filters
  const [statusFilter, setStatusFilter]   = useState('open')
  const [typeFilter, setTypeFilter]       = useState('')
  const [kevOnly, setKevOnly]             = useState(false)
  const [page, setPage]                   = useState(0)
  const PAGE_SIZE = 50

  // Chip-based advanced filters — "pending" = what's shown in the bar,
  // "applied" = what's actually sent to the API (committed on Apply).
  const EMPTY_CHIPS = { hostname: '', cve_id: '', severity: '', matched_product: '' }
  const [pendingChips, setPendingChips]   = useState(EMPTY_CHIPS)
  const [appliedChips, setAppliedChips]   = useState(EMPTY_CHIPS)

  // Software options for the chip dropdown (distinct product names)
  const [softwareOptions, setSoftwareOptions] = useState([])

  useEffect(() => {
    fetchAllSoftware({ limit: 500 })
      .then(r => {
        const rows = r.data?.data ?? []
        const uniq = [...new Set(rows.map(s => s.product).filter(Boolean))].sort()
        setSoftwareOptions(uniq)
      })
      .catch(() => {})
  }, [])

  // Inline status/promote state: { [id]: 'working' | 'done' }
  const [actionState,   setActionState]   = useState({})
  // Per-alert promote state: { [id]: 'promoting' | 'created' | 'exists' | 'error' }
  const [promoteState,  setPromoteState]  = useState({})

  const loadSummary = useCallback(() => {
    fetchThreatSummary()
      .then(r => setSummary(r.data?.data ?? r.data))
      .catch(() => {})
  }, [])

  const loadAlerts = useCallback(() => {
    setLoading(true); setError('')
    const params = {
      status:          statusFilter              || undefined,
      alert_type:      typeFilter               || undefined,
      kev_only:        kevOnly                  || undefined,
      asset_id:        appliedChips.hostname    || undefined,
      cve_id:          appliedChips.cve_id      || undefined,
      severity:        appliedChips.severity    || undefined,
      matched_product: appliedChips.matched_product || undefined,
      sort_by:         alertSortCol,
      sort_dir:        alertSortDir,
      limit:           PAGE_SIZE,
      offset:          page * PAGE_SIZE,
    }
    fetchThreatAlerts(params)
      .then(r => {
        const body = r.data
        setAlerts(body?.data ?? [])
        setTotal(body?.total ?? 0)
      })
      .catch(e => setError(e.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }, [statusFilter, typeFilter, kevOnly, appliedChips, alertSortCol, alertSortDir, page])

  useEffect(() => { loadSummary(); loadAlerts() }, [loadSummary, loadAlerts])

  async function handleAction(alertId, newStatus) {
    setActionState(s => ({ ...s, [alertId]: 'working' }))
    try {
      await updateThreatAlert(alertId, { status: newStatus })
      setActionState(s => ({ ...s, [alertId]: 'done' }))
      loadAlerts(); loadSummary()
    } catch {
      setActionState(s => { const n = { ...s }; delete n[alertId]; return n })
    }
  }

  function onMatchDone()   { loadAlerts(); loadSummary() }
  function onPromoteDone() { loadAlerts(); loadSummary() }

  async function handlePromoteAlert(alertId) {
    setPromoteState(s => ({ ...s, [alertId]: 'promoting' }))
    try {
      const res = await promoteAlerts({ alert_ids: [alertId], grouping: 'by_cve' })
      const d   = res.data?.data
      const next = (d?.jobs_created ?? 0) > 0 ? 'created' : 'exists'
      setPromoteState(s => ({ ...s, [alertId]: next }))
    } catch {
      setPromoteState(s => ({ ...s, [alertId]: 'error' }))
    } finally {
      setTimeout(() => setPromoteState(s => {
        const n = { ...s }; delete n[alertId]; return n
      }), 3000)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="p-6 space-y-6">
      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h1
            className="text-2xl font-bold"
            style={{ fontFamily: 'Syne, sans-serif', color: 'var(--text)' }}
          >
            Threat Alerts
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            CVE matches against installed software — KEV, high-EPSS, and CPE hits
          </p>
        </div>
        {canWrite && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowMatch(true)}
              className="px-4 py-2 rounded text-sm font-semibold flex items-center gap-2"
              style={{ background: '#FFC40D', color: '#000', border: 'none', cursor: 'pointer' }}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728M9.172 14.828a4 4 0 010-5.656m5.656 0a4 4 0 010 5.656M12 12h.01" />
              </svg>
              Run Match
            </button>
            <button
              onClick={() => setShowPromote(true)}
              disabled={!summary?.total_open}
              title={!summary?.total_open ? 'No open alerts to promote' : `Promote ${summary.total_open} open alerts to remediation jobs`}
              className="px-4 py-2 rounded text-sm font-semibold flex items-center gap-2"
              style={{
                background: summary?.total_open ? '#34d399' : 'var(--surface-2)',
                color: summary?.total_open ? '#000' : 'var(--muted)',
                border: `1px solid ${summary?.total_open ? '#34d399' : 'var(--border)'}`,
                cursor: summary?.total_open ? 'pointer' : 'not-allowed',
                opacity: summary?.total_open ? 1 : 0.5,
                transition: 'all 0.15s',
              }}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
              Promote to Jobs
              {summary?.total_open > 0 && (
                <span style={{
                  background: 'rgba(0,0,0,0.2)', borderRadius: 10,
                  padding: '1px 7px', fontSize: 10, fontFamily: '"IBM Plex Mono",monospace',
                }}>
                  {summary.total_open}
                </span>
              )}
            </button>
          </div>
        )}
      </div>

      {/* ── Summary strip ── */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="Open Alerts"      value={summary.total_open}       accent="#f87171" />
          <StatCard label="KEV Matches"      value={summary.kev_alerts}       accent="#f87171" sub="Confirmed exploited" />
          <StatCard label="High EPSS"        value={summary.high_epss_alerts} accent="#fb923c" sub="≥ 40% exploit probability" />
          <StatCard label="Impacted Assets"  value={summary.impacted_assets}  accent="#fbbf24" />
        </div>
      )}

      {/* ── Filter bar ── */}
      <div
        className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-lg"
        style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        {/* Status */}
        <div className="flex items-center gap-2">
          <span className="mono-label">Status</span>
          <select
            value={statusFilter}
            onChange={e => { setStatusFilter(e.target.value); setPage(0) }}
            className="rounded px-2 py-1 text-sm"
            style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)' }}
          >
            <option value="open">Open</option>
            <option value="dismissed">Dismissed</option>
            <option value="resolved">Resolved</option>
            <option value="">All</option>
          </select>
        </div>

        {/* Type */}
        <div className="flex items-center gap-2">
          <span className="mono-label">Type</span>
          <select
            value={typeFilter}
            onChange={e => { setTypeFilter(e.target.value); setPage(0) }}
            className="rounded px-2 py-1 text-sm"
            style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)' }}
          >
            <option value="">All types</option>
            <option value="kev_match">KEV Match</option>
            <option value="high_epss">High EPSS</option>
            <option value="cpe_match">CPE Match</option>
          </select>
        </div>

        {/* KEV only toggle */}
        <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={e => { setKevOnly(e.target.checked); setPage(0) }}
            className="accent-yellow-400"
          />
          KEV only
        </label>

        {/* Chip-based advanced filters */}
        <FilterChipBar
          chips={pendingChips}
          onChange={chips => { setPendingChips(chips) }}
          onApply={() => { setAppliedChips({ ...pendingChips }); setPage(0) }}
          onReset={() => {
            setStatusFilter('open'); setTypeFilter(''); setKevOnly(false)
            setPendingChips(EMPTY_CHIPS); setAppliedChips(EMPTY_CHIPS); setPage(0)
          }}
          softwareOptions={softwareOptions}
        />
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="px-4 py-3 rounded" style={{ background: 'rgba(248,113,113,0.1)', color: '#f87171', border: '1px solid #f8717133' }}>
          {error}
        </div>
      )}

      {/* ── Pagination (top) ── */}
      {totalPages > 1 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={total}
          pageSize={PAGE_SIZE}
          onChange={setPage}
        />
      )}

      {/* ── Table ── */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid var(--border)' }}>
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr style={{ background: 'var(--surface)' }}>
              {[['asset_id','Asset'],['cve_id','CVE ID'],['alert_type','Type'],['severity','Severity'],
                ['epss_score','EPSS'],['is_kev','KEV'],['matched_product','Matched Sftw.'],
                ['status','Status']].map(([c,h]) => (
                <SortTh key={c} col={c} sortCol={alertSortCol} sortDir={alertSortDir} onSort={toggleAlertSort}
                  style={{ padding: '10px 14px', fontFamily: '"IBM Plex Mono", monospace',
                           fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase',
                           fontWeight: 500, color: alertSortCol === c ? 'var(--amber)' : 'var(--muted)' }}>
                  {h}
                </SortTh>
              ))}
              <th style={{ padding: '10px 14px', color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace',
                           fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center" style={{ color: 'var(--muted)' }}>
                  Loading…
                </td>
              </tr>
            )}
            {!loading && alerts.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center" style={{ color: 'var(--muted)' }}>
                  No alerts match the current filters.
                  {statusFilter === 'open' && ' Try running a threat match first.'}
                </td>
              </tr>
            )}
            {!loading && alerts.map((alert, idx) => {
              const working = actionState[alert.id] === 'working'
              const epssStr = alert.epss_score != null
                ? `${(alert.epss_score * 100).toFixed(1)}%`
                : '—'
              const hostname = alert.hostname || alert.asset_id?.slice(0, 8) + '…'
              const matchSw  = [alert.matched_product, alert.matched_version].filter(Boolean).join(' ')

              return (
                <tr
                  key={alert.id}
                  style={{
                    background: idx % 2 === 0 ? 'var(--dark)' : 'var(--surface)',
                    borderBottom: '1px solid var(--border)',
                    opacity: alert.status !== 'open' ? 0.6 : 1,
                  }}
                >
                  {/* Asset */}
                  <td className="px-4 py-3">
                    <div className="font-medium" style={{ color: 'var(--text)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}>
                      {hostname}
                    </div>
                    {alert.ip_address && (
                      <div style={{ color: 'var(--muted)', fontSize: 11 }}>{alert.ip_address}</div>
                    )}
                  </td>

                  {/* CVE ID */}
                  <td className="px-4 py-3">
                    <span
                      className="font-mono text-xs"
                      style={{ color: alert.is_kev ? '#f87171' : 'var(--text)' }}
                    >
                      {alert.cve_id}
                    </span>
                  </td>

                  {/* Type */}
                  <td className="px-4 py-3">
                    <AlertTypeBadge type={alert.alert_type} />
                  </td>

                  {/* Severity */}
                  <td className="px-4 py-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>

                  {/* EPSS */}
                  <td className="px-4 py-3">
                    <span
                      className="text-xs font-mono"
                      style={{ color: alert.epss_score >= 0.4 ? '#fb923c' : 'var(--text)' }}
                    >
                      {epssStr}
                    </span>
                  </td>

                  {/* KEV */}
                  <td className="px-4 py-3">
                    {alert.is_kev ? (
                      <span className="text-xs font-bold" style={{ color: '#f87171' }}>✓ KEV</span>
                    ) : (
                      <span style={{ color: 'var(--muted)' }}>—</span>
                    )}
                  </td>

                  {/* Matched software */}
                  <td className="px-4 py-3">
                    {matchSw ? (
                      <div>
                        <div className="text-xs" style={{ color: 'var(--text)' }}>{matchSw}</div>
                        {alert.matched_cpe && (
                          <div className="text-xs font-mono truncate max-w-[160px]" style={{ color: 'var(--muted)' }} title={alert.matched_cpe}>
                            {alert.matched_cpe}
                          </div>
                        )}
                      </div>
                    ) : (
                      <span style={{ color: 'var(--muted)' }}>—</span>
                    )}
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3">
                    <span
                      className="text-xs px-2 py-0.5 rounded"
                      style={{
                        color: alert.status === 'open' ? '#34d399' : 'var(--muted)',
                        background: alert.status === 'open' ? 'rgba(52,211,153,0.1)' : 'var(--surface)',
                        border: `1px solid ${alert.status === 'open' ? '#34d39944' : 'var(--border)'}`,
                        fontFamily: '"IBM Plex Mono", monospace',
                      }}
                    >
                      {alert.status}
                    </span>
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3">
                    {canWrite && alert.status === 'open' && (() => {
                      const ps = promoteState[alert.id]
                      const promoting = ps === 'promoting'
                      const promoteLabel =
                        promoting    ? '…'         :
                        ps === 'created' ? '✓ Job created' :
                        ps === 'exists'  ? '✓ Already a job' :
                        ps === 'error'   ? '✗ Error' :
                        '⬡ → Job'
                      const promoteColor =
                        ps === 'created' ? '#34d399' :
                        ps === 'exists'  ? '#60a5fa' :
                        ps === 'error'   ? '#f87171' :
                        'var(--amber)'
                      return (
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <button
                            onClick={() => handleAction(alert.id, 'resolved')}
                            disabled={working}
                            title="Mark resolved"
                            className="text-xs px-2 py-1 rounded"
                            style={{ background: 'rgba(52,211,153,0.1)', color: '#34d399',
                                     border: '1px solid #34d39944', cursor: 'pointer', opacity: working ? 0.5 : 1 }}
                          >
                            Resolve
                          </button>
                          <button
                            onClick={() => handleAction(alert.id, 'dismissed')}
                            disabled={working}
                            title="Dismiss alert"
                            className="text-xs px-2 py-1 rounded"
                            style={{ background: 'rgba(148,163,184,0.1)', color: 'var(--muted)',
                                     border: '1px solid var(--border)', cursor: 'pointer', opacity: working ? 0.5 : 1 }}
                          >
                            Dismiss
                          </button>
                          <button
                            onClick={() => handlePromoteAlert(alert.id)}
                            disabled={promoting || !!ps}
                            title="Promote this alert to a remediation job"
                            className="text-xs px-2 py-1 rounded whitespace-nowrap"
                            style={{
                              background: `${promoteColor}15`,
                              color: promoteColor,
                              border: `1px solid ${promoteColor}44`,
                              cursor: (promoting || !!ps) ? 'default' : 'pointer',
                              opacity: promoting ? 0.7 : 1,
                              fontFamily: '"IBM Plex Mono", monospace',
                              fontSize: 10,
                            }}
                          >
                            {promoteLabel}
                          </button>
                        </div>
                      )
                    })()}
                    {canWrite && alert.status !== 'open' && (
                      <button
                        onClick={() => handleAction(alert.id, 'open')}
                        disabled={working}
                        title="Re-open alert"
                        className="text-xs px-2 py-1 rounded"
                        style={{ background: 'rgba(251,191,36,0.1)', color: '#fbbf24',
                                 border: '1px solid #fbbf2444', cursor: 'pointer', opacity: working ? 0.5 : 1 }}
                      >
                        Re-open
                      </button>
                    )}
                    {!canWrite && <span style={{ color: 'var(--muted)' }}>—</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ── */}
      {totalPages > 1 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={total}
          pageSize={PAGE_SIZE}
          onChange={setPage}
        />
      )}

      {/* ── Software inventory ── */}
      <SoftwarePanel canWrite={canWrite} onCountChange={setSoftwareCount} />

      {/* ── Match modal ── */}
      {showMatch && (
        <MatchModal
          onClose={() => setShowMatch(false)}
          onDone={onMatchDone}
          softwareCount={softwareCount}
        />
      )}

      {/* ── Promote modal ── */}
      {showPromote && (
        <PromoteModal
          onClose={() => setShowPromote(false)}
          onDone={onPromoteDone}
          openAlertCount={summary?.total_open ?? 0}
        />
      )}
    </div>
  )
}
