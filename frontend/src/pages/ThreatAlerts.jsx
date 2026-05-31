import { useCallback, useEffect, useRef, useState } from 'react'
import {
  fetchThreatAlerts,
  fetchThreatSummary,
  runThreatMatch,
  updateThreatAlert,
} from '../api/client'
import { useAuth } from '../context/AuthContext'
import { useSortable, SortTh } from '../utils/sortable'

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

// ─── MatchModal ────────────────────────────────────────────────────────────────

function MatchModal({ onClose, onDone }) {
  const [assetId, setAssetId]   = useState('')
  const [useNvd, setUseNvd]     = useState(true)
  const [useOsv, setUseOsv]     = useState(true)
  const [running, setRunning]   = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState('')

  async function submit() {
    setRunning(true); setError(''); setResult(null)
    try {
      const res = await runThreatMatch({ asset_id: assetId || null, use_nvd: useNvd, use_osv: useOsv })
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
      <div
        className="rounded-xl p-6 w-full max-w-md shadow-2xl"
        style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <h2 className="text-lg font-bold mb-4" style={{ fontFamily: 'Syne, sans-serif', color: 'var(--text)' }}>
          Run Threat Matching
        </h2>

        <div className="space-y-4">
          <div>
            <label className="mono-label block mb-1">Asset ID (leave blank for all assets)</label>
            <input
              className="w-full rounded px-3 py-2 text-sm"
              style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)' }}
              placeholder="e.g. abc123… or leave empty"
              value={assetId}
              onChange={e => setAssetId(e.target.value)}
            />
          </div>

          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
              <input type="checkbox" checked={useNvd} onChange={e => setUseNvd(e.target.checked)} className="accent-yellow-400" />
              Use NVD
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text)' }}>
              <input type="checkbox" checked={useOsv} onChange={e => setUseOsv(e.target.checked)} className="accent-yellow-400" />
              Use OSV
            </label>
          </div>

          {error && (
            <div className="text-sm px-3 py-2 rounded" style={{ background: 'rgba(248,113,113,0.12)', color: '#f87171', border: '1px solid #f8717144' }}>
              {error}
            </div>
          )}

          {result && (
            <div className="text-sm px-3 py-2 rounded" style={{ background: 'rgba(52,211,153,0.1)', color: '#34d399', border: '1px solid #34d39944' }}>
              Scanned {result.assets_scanned} assets · {result.software_entries} software entries ·
              {' '}{result.new_alerts} new alerts · {result.updated_alerts} updated
              {result.errors?.length > 0 && ` · ${result.errors.length} errors`}
            </div>
          )}
        </div>

        <div className="flex gap-3 mt-6 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded text-sm"
            style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--muted)', cursor: 'pointer' }}
          >
            {result ? 'Close' : 'Cancel'}
          </button>
          {!result && (
            <button
              onClick={submit}
              disabled={running}
              className="px-4 py-2 rounded text-sm font-semibold"
              style={{ background: '#FFC40D', color: '#000', border: 'none', cursor: running ? 'wait' : 'pointer', opacity: running ? 0.7 : 1 }}
            >
              {running ? 'Running…' : 'Run Match'}
            </button>
          )}
        </div>
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
  const [showMatch, setShowMatch] = useState(false)

  const { sorted: sortedAlerts, col: alertSortCol, dir: alertSortDir, toggle: toggleAlertSort } =
    useSortable(alerts, 'cve_id')

  // Filters
  const [statusFilter, setStatusFilter]   = useState('open')
  const [typeFilter, setTypeFilter]       = useState('')
  const [kevOnly, setKevOnly]             = useState(false)
  const [assetFilter, setAssetFilter]     = useState('')
  const [page, setPage]                   = useState(0)
  const PAGE_SIZE = 50

  // Inline action state: { [id]: 'working' | 'done' }
  const [actionState, setActionState] = useState({})

  const loadSummary = useCallback(() => {
    fetchThreatSummary()
      .then(r => setSummary(r.data?.data ?? r.data))
      .catch(() => {})
  }, [])

  const loadAlerts = useCallback(() => {
    setLoading(true); setError('')
    const params = {
      status:     statusFilter || undefined,
      alert_type: typeFilter   || undefined,
      kev_only:   kevOnly      || undefined,
      asset_id:   assetFilter  || undefined,
      limit:      PAGE_SIZE,
      offset:     page * PAGE_SIZE,
    }
    fetchThreatAlerts(params)
      .then(r => {
        const body = r.data
        setAlerts(body?.data ?? [])
        setTotal(body?.total ?? 0)
      })
      .catch(e => setError(e.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }, [statusFilter, typeFilter, kevOnly, assetFilter, page])

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

  function onMatchDone() { loadAlerts(); loadSummary() }

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

        {/* Asset filter */}
        <input
          className="rounded px-3 py-1 text-sm flex-1 min-w-[160px]"
          style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--text)' }}
          placeholder="Filter by asset hostname / IP…"
          value={assetFilter}
          onChange={e => { setAssetFilter(e.target.value); setPage(0) }}
        />

        <button
          onClick={() => { setStatusFilter('open'); setTypeFilter(''); setKevOnly(false); setAssetFilter(''); setPage(0) }}
          className="text-xs px-3 py-1 rounded"
          style={{ background: 'var(--dark)', border: '1px solid var(--border)', color: 'var(--muted)', cursor: 'pointer' }}
        >
          Reset
        </button>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="px-4 py-3 rounded" style={{ background: 'rgba(248,113,113,0.1)', color: '#f87171', border: '1px solid #f8717133' }}>
          {error}
        </div>
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
            {!loading && sortedAlerts.map((alert, idx) => {
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
                    {canWrite && alert.status === 'open' && (
                      <div className="flex items-center gap-2">
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
                      </div>
                    )}
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
        <div className="flex items-center justify-between text-sm" style={{ color: 'var(--muted)' }}>
          <span>
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 rounded text-xs"
              style={{ background: 'var(--surface)', border: '1px solid var(--border)',
                       color: page === 0 ? 'var(--muted)' : 'var(--text)', cursor: page === 0 ? 'default' : 'pointer' }}
            >
              ← Prev
            </button>
            <span className="px-3 py-1" style={{ fontFamily: '"IBM Plex Mono", monospace' }}>
              {page + 1} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 rounded text-xs"
              style={{ background: 'var(--surface)', border: '1px solid var(--border)',
                       color: page >= totalPages - 1 ? 'var(--muted)' : 'var(--text)',
                       cursor: page >= totalPages - 1 ? 'default' : 'pointer' }}
            >
              Next →
            </button>
          </div>
        </div>
      )}

      {/* ── Match modal ── */}
      {showMatch && (
        <MatchModal
          onClose={() => setShowMatch(false)}
          onDone={onMatchDone}
        />
      )}
    </div>
  )
}
