import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchJobs, updateJobStatus } from '../api/client'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

const STATUS_OPTIONS = ['', 'TO_DO', 'IN_PROGRESS', 'DONE', 'CLOSED', 'RESURFACED']
const RISK_OPTIONS = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div
        className="w-8 h-8 rounded-full border-2 animate-spin"
        style={{ borderColor: 'var(--border)', borderTopColor: 'var(--amber)' }}
      />
    </div>
  )
}

function DaysLeft({ dueDate }) {
  if (!dueDate) return <span style={{ color: 'var(--muted)' }}>—</span>
  const due = new Date(dueDate)
  const now = new Date()
  const diff = Math.ceil((due - now) / 86400000)
  if (diff < 0) return <span style={{ color: 'var(--red)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}>{diff}d</span>
  if (diff <= 7) return <span style={{ color: 'var(--amber)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}>{diff}d</span>
  return <span style={{ color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}>{diff}d</span>
}

export default function JobsList() {
  const navigate = useNavigate()
  const [jobs, setJobs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ status: '', risk_level: '', kev_only: false })
  const [offset, setOffset] = useState(0)
  const LIMIT = 50

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    const params = { limit: LIMIT, offset }
    if (filters.status) params.status = filters.status
    if (filters.risk_level) params.risk_level = filters.risk_level
    if (filters.kev_only) params.kev_only = true
    fetchJobs(params)
      .then((r) => {
        setJobs(r.data?.data ?? [])
        setTotal(r.data?.total ?? 0)
      })
      .catch((e) => setError(e.message || 'Failed to load jobs'))
      .finally(() => setLoading(false))
  }, [filters, offset])

  useEffect(() => { load() }, [load])

  const handleStatusChange = async (jobId, newStatus) => {
    try {
      await updateJobStatus(jobId, { status: newStatus })
      load()
    } catch {
      alert('Failed to update status')
    }
  }

  const selectStyle = {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    borderRadius: 6,
    padding: '6px 10px',
    fontSize: 13,
    fontFamily: 'Inter, sans-serif',
    cursor: 'pointer',
  }

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Jobs</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
            All remediation jobs — filter, triage, and manage status
          </p>
        </div>
        <div className="mono-label">{total} total</div>
      </div>

      {/* Filters */}
      <div className="vra-card flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="mono-label">Status</span>
          <select style={selectStyle} value={filters.status} onChange={(e) => { setFilters(f => ({ ...f, status: e.target.value })); setOffset(0) }}>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s || 'All'}</option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <span className="mono-label">Risk</span>
          <select style={selectStyle} value={filters.risk_level} onChange={(e) => { setFilters(f => ({ ...f, risk_level: e.target.value })); setOffset(0) }}>
            {RISK_OPTIONS.map((r) => (
              <option key={r} value={r}>{r || 'All'}</option>
            ))}
          </select>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={filters.kev_only}
            onChange={(e) => { setFilters(f => ({ ...f, kev_only: e.target.checked })); setOffset(0) }}
            className="w-4 h-4 accent-[#FFC40D]"
          />
          <span className="text-sm" style={{ color: 'var(--text)' }}>KEV Only</span>
        </label>
        <button className="btn-ghost text-xs" onClick={load}>Refresh</button>
      </div>

      {/* Table */}
      {loading ? (
        <Spinner />
      ) : error ? (
        <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
          <p className="text-sm font-mono" style={{ color: 'var(--red)' }}>{error}</p>
        </div>
      ) : jobs.length === 0 ? (
        <div className="text-center py-16" style={{ color: 'var(--muted)' }}>
          <div className="text-5xl mb-3">🔍</div>
          <div className="text-sm">No jobs match the current filters</div>
        </div>
      ) : (
        <div className="vra-card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--surface-2)', borderBottom: '1px solid var(--border)' }}>
                  {['Job ID', 'Product', 'Assets', 'Risk Level', 'KEV', 'Status', 'Due Date', 'Days Left', 'Actions'].map((h) => (
                    <th key={h} className="text-left py-3 px-4 mono-label">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr
                    key={job.job_id}
                    style={{ borderBottom: '1px solid var(--border)' }}
                    className="hover:bg-[var(--surface-2)] transition-colors"
                  >
                    <td className="py-3 px-4">
                      <span
                        className="cursor-pointer hover:underline"
                        style={{ color: 'var(--amber)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}
                        onClick={() => navigate(`/jobs/${job.job_id}`)}
                      >
                        {job.job_id}
                      </span>
                    </td>
                    <td className="py-3 px-4" style={{ color: 'var(--text)' }}>{job.product_name || '—'}</td>
                    <td className="py-3 px-4 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {job.assets_count ?? '—'}
                    </td>
                    <td className="py-3 px-4"><RiskBadge level={job.risk_level} /></td>
                    <td className="py-3 px-4 text-center">
                      {job.kev_count > 0 ? (
                        <span title="Known Exploited Vulnerability">🔴</span>
                      ) : (
                        <span style={{ color: 'var(--border)' }}>—</span>
                      )}
                    </td>
                    <td className="py-3 px-4"><StatusBadge status={job.status} /></td>
                    <td className="py-3 px-4 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {job.due_date ? job.due_date.slice(0, 10) : '—'}
                    </td>
                    <td className="py-3 px-4"><DaysLeft dueDate={job.due_date} /></td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button
                          className="btn-ghost text-xs"
                          onClick={() => navigate(`/jobs/${job.job_id}`)}
                        >
                          Details
                        </button>
                        {job.status === 'TO_DO' && (
                          <button
                            className="btn-ghost text-xs"
                            style={{ color: 'var(--blue)', borderColor: 'var(--blue)' }}
                            onClick={() => handleStatusChange(job.job_id, 'IN_PROGRESS')}
                          >
                            Activate
                          </button>
                        )}
                        {job.status === 'IN_PROGRESS' && (
                          <button
                            className="btn-ghost text-xs"
                            style={{ color: 'var(--green)', borderColor: 'var(--green)' }}
                            onClick={() => handleStatusChange(job.job_id, 'DONE')}
                          >
                            Mark Done
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* Pagination */}
          <div
            className="flex items-center justify-between px-4 py-3"
            style={{ borderTop: '1px solid var(--border)' }}
          >
            <span className="mono-label">
              {offset + 1}–{Math.min(offset + LIMIT, total)} of {total}
            </span>
            <div className="flex gap-2">
              <button
                className="btn-ghost text-xs"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - LIMIT))}
              >
                ← Prev
              </button>
              <button
                className="btn-ghost text-xs"
                disabled={offset + LIMIT >= total}
                onClick={() => setOffset(offset + LIMIT)}
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
