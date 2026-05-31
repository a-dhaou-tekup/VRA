import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchRiskRegister, updateRiskAcceptance } from '../api/client'
import { useAuth } from '../context/AuthContext'
import { jobLabel } from '../utils/jobLabel'
import { useSortable, SortTh } from '../utils/sortable'

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 rounded-full border-2 animate-spin"
        style={{ borderColor: 'var(--border)', borderTopColor: 'var(--amber)' }} />
    </div>
  )
}

function StatusChip({ overdue }) {
  if (overdue) {
    return (
      <span className="font-mono text-xs px-2 py-0.5 rounded"
        style={{ background: 'rgba(224,82,82,0.15)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.4)' }}>
        OVERDUE
      </span>
    )
  }
  return (
    <span className="font-mono text-xs px-2 py-0.5 rounded"
      style={{ background: 'rgba(34,197,94,0.12)', color: 'var(--green)', border: '1px solid rgba(34,197,94,0.3)' }}>
      ACTIVE
    </span>
  )
}

export default function RiskRegister() {
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [actioning, setActioning] = useState(null)

  const { sorted: sortedRows, col: rrSortCol, dir: rrSortDir, toggle: toggleRrSort } =
    useSortable(rows, 'job_id')
  const navigate = useNavigate()
  const { role } = useAuth()
  const canManage = role === 'risk_owner' || role === 'admin'

  const load = () => {
    setLoading(true)
    fetchRiskRegister()
      .then((r) => {
        setRows(r.data?.data ?? [])
        setTotal(r.data?.total ?? 0)
      })
      .catch((e) => setError(e.message || 'Failed to load risk register'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleExpire = async (raId, newStatus) => {
    setActioning(raId)
    try {
      await updateRiskAcceptance(raId, { status: newStatus })
      load()
    } catch (e) {
      alert(e.response?.data?.detail || e.message || 'Failed to update acceptance')
    } finally {
      setActioning(null)
    }
  }

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="page-title">Risk Register</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
          All active risk acceptances — review expiry dates and compensating controls
        </p>
      </div>

      {loading ? (
        <Spinner />
      ) : error ? (
        <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
          <p className="font-mono text-sm" style={{ color: 'var(--red)' }}>{error}</p>
        </div>
      ) : rows.length === 0 ? (
        <div className="vra-card text-center py-12" style={{ color: 'var(--muted)' }}>
          <div className="text-4xl mb-3">✅</div>
          <div className="text-sm">No active risk acceptances — all risks are being remediated.</div>
        </div>
      ) : (
        <div className="vra-card p-0 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4"
            style={{ borderBottom: '1px solid var(--border)' }}>
            <span className="mono-label">Active Acceptances ({total})</span>
            <button className="btn-ghost text-xs" onClick={load}>Refresh</button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--surface-2)', borderBottom: '1px solid var(--border)' }}>
                  {[['job_id','Job'],['main_product','Product'],['max_risk_level','Risk'],
                    ['job_status','Job Status'],['accepted_by','Accepted By'],
                    ['justification','Justification'],['compensating_controls','Controls'],
                    ['expiry_date','Expiry'],['status','Status']].map(([c,h]) => (
                    <SortTh key={c} col={c} sortCol={rrSortCol} sortDir={rrSortDir} onSort={toggleRrSort}
                      className="text-left py-3 px-4 mono-label"
                      style={{ color: rrSortCol === c ? 'var(--amber)' : undefined }}>{h}</SortTh>
                  ))}
                  {canManage && <th className="text-left py-3 px-4 mono-label">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((ra) => (
                  <tr key={ra.id}
                    style={{ borderBottom: '1px solid var(--border)' }}
                    className="hover:bg-[var(--surface-2)] transition-colors">
                    <td className="py-3 px-4 min-w-[220px]">
                      <span
                        className="font-mono text-xs cursor-pointer hover:underline block leading-snug"
                        style={{ color: 'var(--amber)' }}
                        onClick={() => navigate(`/jobs/${ra.job_id}`)}
                        title={ra.job_id}
                      >
                        {jobLabel(ra)}
                      </span>
                      <span className="text-[10px] text-[var(--muted)] font-mono">{ra.job_id.slice(0, 8)}…</span>
                    </td>
                    <td className="py-3 px-4 text-sm" style={{ color: 'var(--text)' }}>
                      {ra.main_product || '—'}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`badge-${(ra.max_risk_level || 'info').toLowerCase()}`}>
                        {ra.max_risk_level || '—'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {ra.job_status || '—'}
                    </td>
                    <td className="py-3 px-4 text-xs" style={{ color: 'var(--text)' }}>
                      {ra.accepted_by}
                    </td>
                    <td className="py-3 px-4 text-xs" style={{ color: 'var(--text)', maxWidth: 220 }}>
                      <span className="line-clamp-2" title={ra.justification}>{ra.justification}</span>
                    </td>
                    <td className="py-3 px-4 text-xs" style={{ color: 'var(--muted)', maxWidth: 180 }}>
                      <span className="line-clamp-2" title={ra.compensating_controls || ''}>
                        {ra.compensating_controls || '—'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs" style={{ color: ra.overdue ? 'var(--red)' : 'var(--muted)' }}>
                      {ra.expiry_date || '—'}
                    </td>
                    <td className="py-3 px-4">
                      <StatusChip overdue={ra.overdue} />
                    </td>
                    {canManage && (
                      <td className="py-3 px-4">
                        <div className="flex gap-2">
                          <button
                            className="btn-ghost text-xs"
                            style={{ color: 'var(--amber)', borderColor: 'var(--amber)' }}
                            disabled={actioning === ra.id}
                            onClick={() => handleExpire(ra.id, 'expired')}
                          >
                            Expire
                          </button>
                          <button
                            className="btn-ghost text-xs"
                            disabled={actioning === ra.id}
                            onClick={() => handleExpire(ra.id, 'superseded')}
                          >
                            Supersede
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
