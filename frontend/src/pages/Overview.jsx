import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { fetchMetricsOverview, fetchRescanStatus } from '../api/client'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

const RISK_COLORS = {
  CRITICAL: '#e05252',
  HIGH:     '#f5a623',
  MEDIUM:   '#4e8faf',
  LOW:      '#4eaf7c',
  INFO:     '#7a7d9c',
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-24">
      <div className="w-7 h-7 rounded-full border-2 animate-spin"
        style={{ borderColor: 'var(--border-2)', borderTopColor: 'var(--amber)' }} />
    </div>
  )
}

function KpiCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 12,
      padding: '18px 20px',
      borderTop: `3px solid ${accent ?? 'var(--amber)'}`,
      display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div className="mono-label">{label}</div>
      <div style={{
        fontFamily: 'Syne, sans-serif', fontWeight: 800, fontSize: 32,
        color: accent ?? 'var(--text)', letterSpacing: '-0.02em', lineHeight: 1,
      }}>
        {value ?? '—'}
      </div>
      {sub && (
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
          {sub}
        </div>
      )}
    </div>
  )
}

const CHART_TOOLTIP_STYLE = {
  background: 'var(--surface-2)',
  border: '1px solid var(--border-2)',
  borderRadius: 8,
  color: 'var(--text)',
  fontSize: 12,
}

export default function Overview() {
  const navigate = useNavigate()
  const [data,        setData]        = useState(null)
  const [rescanStatus, setRescanStatus] = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)

  useEffect(() => {
    Promise.all([fetchMetricsOverview(), fetchRescanStatus()])
      .then(([metricsRes, rescanRes]) => {
        setData(metricsRes.data?.data ?? metricsRes.data)
        setRescanStatus(rescanRes.data)
      })
      .catch((err) => setError(err.message || 'Failed to load overview'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <Spinner />
  if (error) return (
    <div className="p-8">
      <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
        <p style={{ color: 'var(--red)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 13 }}>
          ⚠ {error}
        </p>
      </div>
    </div>
  )

  const sla          = data?.sla_compliance_pct ?? 0
  const slaColor     = sla > 90 ? 'var(--green)' : sla > 70 ? 'var(--amber)' : 'var(--red)'
  const resurfaced   = rescanStatus?.resurfaced_jobs ?? 0
  const recentJobs   = (data?.recent_jobs ?? []).slice(0, 10)

  const pieData = Object.entries(data?.jobs_by_risk_level ?? {})
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const barData = Object.entries(data?.jobs_by_status ?? {})
    .map(([name, value]) => ({ name: name.replace(/_/g, ' '), value }))
    .sort((a, b) => b.value - a.value)

  return (
    <div style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1 className="page-title">Security Posture</h1>
          <p style={{ marginTop: 4, fontSize: 13, color: 'var(--muted)' }}>
            Real-time vulnerability remediation overview
          </p>
        </div>
        {resurfaced > 0 && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 14px', borderRadius: 8,
            background: 'rgba(224,82,82,0.08)',
            border: '1px solid rgba(224,82,82,0.28)',
            color: 'var(--red)', fontSize: 13, fontWeight: 500,
          }}>
            <span style={{
              width: 7, height: 7, borderRadius: '50%',
              background: 'var(--red)', display: 'inline-block',
              animation: 'pulse 1.5s infinite',
            }} />
            {resurfaced} job{resurfaced !== 1 ? 's' : ''} resurfaced
          </div>
        )}
      </div>

      {/* KPI strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        <KpiCard
          label="Total Remediation Jobs"
          value={data?.total_jobs}
          sub="all active remediation jobs"
          accent="var(--amber)"
        />
        <KpiCard
          label="Critical Open"
          value={data?.critical_open ?? 0}
          sub={`+ ${data?.high_open ?? 0} high`}
          accent="var(--red)"
        />
        <KpiCard
          label="Overdue"
          value={data?.overdue_count ?? 0}
          sub="past SLA deadline"
          accent={data?.overdue_count > 0 ? 'var(--red)' : 'var(--green)'}
        />
        <KpiCard
          label="SLA Compliance"
          value={`${sla.toFixed(1)}%`}
          sub="non-closed jobs within SLA"
          accent={slaColor}
        />
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: 16 }}>

        {/* Donut — risk distribution */}
        <div className="vra-card">
          <div className="mono-label" style={{ marginBottom: 16 }}>Remediation Jobs by Risk Level</div>
          {pieData.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontSize: 13 }}>
              No data yet
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%"
                  innerRadius={52} outerRadius={82}
                  paddingAngle={3} dataKey="value"
                  strokeWidth={0}
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name] ?? '#888'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Legend
                  formatter={(v) => (
                    <span style={{ color: 'var(--muted)', fontSize: 11,
                      fontFamily: '"IBM Plex Mono", monospace' }}>{v}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Bar — jobs by status */}
        <div className="vra-card">
          <div className="mono-label" style={{ marginBottom: 16 }}>Remediation Jobs by Status</div>
          {barData.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontSize: 13 }}>
              No data yet
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData} layout="vertical" margin={{ left: 8, right: 16 }}>
                <XAxis type="number"
                  tick={{ fill: 'var(--muted)', fontSize: 10,
                    fontFamily: '"IBM Plex Mono", monospace' }}
                  axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={110}
                  tick={{ fill: 'var(--muted)', fontSize: 10,
                    fontFamily: '"IBM Plex Mono", monospace' }}
                  axisLine={false} tickLine={false} />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Bar dataKey="value" fill="var(--amber)" radius={[0, 5, 5, 0]} maxBarSize={18} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent jobs table */}
      <div className="vra-card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div className="mono-label">Recent Active Remediation Jobs</div>
          <button
            className="btn-ghost"
            style={{ fontSize: 11, padding: '4px 10px' }}
            onClick={() => navigate('/jobs')}
          >
            View all →
          </button>
        </div>

        {recentJobs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', fontSize: 13 }}>
            No active jobs
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Job ID', 'Product', 'Risk', 'Due Date', 'Status'].map((h) => (
                  <th key={h} style={{
                    textAlign: 'left', padding: '10px 20px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
                    letterSpacing: '0.12em', textTransform: 'uppercase',
                    color: 'var(--muted)', fontWeight: 500,
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recentJobs.map((job, i) => (
                <tr
                  key={job.job_id}
                  onClick={() => navigate(`/jobs/${job.job_id}`)}
                  style={{
                    borderBottom: i < recentJobs.length - 1
                      ? '1px solid var(--border)' : 'none',
                    cursor: 'pointer',
                    transition: 'background 0.12s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-2)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{
                    padding: '11px 20px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                    color: 'var(--amber)',
                  }}>
                    {job.job_id?.slice(0, 8)}…
                  </td>
                  <td style={{ padding: '11px 20px', color: 'var(--text)', fontWeight: 500 }}>
                    {job.main_product || '—'}
                  </td>
                  <td style={{ padding: '11px 20px' }}>
                    <RiskBadge level={job.max_risk_level} />
                  </td>
                  <td style={{
                    padding: '11px 20px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                    color: 'var(--muted)',
                  }}>
                    {job.due_date ? job.due_date.slice(0, 10) : '—'}
                  </td>
                  <td style={{ padding: '11px 20px' }}>
                    <StatusBadge status={job.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
