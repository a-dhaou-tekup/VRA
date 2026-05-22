import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { fetchMetricsOverview, fetchRescanStatus } from '../api/client'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

const RISK_COLORS = {
  CRITICAL: '#E05252',
  HIGH: '#FFC40D',
  MEDIUM: '#4E8FAF',
  LOW: '#4EAF7C',
  INFO: '#888888',
}

function KpiCard({ label, value, valueClass = '' }) {
  return (
    <div
      className="vra-card flex flex-col gap-2"
      style={{ borderTop: '2px solid var(--amber)' }}
    >
      <div className="mono-label">{label}</div>
      <div className={`text-3xl font-bold font-syne ${valueClass}`}>{value ?? '—'}</div>
    </div>
  )
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div
        className="w-8 h-8 rounded-full border-2 border-t-transparent animate-spin"
        style={{ borderColor: 'var(--muted)', borderTopColor: 'transparent' }}
      />
    </div>
  )
}

export default function Overview() {
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [rescanStatus, setRescanStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([fetchMetricsOverview(), fetchRescanStatus()])
      .then(([metricsRes, rescanRes]) => {
        setData(metricsRes.data)
        setRescanStatus(rescanRes.data)
      })
      .catch((err) => setError(err.message || 'Failed to load overview'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8"><Spinner /></div>
  if (error) return (
    <div className="p-8">
      <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
        <p className="text-[var(--red)] font-mono text-sm">{error}</p>
      </div>
    </div>
  )

  const sla = data?.sla_compliance_pct ?? 0
  const slaClass = sla > 90 ? 'text-[var(--green)]' : sla > 70 ? 'text-[var(--amber)]' : 'text-[var(--red)]'

  // Donut chart data
  const riskDist = data?.risk_distribution ?? {}
  const pieData = Object.entries(riskDist)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  // Status bar data
  const statusDist = data?.status_distribution ?? {}
  const barData = Object.entries(statusDist).map(([name, value]) => ({ name, value }))

  // Recent jobs
  const recentJobs = (data?.recent_jobs ?? []).slice(0, 10)

  const resurfaced = rescanStatus?.resurfaced_jobs ?? 0

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="page-title">Overview</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
          Vulnerability remediation dashboard — real-time posture summary
        </p>
      </div>

      {/* Rescan alert */}
      {resurfaced > 0 && (
        <div
          className="flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium"
          style={{ background: 'rgba(255,196,13,0.08)', border: '1px solid rgba(255,196,13,0.35)', color: '#FFC40D' }}
        >
          <span>⚠</span>
          <span>
            <strong>{resurfaced}</strong> job{resurfaced > 1 ? 's' : ''} resurfaced since last scan — review required.
          </span>
        </div>
      )}

      {/* KPI Row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard label="Total Jobs" value={data?.total_jobs} />
        <KpiCard
          label="Critical / High Open"
          value={`${data?.critical_open ?? 0} / ${data?.high_open ?? 0}`}
          valueClass="text-[var(--red)]"
        />
        <KpiCard label="Overdue" value={data?.overdue_count} valueClass="text-[var(--red)]" />
        <KpiCard label="SLA Compliance" value={`${sla.toFixed(1)}%`} valueClass={slaClass} />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Donut – risk distribution */}
        <div className="vra-card">
          <div className="mono-label mb-4">Jobs by Risk Level</div>
          {pieData.length === 0 ? (
            <div className="text-center py-10 text-sm" style={{ color: 'var(--muted)' }}>No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={88}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name] || '#888'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                />
                <Legend
                  formatter={(value) => <span style={{ color: 'var(--muted)', fontSize: 11 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Bar – jobs by status */}
        <div className="vra-card">
          <div className="mono-label mb-4">Jobs by Status</div>
          {barData.length === 0 ? (
            <div className="text-center py-10 text-sm" style={{ color: 'var(--muted)' }}>No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData} layout="vertical" margin={{ left: 10 }}>
                <XAxis type="number" tick={{ fill: 'var(--muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: 'var(--muted)', fontSize: 11 }} axisLine={false} tickLine={false} width={90} />
                <Tooltip
                  contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }}
                />
                <Bar dataKey="value" fill="var(--amber)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent jobs table */}
      <div className="vra-card">
        <div className="mono-label mb-4">Recent Active Jobs</div>
        {recentJobs.length === 0 ? (
          <div className="text-center py-8 text-sm" style={{ color: 'var(--muted)' }}>No active jobs</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Job ID', 'Product', 'Risk', 'Due Date', 'Status'].map((h) => (
                    <th
                      key={h}
                      className="text-left py-2 px-3 mono-label"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recentJobs.map((job) => (
                  <tr
                    key={job.job_id}
                    className="cursor-pointer hover:bg-[var(--surface-2)] transition-colors"
                    style={{ borderBottom: '1px solid var(--border)' }}
                    onClick={() => navigate(`/jobs/${job.job_id}`)}
                  >
                    <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--amber)' }}>
                      {job.job_id}
                    </td>
                    <td className="py-2 px-3" style={{ color: 'var(--text)' }}>{job.product_name || '—'}</td>
                    <td className="py-2 px-3"><RiskBadge level={job.risk_level} /></td>
                    <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {job.due_date ? job.due_date.slice(0, 10) : '—'}
                    </td>
                    <td className="py-2 px-3"><StatusBadge status={job.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
