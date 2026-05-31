import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'
import { fetchMetricsSLA, fetchMetricsTimeline, fetchMetricsOverview } from '../api/client'

const RISK_COLORS = {
  CRITICAL: '#E05252',
  HIGH: '#FFC40D',
  MEDIUM: '#4E8FAF',
  LOW: '#4EAF7C',
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 rounded-full border-2 animate-spin" style={{ borderColor: 'var(--border)', borderTopColor: 'var(--amber)' }} />
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div className="vra-card">
      <div className="mono-label mb-4">{title}</div>
      {children}
    </div>
  )
}

export default function Metrics() {
  const navigate = useNavigate()
  const [sla, setSla] = useState(null)
  const [timeline, setTimeline] = useState(null)
  const [overview, setOverview] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([fetchMetricsSLA(), fetchMetricsTimeline(), fetchMetricsOverview()])
      .then(([slaRes, timelineRes, overviewRes]) => {
        setSla(slaRes.data.data)
        // Timeline arrives as {date: {RISK: n, …}} — normalise to sorted array
        const raw = timelineRes.data.data ?? {}
        const days = Object.entries(raw)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([date, counts]) => ({ date, ...counts }))
        setTimeline(days)
        setOverview(overviewRes.data.data)
      })
      .catch((e) => setError(e.message || 'Failed to load metrics'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-8"><Spinner /></div>
  if (error) return (
    <div className="p-8">
      <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
        <p className="font-mono text-sm" style={{ color: 'var(--red)' }}>{error}</p>
      </div>
    </div>
  )

  const compliance = sla?.compliance_pct ?? sla?.sla_compliance_pct ?? 0
  const complianceClass = compliance > 90 ? 'var(--green)' : compliance > 70 ? 'var(--amber)' : 'var(--red)'

  const overdueJobs = sla?.overdue_jobs ?? []
  const timelineDays = timeline ?? []

  // Build risk dist pie data from overview
  const riskDist = overview?.jobs_by_risk_level ?? {}
  const pieData = Object.entries(riskDist)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  // Determine area keys for timeline
  const areaKeys = timelineDays.length > 0
    ? Object.keys(timelineDays[0]).filter((k) => k !== 'date' && k !== 'day')
    : []

  // ── Security Posture KPIs (from overview data) ──────────────────────────────
  const kpiStrip = [
    { label: 'Total Jobs',     value: overview?.total_jobs       ?? '—', accent: 'var(--amber)' },
    { label: 'Critical Open',  value: overview?.critical_open    ?? '—', accent: 'var(--red)'   },
    { label: 'High Open',      value: overview?.high_open        ?? '—', accent: 'var(--amber)' },
    { label: 'KEV-Flagged',    value: overview?.kev_jobs_count   ?? '—', accent: '#ff6b35'      },
    { label: 'Overdue',        value: overview?.overdue_count    ?? '—', accent: 'var(--red)'   },
    { label: 'SLA Compliance', value: overview ? `${(overview.sla_compliance_pct ?? 0).toFixed(1)}%` : '—',
      accent: (overview?.sla_compliance_pct ?? 0) > 90 ? 'var(--green)'
            : (overview?.sla_compliance_pct ?? 0) > 70 ? 'var(--amber)' : 'var(--red)' },
  ]

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="page-title">Metrics</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
          SLA compliance, risk trends, and operational metrics
        </p>
      </div>

      {/* Security posture KPI strip */}
      <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
        {kpiStrip.map(({ label, value, accent }) => (
          <div key={label} className="vra-card py-4 text-center"
            style={{ borderTop: `2px solid ${accent}` }}>
            <div className="mono-label mb-2">{label}</div>
            <div className="text-2xl font-bold font-syne" style={{ color: accent, letterSpacing: '-0.02em' }}>
              {value}
            </div>
          </div>
        ))}
      </div>

      {/* SLA Compliance Card */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <div className="vra-card text-center" style={{ borderTop: `2px solid ${complianceClass}` }}>
          <div className="mono-label mb-3">SLA Compliance</div>
          <div className="text-5xl font-bold font-syne" style={{ color: complianceClass }}>
            {compliance.toFixed(1)}%
          </div>
          <div className="mt-4 flex justify-center gap-8 text-sm">
            <div>
              <div className="mono-label mb-1">Within SLA</div>
              <div className="font-semibold" style={{ color: 'var(--green)' }}>
                {sla?.within_sla ?? '—'}
              </div>
            </div>
            <div>
              <div className="mono-label mb-1">Breached</div>
              <div className="font-semibold" style={{ color: 'var(--red)' }}>
                {sla?.breached ?? overdueJobs.length ?? '—'}
              </div>
            </div>
          </div>
        </div>

        {/* Risk distribution */}
        <div className="vra-card md:col-span-2">
          <div className="mono-label mb-4">Risk Level Distribution</div>
          {pieData.length === 0 ? (
            <div className="text-center py-8 text-sm" style={{ color: 'var(--muted)' }}>No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={70} dataKey="value" paddingAngle={3}>
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name] || '#888'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }} />
                <Legend formatter={(value) => <span style={{ color: 'var(--muted)', fontSize: 11 }}>{value}</span>} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Timeline chart */}
      <Section title="Remediation Jobs Created — Last 30 Days">
        {timelineDays.length === 0 ? (
          <div className="text-center py-8 text-sm" style={{ color: 'var(--muted)' }}>No timeline data</div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timelineDays} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
              <XAxis dataKey="date" tick={{ fill: 'var(--muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)' }} />
              <Legend formatter={(value) => <span style={{ color: 'var(--muted)', fontSize: 11 }}>{value}</span>} />
              {areaKeys.map((key) => (
                <Area
                  key={key}
                  type="monotone"
                  dataKey={key}
                  stackId="1"
                  fill={RISK_COLORS[key.toUpperCase()] || '#888'}
                  stroke={RISK_COLORS[key.toUpperCase()] || '#888'}
                  fillOpacity={0.35}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </Section>

      {/* Overdue jobs table */}
      <Section title={`Overdue Remediation Jobs (${overdueJobs.length})`}>
        {overdueJobs.length === 0 ? (
          <div className="text-center py-8" style={{ color: 'var(--green)' }}>
            <div className="text-3xl mb-2">✅</div>
            <div className="text-sm">No overdue jobs — great job!</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Job ID', 'Product', 'Risk', 'Due Date', 'Days Overdue'].map((h) => (
                    <th key={h} className="text-left py-2 px-3 mono-label">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...overdueJobs]
                  .sort((a, b) => (b.days_overdue ?? 0) - (a.days_overdue ?? 0))
                  .map((job) => (
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
                      <td className="py-2 px-3">
                        <span
                          className={`badge-${(job.risk_level || '').toLowerCase()}`}
                        >
                          {job.risk_level}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                        {job.due_date ? job.due_date.slice(0, 10) : '—'}
                      </td>
                      <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--red)' }}>
                        {job.days_overdue != null ? `+${job.days_overdue}d` : '—'}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  )
}
