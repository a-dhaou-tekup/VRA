import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  fetchJob,
  fetchJobEvents,
  triageJob,
  updateJobSla,
  fetchRagRecommendation,
  submitRagFeedback,
  transitionJob,
  createRiskAcceptance,
  fetchRiskAcceptances,
  createWorkaround,
  fetchWorkarounds,
} from '../api/client'
import { useAuth } from '../context/AuthContext'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import { jobLabel } from '../utils/jobLabel'
import ChatPanel from '../components/ChatPanel'

// Full 15-state machine transitions (mirrors lifecycle_service.py)
const STATUS_TRANSITIONS = {
  TO_DO:                ['TRIAGED', 'IN_PROGRESS', 'FALSE_POSITIVE', 'RISK_ACCEPTED', 'DEFERRED'],
  TRIAGED:              ['PATCHABLE', 'WORKAROUND_AVAILABLE', 'NO_FIX', 'IN_PROGRESS'],
  PATCHABLE:            ['IN_PROGRESS'],
  WORKAROUND_AVAILABLE: ['IN_PROGRESS'],
  NO_FIX:               ['RISK_ACCEPTED', 'DEFERRED', 'IN_PROGRESS'],
  IN_PROGRESS:          ['PATCHED', 'MITIGATED', 'FALSE_POSITIVE', 'RISK_ACCEPTED', 'DONE', 'DEFERRED'],
  PATCHED:              ['VERIFIED'],
  MITIGATED:            ['VERIFIED', 'RISK_ACCEPTED'],
  DONE:                 ['VERIFIED', 'CLOSED', 'RESURFACED'],
  RISK_ACCEPTED:        ['IN_PROGRESS'],
  FALSE_POSITIVE:       ['TO_DO'],
  DEFERRED:             ['IN_PROGRESS', 'RISK_ACCEPTED'],
  VERIFIED:             ['CLOSED'],
  CLOSED:               ['RESURFACED'],   // reopen a closed job
  RESURFACED:           ['TO_DO', 'IN_PROGRESS'],
}

// States only risk_owner/admin may enter
const RISK_STATES = new Set(['RISK_ACCEPTED'])

const TRIAGE_OPTIONS = ['CONFIRMED', 'FALSE_POSITIVE', 'RISK_ACCEPTED', 'DEFERRED']

function Spinner({ small }) {
  const sz = small ? 'w-5 h-5' : 'w-8 h-8'
  return (
    <div className={`${sz} rounded-full border-2 animate-spin`}
      style={{ borderColor: 'var(--border)', borderTopColor: 'var(--amber)' }} />
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

// ── Risk score breakdown ──────────────────────────────────────────────────────

const FACTOR_META = {
  cvss: {
    label:   'CVSS',
    max:     40,
    color:   '#FFC40D',
    desc:    'NVD base severity score (0–10) scaled to 40 pts. Measures intrinsic vulnerability severity independent of your environment.',
  },
  kev: {
    label:   'KEV',
    max:     20,
    color:   '#e05252',
    desc:    'CISA Known Exploited Vulnerability flag. A confirmed in-the-wild exploit adds a flat 20 pts regardless of CVSS.',
  },
  epss: {
    label:   'EPSS',
    max:     15,
    color:   '#fb923c',
    desc:    'FIRST Exploit Prediction Scoring System — 30-day probability of exploitation (0–1) scaled to 15 pts.',
  },
  criticality: {
    label:   'Criticality',
    max:     15,
    color:   '#9b6dff',
    desc:    'Asset criticality multiplier: low 0.25×, medium 0.50×, high 0.75×, critical 1.00×, scaled to 15 pts.',
  },
  exposure: {
    label:   'Exposure',
    max:     10,
    color:   '#4e8faf',
    desc:    'Internet-exposed asset flag. Reachability from the public internet adds a flat 10 pts to the risk score.',
  },
}

function ScoreBreakdown({ breakdown }) {
  const entries = Object.entries(breakdown).map(([key, rawVal]) => {
    const val  = Number(rawVal)
    const meta = FACTOR_META[key] ?? {
      label:   key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      max:     40,
      color:   'var(--amber)',
      desc:    '',
    }
    const pct  = meta.max > 0 ? Math.min(100, (val / meta.max) * 100) : 0
    return { key, val, meta, pct }
  })

  const total = entries.reduce((s, e) => s + e.val, 0)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 780 }}>
      {entries.map(({ key, val, meta, pct }) => (
        <div key={key} style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          {/* top row: label · description · value */}
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
            {/* Factor label */}
            <span style={{
              fontFamily: '"IBM Plex Mono", monospace',
              fontSize: 11, fontWeight: 700,
              color: meta.color,
              width: 78, flexShrink: 0, textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}>
              {meta.label}
            </span>
            {/* Description */}
            <span style={{
              flex: 1, fontSize: 11, color: 'var(--muted)', lineHeight: 1.45,
            }}>
              {meta.desc}
            </span>
            {/* Raw value + max */}
            <span style={{
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
              color: val > 0 ? 'var(--text)' : 'var(--muted)',
              flexShrink: 0, whiteSpace: 'nowrap',
            }}>
              {val.toFixed(2)}
              <span style={{ color: 'var(--muted)', fontSize: 9 }}> / {meta.max}</span>
            </span>
          </div>

          {/* bar row — track is 50% of the card width */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 78, flexShrink: 0 }} />
            <div style={{
              width: '50%', height: 6, borderRadius: 4,
              background: 'var(--border)', flexShrink: 0, overflow: 'hidden',
            }}>
              <div style={{
                width: `${pct}%`, height: '100%', borderRadius: 4,
                background: meta.color,
                transition: 'width 0.5s ease',
                boxShadow: val > 0 ? `0 0 6px ${meta.color}66` : 'none',
              }} />
            </div>
            {/* percentage label */}
            <span style={{
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
              color: 'var(--muted)',
            }}>
              {pct.toFixed(1)}%
            </span>
          </div>
        </div>
      ))}

      {/* Total */}
      <div style={{
        borderTop: '1px solid var(--border)', paddingTop: 10, marginTop: 2,
        display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <span style={{ width: 78, flexShrink: 0, fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Total
        </span>
        <span style={{ flex: 1, fontSize: 11, color: 'var(--muted)' }}>
          Sum of all factors — maximum possible score is 100
        </span>
        <span style={{
          fontFamily: '"IBM Plex Mono", monospace', fontSize: 13, fontWeight: 700,
          color: total >= 80 ? '#e05252' : total >= 60 ? '#fb923c' : total >= 40 ? '#FFC40D' : 'var(--muted)',
        }}>
          {total.toFixed(1)}
          <span style={{ fontSize: 9, color: 'var(--muted)', fontWeight: 400 }}> / 100</span>
        </span>
      </div>
    </div>
  )
}

function MetaItem({ label, value }) {
  return (
    <div>
      <div className="mono-label mb-1">{label}</div>
      <div className="text-sm" style={{ color: 'var(--text)' }}>{value ?? '—'}</div>
    </div>
  )
}

// ── Risk Acceptance Modal ─────────────────────────────────────────────────────

function RiskAcceptanceModal({ jobId, onClose, onCreated }) {
  const [form, setForm] = useState({
    justification: '',
    compensating_controls: '',
    expiry_date: '',
    review_trigger: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const inputStyle = {
    background: 'var(--surface-2)', border: '1px solid var(--border)',
    color: 'var(--text)', borderRadius: 6, padding: '8px 12px',
    fontSize: 13, fontFamily: 'Inter, sans-serif', outline: 'none', width: '100%',
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.justification.trim()) return
    setLoading(true)
    setError(null)
    try {
      await createRiskAcceptance(jobId, {
        justification: form.justification,
        compensating_controls: form.compensating_controls || undefined,
        expiry_date: form.expiry_date || undefined,
        review_trigger: form.review_trigger || undefined,
      })
      onCreated()
      onClose()
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to create risk acceptance')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.7)' }} onClick={onClose}>
      <div className="vra-card w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-syne font-bold text-lg text-white">Record Risk Acceptance</h2>
          <button className="text-xl hover:opacity-70" style={{ color: 'var(--muted)' }} onClick={onClose}>✕</button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <div className="mono-label mb-2">Justification *</div>
            <textarea
              style={{ ...inputStyle, resize: 'vertical', minHeight: 80 }}
              placeholder="Business justification for accepting this risk…"
              value={form.justification}
              onChange={(e) => setForm(f => ({ ...f, justification: e.target.value }))}
              required
            />
          </div>
          <div>
            <div className="mono-label mb-2">Compensating Controls</div>
            <textarea
              style={{ ...inputStyle, resize: 'vertical', minHeight: 60 }}
              placeholder="Controls in place to reduce exposure…"
              value={form.compensating_controls}
              onChange={(e) => setForm(f => ({ ...f, compensating_controls: e.target.value }))}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="mono-label mb-2">Expiry Date</div>
              <input style={inputStyle} type="date" value={form.expiry_date}
                onChange={(e) => setForm(f => ({ ...f, expiry_date: e.target.value }))} />
            </div>
            <div>
              <div className="mono-label mb-2">Review Trigger</div>
              <input style={inputStyle} type="text" placeholder="e.g. next vuln scan"
                value={form.review_trigger}
                onChange={(e) => setForm(f => ({ ...f, review_trigger: e.target.value }))} />
            </div>
          </div>
          {error && (
            <div className="text-sm px-3 py-2 rounded"
              style={{ background: 'rgba(224,82,82,0.1)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.3)' }}>
              {error}
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-amber" disabled={loading || !form.justification.trim()}>
              {loading ? 'Saving…' : 'Record Acceptance'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Workaround Modal ──────────────────────────────────────────────────────────

function WorkaroundModal({ jobId, onClose, onCreated }) {
  const [control, setControl] = useState('')
  const [followup, setFollowup] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const inputStyle = {
    background: 'var(--surface-2)', border: '1px solid var(--border)',
    color: 'var(--text)', borderRadius: 6, padding: '8px 12px',
    fontSize: 13, fontFamily: 'Inter, sans-serif', outline: 'none', width: '100%',
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!control.trim()) return
    setLoading(true)
    setError(null)
    try {
      await createWorkaround(jobId, {
        control_description: control,
        followup_date: followup || undefined,
      })
      onCreated()
      onClose()
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to record workaround')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.7)' }} onClick={onClose}>
      <div className="vra-card w-full max-w-md" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-syne font-bold text-lg text-white">Record Workaround</h2>
          <button className="text-xl hover:opacity-70" style={{ color: 'var(--muted)' }} onClick={onClose}>✕</button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <div className="mono-label mb-2">Control Description *</div>
            <textarea
              style={{ ...inputStyle, resize: 'vertical', minHeight: 80 }}
              placeholder="Describe the workaround or compensating control applied…"
              value={control}
              onChange={(e) => setControl(e.target.value)}
              required
            />
          </div>
          <div>
            <div className="mono-label mb-2">Follow-up Date</div>
            <input style={inputStyle} type="date" value={followup}
              onChange={(e) => setFollowup(e.target.value)} />
          </div>
          {error && (
            <div className="text-sm px-3 py-2 rounded"
              style={{ background: 'rgba(224,82,82,0.1)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.3)' }}>
              {error}
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-amber" disabled={loading || !control.trim()}>
              {loading ? 'Saving…' : 'Record Workaround'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function JobDetail() {
  const { id } = useParams()
  const { role } = useAuth()

  const [job, setJob] = useState(null)
  const [events, setEvents] = useState([])
  const [riskAcceptances, setRiskAcceptances] = useState([])
  const [workarounds, setWorkarounds] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // AI
  const [aiRec, setAiRec] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [feedbackSent, setFeedbackSent] = useState(null)

  // Triage form
  const [triageDecision, setTriageDecision] = useState('')
  const [triageTeam, setTriageTeam] = useState('')
  const [triageComment, setTriageComment] = useState('')
  const [triageLoading, setTriageLoading] = useState(false)
  const [showRationaleAlert, setShowRationaleAlert] = useState(false)

  // Lifecycle transition
  const [transTarget, setTransTarget]   = useState('')
  const [transComment, setTransComment] = useState('')
  const [transNote, setTransNote]       = useState('')
  const [transLoading, setTransLoading] = useState(false)
  const [transError, setTransError]     = useState(null)

  // Modals
  const [showRaModal, setShowRaModal] = useState(false)
  const [showWrModal, setShowWrModal] = useState(false)

  // Custom SLA override
  const [slaOverride, setSlaOverride] = useState('')
  const [slaLoading, setSlaLoading] = useState(false)
  const [slaMsg, setSlaMsg] = useState(null)

  const canWrite = ['analyst', 'remediation_owner', 'risk_owner', 'admin'].includes(role)
  const canRiskAccept = ['risk_owner', 'admin'].includes(role)

  const loadSideData = () => {
    fetchRiskAcceptances(id).then(r => setRiskAcceptances(r.data?.data ?? [])).catch(() => {})
    fetchWorkarounds(id).then(r => setWorkarounds(r.data?.data ?? [])).catch(() => {})
  }

  const loadAll = () => {
    setLoading(true)
    Promise.all([fetchJob(id), fetchJobEvents(id)])
      .then(([jobRes, eventsRes]) => {
        // Fix: API wraps in { data: ... }
        setJob(jobRes.data?.data ?? jobRes.data)
        setEvents(eventsRes.data?.data ?? eventsRes.data ?? [])
      })
      .catch((e) => setError(e.message || 'Failed to load job'))
      .finally(() => setLoading(false))
    loadSideData()
  }

  useEffect(() => { loadAll() }, [id])

  // ── Lifecycle transition ──────────────────────────────────────────────────

  const handleTransition = async (newStatus) => {
    if (RISK_STATES.has(newStatus) && !canRiskAccept) {
      alert('Only risk_owner or admin may move a job to RISK_ACCEPTED.')
      return
    }
    setTransLoading(true)
    setTransError(null)
    try {
      const res = await transitionJob(id, {
        new_status: newStatus,
        comment: transComment || undefined,
        lifecycle_note: transNote || undefined,
      })
      setJob(res.data?.data ?? res.data)
      setTransTarget('')
      setTransComment('')
      setTransNote('')
      // Reload events
      fetchJobEvents(id).then(r => setEvents(r.data?.data ?? r.data ?? []))
    } catch (e) {
      setTransError(e.response?.data?.detail || e.message || 'Transition failed')
    } finally {
      setTransLoading(false)
    }
  }

  // ── Triage ────────────────────────────────────────────────────────────────

  const handleTriage = async (e) => {
    e.preventDefault()
    if (!triageDecision) return
    // RISK_ACCEPTED requires a risk acceptance record first — block and prompt
    if (triageDecision === 'RISK_ACCEPTED') {
      setShowRationaleAlert(true)
      return
    }
    setTriageLoading(true)
    try {
      const res = await triageJob(id, {
        triage_decision: triageDecision,   // fixed: was 'decision'
        assigned_team: triageTeam || undefined,
        comment: triageComment || undefined,
      })
      setJob(res.data?.data ?? res.data)
      setTriageDecision('')
      setTriageTeam('')
      setTriageComment('')
      fetchJobEvents(id).then(r => setEvents(r.data?.data ?? r.data ?? []))
    } catch {
      alert('Failed to submit triage')
    } finally {
      setTriageLoading(false)
    }
  }

  // ── AI ────────────────────────────────────────────────────────────────────

  const handleGenerateAI = async () => {
    setAiLoading(true)
    setAiError(null)
    setAiRec(null)
    try {
      const res = await fetchRagRecommendation(id)
      // API wraps in { data: {...} }; unwrap like other endpoints
      const rec = res.data?.data ?? res.data
      // Flatten _meta so model/latency_ms are always at top level
      if (rec?._meta && !rec.model) {
        rec.model      = rec._meta.model
        rec.latency_ms = rec._meta.latency_ms
      }
      setAiRec(rec)
    } catch (e) {
      setAiError(e.response?.data?.detail || e.message || 'AI recommendation unavailable')
    } finally {
      setAiLoading(false)
    }
  }

  const handleFeedback = async (rating) => {
    try {
      await submitRagFeedback(id, { rating })
      setFeedbackSent(rating)
    } catch { /* silent */ }
  }

  // ── Custom SLA override ───────────────────────────────────────────────────

  const handleSlaOverride = async (e) => {
    e.preventDefault()
    setSlaLoading(true)
    setSlaMsg(null)
    try {
      const days = slaOverride === '' ? null : parseInt(slaOverride, 10)
      const res = await updateJobSla(id, { sla_override_days: days })
      setJob(res.data?.data ?? res.data)
      setSlaMsg({ type: 'ok', text: days ? `SLA set to ${days} days` : 'SLA override cleared' })
      setSlaOverride('')
    } catch (e) {
      setSlaMsg({ type: 'err', text: e.response?.data?.detail || 'Failed to update SLA' })
    } finally {
      setSlaLoading(false)
      setTimeout(() => setSlaMsg(null), 4000)
    }
  }

  // ── Shared styles ─────────────────────────────────────────────────────────

  const inputStyle = {
    background: 'var(--surface-2)', border: '1px solid var(--border)',
    color: 'var(--text)', borderRadius: 6, padding: '8px 12px',
    fontSize: 13, fontFamily: 'Inter, sans-serif', outline: 'none', width: '100%',
  }
  const selectStyle = { ...inputStyle, cursor: 'pointer' }

  // ── Render ────────────────────────────────────────────────────────────────

  if (loading) return <div className="p-8 flex justify-center"><Spinner /></div>
  if (error) return (
    <div className="p-8">
      <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
        <p className="font-mono text-sm" style={{ color: 'var(--red)' }}>{error}</p>
      </div>
    </div>
  )

  const nextStatuses = STATUS_TRANSITIONS[job?.status] ?? []
  const scoreBreakdown = (() => {
    if (!job?.score_breakdown) return null
    if (typeof job.score_breakdown === 'string') {
      try { return JSON.parse(job.score_breakdown) } catch { return null }
    }
    return job.score_breakdown
  })()
  const slaBreached =
    job?.due_date && new Date(job.due_date) < new Date() && !['DONE', 'CLOSED'].includes(job?.status)
  const slaPaused = Boolean(job?.sla_paused_at)

  return (
    <div className="p-8 space-y-6">

      {/* Modals */}
      {showRaModal && (
        <RiskAcceptanceModal
          jobId={id}
          onClose={() => setShowRaModal(false)}
          onCreated={() => { loadSideData(); fetchJobEvents(id).then(r => setEvents(r.data?.data ?? [])) }}
        />
      )}
      {showWrModal && (
        <WorkaroundModal
          jobId={id}
          onClose={() => setShowWrModal(false)}
          onCreated={() => loadSideData()}
        />
      )}

      {/* Breadcrumb + Header */}
      <div>
        <div className="flex items-center gap-2 mb-3 text-sm" style={{ color: 'var(--muted)' }}>
          <Link to="/jobs" className="hover:text-[var(--text)] transition-colors">Remediation Jobs</Link>
          <span>/</span>
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)', fontSize: 12 }}>{id}</span>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="page-title font-mono text-lg">{jobLabel(job) || job?.product_name || job?.main_product || id}</h1>
          <RiskBadge level={job?.risk_level || job?.max_risk_level} />
          {job?.kev_count > 0 || job?.kev_present ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold"
              style={{ background: 'rgba(224,82,82,0.15)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.3)' }}>
              🔴 KEV
            </span>
          ) : null}
          {slaBreached && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold"
              style={{ background: 'rgba(224,82,82,0.12)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.25)' }}>
              ⚠ SLA BREACHED
            </span>
          )}
          {slaPaused && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold"
              style={{ background: 'rgba(255,196,13,0.12)', color: 'var(--amber)', border: '1px solid rgba(255,196,13,0.3)' }}>
              ⏸ SLA PAUSED
            </span>
          )}
          <StatusBadge status={job?.status} />
        </div>
      </div>

      {/* Metadata */}
      <Section title="Metadata">
        <div className="grid grid-cols-2 gap-x-8 gap-y-5 md:grid-cols-4">
          <MetaItem label="Product" value={job?.product_name || job?.main_product} />
          <MetaItem label="Business Unit" value={job?.business_unit} />
          <MetaItem label="Owner" value={job?.business_owner || job?.owner} />
          <MetaItem label="Environment" value={job?.environment} />
          {/* Assets — show hostnames as links to the asset inventory */}
          <div>
            <div className="mono-label mb-1">Assets</div>
            {(() => {
              const hostnames = job?.asset_hostnames ?? []
              if (hostnames.length === 0) {
                return (
                  <div className="text-sm" style={{ color: 'var(--text)' }}>
                    {job?.assets_count ?? job?.affected_asset_count ?? '—'}
                  </div>
                )
              }
              return (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {hostnames.map(({ asset_id, hostname }) => (
                    <a
                      key={asset_id}
                      href={`/assets?search=${encodeURIComponent(hostname)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        fontFamily: '"IBM Plex Mono", monospace',
                        fontSize: 11,
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(78,143,175,0.12)',
                        border: '1px solid rgba(78,143,175,0.35)',
                        color: '#4e8faf',
                        textDecoration: 'none',
                        whiteSpace: 'nowrap',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(78,143,175,0.22)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'rgba(78,143,175,0.12)'}
                    >
                      {hostname || asset_id}
                    </a>
                  ))}
                </div>
              )
            })()}
          </div>
          <MetaItem label="CVEs" value={job?.cve_count} />
          <MetaItem label="SLA Days" value={job?.sla_override_days ? `${job.sla_override_days}d (custom)` : job?.sla_days} />
          <MetaItem label="Due Date" value={job?.due_date ? job.due_date.slice(0, 10) : null} />
          {job?.sla_paused_days > 0 && (
            <MetaItem label="SLA Paused Days" value={job.sla_paused_days} />
          )}
          {job?.lifecycle_note && (
            <div className="col-span-2 md:col-span-4">
              <div className="mono-label mb-1">Lifecycle Note</div>
              <div className="text-sm" style={{ color: 'var(--text)' }}>{job.lifecycle_note}</div>
            </div>
          )}
          {canWrite && (
            <div className="col-span-2 md:col-span-4 pt-2 border-t border-[var(--border)]">
              <div className="mono-label mb-2">Custom SLA Override</div>
              <form onSubmit={handleSlaOverride} className="flex items-center gap-2 flex-wrap">
                <input
                  type="number"
                  min="1"
                  max="3650"
                  placeholder={job?.sla_override_days ? String(job.sla_override_days) : 'Days (e.g. 30)'}
                  value={slaOverride}
                  onChange={(e) => setSlaOverride(e.target.value)}
                  style={{ ...inputStyle, width: 140 }}
                />
                <button type="submit" className="btn-amber text-xs px-3 py-1.5" disabled={slaLoading}>
                  {slaLoading ? 'Saving…' : 'Set SLA'}
                </button>
                {job?.sla_override_days && (
                  <button
                    type="button"
                    className="btn-ghost text-xs px-3 py-1.5"
                    disabled={slaLoading}
                    onClick={() => { setSlaOverride(''); updateJobSla(id, { sla_override_days: null }).then(r => setJob(r.data?.data ?? r.data)) }}
                  >
                    Clear override
                  </button>
                )}
                {slaMsg && (
                  <span className="text-xs font-mono" style={{ color: slaMsg.type === 'ok' ? 'var(--green)' : 'var(--red)' }}>
                    {slaMsg.text}
                  </span>
                )}
              </form>
            </div>
          )}
        </div>
      </Section>

      {/* CVEs */}
      {(() => {
        const cves = (() => {
          if (Array.isArray(job?.cves)) return job.cves
          if (typeof job?.cve_list === 'string') {
            try { return JSON.parse(job.cve_list) } catch { return job.cve_list.split(',').map(s => s.trim()).filter(Boolean) }
          }
          return []
        })()
        if (!cves.length) return null
        return (
          <Section title={`CVEs (${cves.length})`}>
            <div className="flex flex-wrap gap-2">
              {cves.map((cve) => (
                <div key={cve} className="flex items-center gap-2 px-3 py-1.5 rounded"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: 'var(--amber)' }}>{cve}</span>
                  <button className="text-xs hover:opacity-70" style={{ color: 'var(--muted)' }} title="Copy"
                    onClick={() => navigator.clipboard.writeText(cve)}>📋</button>
                </div>
              ))}
            </div>
          </Section>
        )
      })()}

      {/* Score breakdown */}
      {scoreBreakdown && (
        <Section title="Risk Score Breakdown">
          <ScoreBreakdown breakdown={scoreBreakdown} />
        </Section>
      )}

      {/* Lifecycle Controls */}
      <div className="vra-card">
        <div className="mono-label mb-4">Lifecycle Controls</div>
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">

          {/* Transition dropdown */}
          <div>
            <div className="text-xs mb-3 flex items-center gap-2" style={{ color: 'var(--muted)' }}>
              Current: <StatusBadge status={job?.status} />
            </div>
            {nextStatuses.length === 0 ? (
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                No further transitions available from this state.
              </p>
            ) : (
              <div className="space-y-2">
                <select
                  style={selectStyle}
                  value={transTarget}
                  onChange={(e) => { setTransTarget(e.target.value); setTransError(null) }}
                  disabled={transLoading || !canWrite}
                >
                  <option value="">Select next state…</option>
                  {nextStatuses.map((s) => {
                    const restricted = RISK_STATES.has(s) && !canRiskAccept
                    return (
                      <option key={s} value={s} disabled={restricted}>
                        {s.replace(/_/g, ' ')}{restricted ? '  (requires risk_owner)' : ''}
                      </option>
                    )
                  })}
                </select>
                <input style={inputStyle} type="text" placeholder="Comment (optional)"
                  value={transComment} onChange={(e) => setTransComment(e.target.value)} />
                <input style={inputStyle} type="text" placeholder="Lifecycle note (optional)"
                  value={transNote} onChange={(e) => setTransNote(e.target.value)} />
                <button
                  className="w-full px-3 py-2 rounded text-xs font-semibold transition disabled:opacity-40"
                  style={{ background: transTarget ? 'var(--amber)' : 'var(--surface-2)', color: transTarget ? '#000' : 'var(--muted)', border: '1px solid var(--border)' }}
                  disabled={!transTarget || transLoading || !canWrite}
                  onClick={() => transTarget && handleTransition(transTarget)}
                >
                  {transLoading ? 'Applying…' : transTarget ? `Apply: ${transTarget.replace(/_/g, ' ')}` : 'Apply Transition'}
                </button>
                {transError && (
                  <div className="mt-1 text-xs px-3 py-2 rounded"
                    style={{ background: 'rgba(224,82,82,0.1)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.3)' }}>
                    {transError}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Triage form */}
          <form onSubmit={handleTriage} className="space-y-3">
            <div className="mono-label mb-2">Triage Decision</div>
            <select style={selectStyle} value={triageDecision}
              onChange={(e) => setTriageDecision(e.target.value)}
              disabled={!canWrite}>
              <option value="">Select decision…</option>
              {TRIAGE_OPTIONS.map((o) => (
                <option key={o} value={o}>{o.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <input style={inputStyle} type="text" placeholder="Assigned team (optional)"
              value={triageTeam} onChange={(e) => setTriageTeam(e.target.value)}
              disabled={!canWrite} />
            <textarea style={{ ...inputStyle, resize: 'vertical', minHeight: 60 }}
              placeholder="Comment (optional)" value={triageComment}
              onChange={(e) => setTriageComment(e.target.value)}
              disabled={!canWrite} />
            {/* RISK_ACCEPTED warning — shown when user tries to submit without rationale */}
            {showRationaleAlert && triageDecision === 'RISK_ACCEPTED' && (
              <div
                className="px-4 py-3 rounded text-sm"
                style={{ background: 'rgba(251,191,36,0.1)', border: '1px solid rgba(251,191,36,0.4)', color: '#fbbf24' }}
              >
                <strong>Risk Acceptance Rationale Required</strong>
                <p className="mt-1 text-xs" style={{ color: 'var(--text)' }}>
                  You must record a Risk Acceptance justification before marking this job as
                  RISK_ACCEPTED. Click <strong>"Record Risk Acceptance"</strong> below, fill in the
                  justification and compensating controls, then submit triage.
                </p>
                <button
                  type="button"
                  className="mt-2 text-xs underline"
                  style={{ color: '#fbbf24', background: 'none', border: 'none', cursor: 'pointer' }}
                  onClick={() => setShowRationaleAlert(false)}
                >
                  Dismiss
                </button>
              </div>
            )}
            <button type="submit" className="btn-ghost text-sm"
              disabled={!triageDecision || triageLoading || !canWrite}>
              {triageLoading ? 'Submitting…' : 'Submit Triage'}
            </button>
          </form>
        </div>

        {/* Risk acceptance + workaround quick-launch */}
        {canWrite && (
          <div className="flex flex-wrap gap-3 mt-5 pt-5" style={{ borderTop: '1px solid var(--border)' }}>
            {canRiskAccept && (
              <button className="btn-ghost text-xs"
                style={{ color: 'var(--amber)', borderColor: 'var(--amber)' }}
                onClick={() => setShowRaModal(true)}>
                📋 Record Risk Acceptance
              </button>
            )}
            <button className="btn-ghost text-xs" onClick={() => setShowWrModal(true)}>
              🔧 Record Workaround
            </button>
          </div>
        )}
      </div>

      {/* Risk Acceptances */}
      {riskAcceptances.length > 0 && (
        <Section title={`Risk Acceptances (${riskAcceptances.length})`}>
          <div className="space-y-3">
            {riskAcceptances.map((ra) => (
              <div key={ra.id} className="px-4 py-3 rounded"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs" style={{ color: 'var(--amber)' }}>
                    #{ra.id} · {ra.status?.toUpperCase()}
                  </span>
                  <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                    {ra.created_at ? new Date(ra.created_at).toLocaleDateString() : ''}
                  </span>
                </div>
                <p className="text-sm" style={{ color: 'var(--text)' }}>{ra.justification}</p>
                {ra.compensating_controls && (
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Controls: {ra.compensating_controls}</p>
                )}
                {ra.expiry_date && (
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Expires: {ra.expiry_date}</p>
                )}
                <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Accepted by: {ra.accepted_by}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Workarounds */}
      {workarounds.length > 0 && (
        <Section title={`Workarounds (${workarounds.length})`}>
          <div className="space-y-3">
            {workarounds.map((wr) => (
              <div key={wr.id} className="px-4 py-3 rounded"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                    by {wr.recorded_by}
                  </span>
                  <span className="font-mono text-xs" style={{ color: 'var(--muted)' }}>
                    {wr.created_at ? new Date(wr.created_at).toLocaleDateString() : ''}
                  </span>
                </div>
                <p className="text-sm" style={{ color: 'var(--text)' }}>{wr.control_description}</p>
                {wr.followup_date && (
                  <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Follow-up: {wr.followup_date}</p>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* AI Recommendation */}
      <div className="vra-card" style={{ borderColor: 'rgba(255,196,13,0.4)', borderLeftWidth: 3 }}>
        <div className="mono-label mb-3">AI Recommendation</div>
        {!aiRec && !aiLoading && !aiError && (
          <button className="btn-amber" onClick={handleGenerateAI}>✨ Generate AI Recommendation</button>
        )}
        {aiLoading && (
          <div className="flex items-center gap-3 py-4">
            <Spinner small />
            <span className="text-sm" style={{ color: 'var(--muted)' }}>Generating recommendation…</span>
          </div>
        )}
        {aiError && (
          <div className="space-y-3">
            <div className="px-4 py-3 rounded text-sm"
              style={{ background: 'rgba(224,82,82,0.1)', border: '1px solid rgba(224,82,82,0.3)', color: 'var(--red)' }}>
              ⚠ Ollama unavailable — {aiError}
            </div>
            <button className="btn-ghost text-sm" onClick={handleGenerateAI}>Retry</button>
          </div>
        )}
        {aiRec && (
          <div className="space-y-5">
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text)' }}>{aiRec.summary}</p>
            <div className="flex flex-wrap items-center gap-6">
              {aiRec.exploitation_likelihood && (
                <div>
                  <div className="mono-label mb-1">Exploitation Likelihood</div>
                  <RiskBadge level={aiRec.exploitation_likelihood} />
                </div>
              )}
              {aiRec.confidence != null && (
                <div className="flex-1 min-w-48">
                  <div className="mono-label mb-1">Confidence — {Math.round(aiRec.confidence * 100)}%</div>
                  <div className="h-2 rounded-full" style={{ background: 'var(--border)' }}>
                    <div className="h-2 rounded-full"
                      style={{ width: `${aiRec.confidence * 100}%`, background: 'var(--amber)' }} />
                  </div>
                </div>
              )}
            </div>
            {aiRec.remediation_steps?.length > 0 && (
              <div>
                <div className="mono-label mb-2">Remediation Steps</div>
                <ol className="list-decimal list-inside space-y-1.5">
                  {aiRec.remediation_steps.map((step, i) => (
                    <li key={i} className="text-sm leading-relaxed" style={{ color: 'var(--text)' }}>{step}</li>
                  ))}
                </ol>
              </div>
            )}
            {aiRec.compensating_controls?.length > 0 && (
              <div>
                <div className="mono-label mb-2">Compensating Controls</div>
                <ul className="list-disc list-inside space-y-1">
                  {aiRec.compensating_controls.map((ctrl, i) => (
                    <li key={i} className="text-sm" style={{ color: 'var(--text)' }}>{ctrl}</li>
                  ))}
                </ul>
              </div>
            )}
            {aiRec.verification && (
              <div>
                <div className="mono-label mb-1">Verification</div>
                <p className="text-sm" style={{ color: 'var(--text)' }}>{aiRec.verification}</p>
              </div>
            )}
            {(aiRec.model || aiRec.latency_ms) && (
              <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
                {aiRec.model && `model: ${aiRec.model}`}
                {aiRec.model && aiRec.latency_ms && ' · '}
                {aiRec.latency_ms && `${aiRec.latency_ms}ms`}
              </div>
            )}
            <div className="flex items-center gap-3 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
              <span className="mono-label">Feedback</span>
              {feedbackSent ? (
                <span className="text-sm" style={{ color: 'var(--green)' }}>
                  Thanks {feedbackSent === 'positive' ? '👍' : '👎'}
                </span>
              ) : (
                <>
                  <button className="text-xl hover:scale-110 transition-transform" onClick={() => handleFeedback('positive')} title="Helpful">👍</button>
                  <button className="text-xl hover:scale-110 transition-transform" onClick={() => handleFeedback('negative')} title="Not helpful">👎</button>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Chat with Finding */}
      <ChatPanel jobId={id} role={role} />

      {/* Events Timeline */}
      <Section title="Events Timeline">
        {events.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--muted)' }}>No events recorded</p>
        ) : (
          <div className="space-y-0">
            {events.map((ev, i) => (
              <div key={ev.id ?? i} className="flex gap-4 pb-4">
                <div className="flex flex-col items-center">
                  <div className="w-2 h-2 rounded-full mt-1 flex-shrink-0" style={{ background: 'var(--amber)' }} />
                  {i < events.length - 1 && (
                    <div className="w-px flex-1 mt-1" style={{ background: 'var(--border)' }} />
                  )}
                </div>
                <div className="flex-1 pb-1">
                  <div className="flex items-center gap-3 mb-0.5 flex-wrap">
                    <span className="text-xs font-semibold uppercase tracking-wider"
                      style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)' }}>
                      {ev.event_type || ev.type}
                    </span>
                    {(ev.old_status || ev.new_status) && (
                      <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
                        {ev.old_status} → {ev.new_status}
                      </span>
                    )}
                    {ev.changed_by && (
                      <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
                        by {ev.changed_by}
                      </span>
                    )}
                    <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)', marginLeft: 'auto' }}>
                      {ev.created_at ? new Date(ev.created_at).toLocaleString() : ''}
                    </span>
                  </div>
                  {ev.comment && (
                    <p className="text-sm mt-1" style={{ color: 'var(--text)' }}>{ev.comment}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}
