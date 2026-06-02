import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  fetchComplianceSummary,
  fetchComplianceControls,
  reloadComplianceCatalog,
} from '../api/client'
import { useAuth } from '../context/AuthContext'

// ─── Constants ────────────────────────────────────────────────────────────────

const STATUS_META = {
  full:           { label: 'Full',       color: 'var(--green)', bg: 'rgba(34,197,94,0.12)',   border: 'rgba(34,197,94,0.3)' },
  partial:        { label: 'Partial',    color: 'var(--amber)', bg: 'rgba(255,196,13,0.10)',  border: 'rgba(255,196,13,0.35)' },
  supporting:     { label: 'Supporting', color: '#818cf8',      bg: 'rgba(129,140,248,0.10)', border: 'rgba(129,140,248,0.35)' },
  not_applicable: { label: 'N/A',        color: 'var(--muted)', bg: 'transparent',            border: 'var(--border)' },
}

const FRAMEWORK_META = {
  ISO27001: { label: 'ISO 27001:2022', short: 'ISO 27001', color: '#f59e0b', bg: 'rgba(245,158,11,0.10)',  border: 'rgba(245,158,11,0.35)' },
  CIS:      { label: 'CIS Controls v8', short: 'CIS v8',   color: '#06b6d4', bg: 'rgba(6,182,212,0.10)',   border: 'rgba(6,182,212,0.35)' },
  CSF:      { label: 'NIST CSF 2.0',    short: 'NIST CSF', color: '#a78bfa', bg: 'rgba(167,139,250,0.10)', border: 'rgba(167,139,250,0.35)' },
}

const FRAMEWORK_ORDER = ['ISO27001', 'CIS', 'CSF']

const FRAMEWORK_TABS = [
  { key: '',        label: 'All Frameworks' },
  { key: 'ISO27001',label: 'ISO 27001' },
  { key: 'CIS',     label: 'CIS v8' },
  { key: 'CSF',     label: 'NIST CSF' },
]

const EVIDENCE_LABELS = {
  assets_total:             'Total Assets',
  assets_classified:        'Classified Assets',
  assets_classified_pct:    'Classification Coverage',
  uploads_count:            'Scan Uploads (done)',
  audit_events_count:       'Audit Events Logged',
  ticket_links_count:       'Ticket Links',
  jobs_total:               'Total Jobs',
  ticket_coverage_pct:      'Ticket Coverage',
  software_records_count:   'Software Records',
  software_coverage_pct:    'Software Coverage',
  risk_acceptances_count:   'Active Risk Acceptances',
  ai_advice_count:          'Jobs with AI Advice',
  ai_advice_coverage_pct:   'AI Advice Coverage',
  workaround_records_count: 'Workaround Records',
  kev_jobs_count:           'KEV-Flagged Jobs',
  threat_alerts_count:      'Threat Alerts',
  users_count:              'Active Users',
  done_jobs_count:          'Resolved Jobs',
  internet_exposed_count:   'Internet-Exposed Assets',
  overdue_jobs_count:       'Overdue Jobs',
  sla_jobs_count:           'Jobs with SLA',
  remediation_rate_pct:     'Remediation Rate',
  sla_configured_pct:       'SLA Configuration',
}

// Thresholds for FULL status — used to colour evidence metrics in the drawer
const FULL_THRESHOLDS = {
  assets_classified_pct:   90,
  ticket_coverage_pct:     50,
  software_coverage_pct:   20,
  ai_advice_coverage_pct:  100,
  remediation_rate_pct:    80,
  sla_configured_pct:      100,
  audit_events_count:      10,
  uploads_count:           1,
  threat_alerts_count:     100,
  kev_jobs_count:          1,
  risk_acceptances_count:  1,
  workaround_records_count:5,
  users_count:             5,
  assets_total:            1,
  done_jobs_count:         1,
  software_records_count:  1,
  ticket_links_count:      1,
}

// What VRA produces as evidence — short human-readable explanation per control
const SUPPORT_NARRATIVE = {
  'ISO-A.8.1':  'VRA maintains an asset inventory with criticality, environment, internet-exposure, and owner fields — queryable by auditors in real time.',
  'ISO-A.8.8':  'VRA ingests scanner exports (Nessus/OpenVAS/CSV), enriches with NVD/EPSS/KEV, and creates scored remediation jobs with SLA deadlines.',
  'ISO-A.5.26': 'Every job lifecycle transition is recorded in job_events with actor, timestamp, old/new status, and free-text comment — forming a tamper-evident audit trail.',
  'ISO-A.5.24': 'VRA creates ticket links to external ITSM tools per job. Ticket coverage (linked jobs ÷ total jobs) is measured live.',
  'ISO-A.8.9':  'VRA\'s asset_software table stores installed product/version/vendor per asset. CPE-CVE matching drives threat alert generation.',
  'ISO-A.5.10': 'VRA captures formal risk acceptances (justification, approver, expiry) and compensating workarounds for jobs that cannot be immediately remediated.',
  'ISO-A.5.35': 'VRA\'s RAG engine (Qwen2.5-14B + ChromaDB) generates structured JSON remediation advice per job, logged with model provenance and analyst feedback scores.',
  'ISO-A.5.29': 'VRA\'s SLA tracking and job audit trail provide business-continuity evidence. Recovery planning and DR remain organisational responsibilities.',
  'CIS-1':      'VRA tracks all assets with criticality, internet-exposure flags, and owner fields. Asset count and classification coverage are measured in real time.',
  'CIS-7':      'VRA cross-references asset CPEs with CISA KEV, FIRST EPSS, and NVD to surface exploitable vulnerabilities. KEV jobs and threat alert counts are live metrics.',
  'CIS-17':     'VRA provides a structured incident-response workflow: scan → enrich → score → remediation job → lifecycle events → SLA enforcement.',
  'CIS-2':      'VRA\'s asset_software inventory tracks installed software per device. Low coverage indicates a data-quality gap that should be addressed via scanner enrichment.',
  'CIS-5':      'VRA enforces RBAC across five roles (admin, analyst, remediation_owner, risk_owner, auditor) with JWT sessions and API-key write controls.',
  'CIS-6':      'Access control is enforced per role. Ticket integration provides an additional workflow gate. Ticket coverage measures how consistently this is applied.',
  'CIS-13':     'VRA\'s threat-alert engine correlates CPEs against live feeds and surfaces 500+ alerts. Remediation rate measures how quickly detected threats are resolved.',
  'CIS-18':     'Penetration testing is an organisational activity. VRA provides supporting evidence through its vulnerability pipeline and remediation tracking.',
  'CSF-ID.AM':  'VRA\'s asset inventory (55 assets, all classified) fulfils the Identify → Asset Management outcome of the NIST CSF.',
  'CSF-PR.IP':  'VRA enforces SLA-bound remediation deadlines on every job based on risk level, implementing the Protect → Information Protection Processes outcome.',
  'CSF-DE.CM':  'VRA\'s threat-alert engine runs continuous correlation against NVD/KEV feeds. Remediation rate tracks closure of detected threats.',
  'CSF-RS.MI':  'VRA measures the remediation rate (resolved jobs ÷ total jobs) as the primary Respond → Incident Mitigation KPI. 80% is the full-evidence threshold.',
  'CSF-RC.RP':  'VRA records compensating workarounds with follow-up dates when immediate remediation is not possible, supporting structured recovery planning.',
  'CSF-GV.OC':  'Organisational context, mission, and regulatory requirements are defined outside VRA. VRA provides supporting evidence through its risk-scored job pipeline.',
}

// ─── Pure helpers ─────────────────────────────────────────────────────────────

function fmt(key, value) {
  if (value === undefined || value === null) return '—'
  if (key.endsWith('_pct')) return `${value}%`
  return typeof value === 'number' ? value.toLocaleString() : value
}

function metricHealth(key, value) {
  const threshold = FULL_THRESHOLDS[key]
  if (threshold === undefined) return 'neutral'
  if (value >= threshold) return 'good'
  if (value > 0) return 'warn'
  return 'bad'
}

function coveragePct(counts) {
  const { full = 0, total = 1 } = counts
  return Math.round((full / total) * 100)
}

function groupByFramework(controls) {
  const groups = {}
  for (const ctrl of controls) {
    if (!groups[ctrl.framework]) groups[ctrl.framework] = []
    groups[ctrl.framework].push(ctrl)
  }
  return groups
}

// ─── Micro components ─────────────────────────────────────────────────────────

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

function StatusChip({ status }) {
  const m = STATUS_META[status] ?? STATUS_META.not_applicable
  return (
    <span
      className="font-mono font-semibold rounded uppercase tracking-wide px-2 py-0.5"
      style={{ fontSize: 10, color: m.color, background: m.bg, border: `1px solid ${m.border}` }}
    >
      {m.label}
    </span>
  )
}

function FrameworkPill({ framework, size = 'sm' }) {
  const m = FRAMEWORK_META[framework] ?? { short: framework, color: 'var(--muted)', bg: 'var(--surface)', border: 'var(--border)' }
  return (
    <span
      className="font-mono rounded px-2 py-0.5 font-semibold"
      style={{ fontSize: size === 'lg' ? 11 : 10, color: m.color, background: m.bg, border: `1px solid ${m.border}` }}
    >
      {size === 'lg' ? (m.label ?? m.short) : m.short}
    </span>
  )
}

function CoverageBar({ full = 0, partial = 0, supporting = 0, total = 1, height = 6 }) {
  return (
    <div className="flex rounded overflow-hidden w-full" style={{ height }}>
      <div style={{ width: `${(full / total) * 100}%`,       background: 'var(--green)', transition: 'width 0.4s' }} title={`Full: ${full}`} />
      <div style={{ width: `${(partial / total) * 100}%`,    background: 'var(--amber)', transition: 'width 0.4s' }} title={`Partial: ${partial}`} />
      <div style={{ width: `${(supporting / total) * 100}%`, background: '#818cf8',      transition: 'width 0.4s' }} title={`Supporting: ${supporting}`} />
    </div>
  )
}

function HealthDot({ health }) {
  const c = health === 'good' ? 'var(--green)' : health === 'warn' ? 'var(--amber)' : health === 'bad' ? 'var(--red)' : 'var(--border)'
  return <span className="w-1.5 h-1.5 rounded-full flex-shrink-0 inline-block" style={{ background: c }} />
}

// ─── Framework tile (header section) ─────────────────────────────────────────

function FrameworkTile({ framework, counts, onClick, active }) {
  const m = FRAMEWORK_META[framework]
  const { full = 0, partial = 0, supporting = 0, total = 0 } = counts
  const pct = coveragePct(counts)

  return (
    <button
      onClick={onClick}
      className="flex flex-col gap-3 rounded p-4 text-left transition-all hover:opacity-90 w-full"
      style={{
        background: active ? m.bg : 'var(--surface)',
        border: `1px solid ${active ? m.color + '80' : 'var(--border)'}`,
        cursor: 'pointer',
        outline: 'none',
      }}
    >
      {/* Top row */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontWeight: 700, fontSize: 11, color: m.color, marginBottom: 2 }}>
            {m.short}
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 400, lineHeight: 1.4 }}>
            {m.label}
          </div>
        </div>
        {/* Coverage % ring */}
        <div
          className="flex-shrink-0 flex items-center justify-center rounded-full"
          style={{ width: 44, height: 44, background: m.bg, border: `2px solid ${m.color}60` }}
        >
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontWeight: 800, fontSize: 13, color: m.color }}>
            {pct}%
          </span>
        </div>
      </div>

      {/* Coverage bar */}
      <CoverageBar full={full} partial={partial} supporting={supporting} total={total} height={5} />

      {/* Counts row */}
      <div className="flex gap-3 flex-wrap" style={{ fontSize: 11 }}>
        <span style={{ color: 'var(--green)' }}>{full} full</span>
        <span style={{ color: 'var(--amber)' }}>{partial} partial</span>
        <span style={{ color: '#818cf8' }}>{supporting} supporting</span>
        <span style={{ color: 'var(--muted)', marginLeft: 'auto' }}>{total} controls</span>
      </div>
    </button>
  )
}

// ─── Evidence metric card ─────────────────────────────────────────────────────

function MetricCard({ label, metricKey, value, showHealth = false }) {
  const health = showHealth ? metricHealth(metricKey, value ?? 0) : 'neutral'
  const threshold = FULL_THRESHOLDS[metricKey]

  return (
    <div
      className="rounded px-3 py-2.5 flex flex-col gap-1"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
    >
      <div className="flex items-center gap-1.5">
        {showHealth && <HealthDot health={health} />}
        <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace' }}>
          {label}
        </span>
      </div>
      <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)', fontFamily: '"IBM Plex Mono", monospace' }}>
        {fmt(metricKey, value)}
      </span>
      {showHealth && threshold !== undefined && health !== 'good' && (
        <span style={{ fontSize: 10, color: 'var(--muted)' }}>
          target: {metricKey.endsWith('_pct') ? `${threshold}%` : threshold}
        </span>
      )}
    </div>
  )
}

// ─── Control row in grouped table ────────────────────────────────────────────

function ControlRow({ ctrl, onOpen }) {
  const sm = STATUS_META[ctrl.status] ?? STATUS_META.not_applicable
  const evidenceCount = Object.keys(ctrl.evidence || {}).length

  // First 3 evidence values as a quick preview
  const preview = Object.entries(ctrl.evidence || {}).slice(0, 3)

  return (
    <tr
      onClick={() => onOpen(ctrl)}
      className="cursor-pointer transition-colors group"
      style={{ borderBottom: '1px solid var(--border)' }}
      onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--surface)' }}
      onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
    >
      {/* Status dot */}
      <td className="pl-4 pr-2 py-3">
        <span
          className="w-2.5 h-2.5 rounded-full inline-block flex-shrink-0"
          style={{ background: sm.color }}
        />
      </td>

      {/* Control ID */}
      <td className="px-2 py-3 whitespace-nowrap">
        <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: 'var(--text)', fontWeight: 700 }}>
          {ctrl.control_id}
        </span>
      </td>

      {/* Name */}
      <td className="px-3 py-3" style={{ maxWidth: 260 }}>
        <span style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{ctrl.name}</span>
      </td>

      {/* Status chip */}
      <td className="px-3 py-3 whitespace-nowrap">
        <StatusChip status={ctrl.status} />
      </td>

      {/* Evidence preview */}
      <td className="px-3 py-3" style={{ minWidth: 200 }}>
        <div className="flex flex-wrap gap-2">
          {preview.map(([k, v]) => (
            <span
              key={k}
              className="flex items-center gap-1"
              style={{ fontSize: 10, fontFamily: '"IBM Plex Mono", monospace', color: 'var(--muted)' }}
            >
              <HealthDot health={metricHealth(k, v)} />
              {fmt(k, v)}
              <span style={{ color: '#444', fontSize: 9 }}>{EVIDENCE_LABELS[k] ?? k}</span>
            </span>
          ))}
          {evidenceCount > 3 && (
            <span style={{ fontSize: 10, color: 'var(--muted)' }}>+{evidenceCount - 3} more</span>
          )}
          {evidenceCount === 0 && (
            <span style={{ fontSize: 10, color: 'var(--muted)', fontStyle: 'italic' }}>organisational</span>
          )}
        </div>
      </td>

      {/* Open caret */}
      <td className="px-4 py-3 text-right" style={{ width: 28 }}>
        <span style={{ color: 'var(--muted)', fontSize: 13 }} className="group-hover:text-[var(--amber)] transition-colors">›</span>
      </td>
    </tr>
  )
}

// ─── Framework section (table group header + rows) ────────────────────────────

function FrameworkSection({ framework, controls, counts }) {
  const m = FRAMEWORK_META[framework]

  return (
    <>
      {/* Section header */}
      <tr>
        <td
          colSpan={6}
          className="px-4 py-2"
          style={{ borderBottom: '1px solid var(--border)', background: m.bg + 'cc' }}
        >
          <div className="flex items-center gap-3">
            <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontWeight: 800, fontSize: 11, color: m.color, letterSpacing: '0.05em' }}>
              {m.label}
            </span>
            {/* Coverage mini bar */}
            <div style={{ width: 80 }}>
              <CoverageBar
                full={counts?.full ?? 0}
                partial={counts?.partial ?? 0}
                supporting={counts?.supporting ?? 0}
                total={counts?.total ?? 1}
                height={4}
              />
            </div>
            {/* Badge */}
            <span
              className="font-mono rounded px-2 py-0.5 text-xs font-bold"
              style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}
            >
              {counts?.full ?? 0}/{counts?.total ?? 0} full
            </span>
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>
              {counts?.partial ?? 0} partial · {counts?.supporting ?? 0} supporting
            </span>
          </div>
        </td>
      </tr>
      {controls.map((ctrl) => (
        <ControlRowWrapper key={ctrl.control_id} ctrl={ctrl} />
      ))}
    </>
  )
}

// Placeholder — will be replaced by the context-based pattern below
function ControlRowWrapper() { return null }

// ─── Detail drawer ────────────────────────────────────────────────────────────

function ControlDrawer({ ctrl, onClose }) {
  const navigate = useNavigate()
  const panelRef = useRef(null)

  // Trap focus and handle Escape
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!ctrl) return null

  const m   = FRAMEWORK_META[ctrl.framework] ?? {}
  const sm  = STATUS_META[ctrl.status] ?? STATUS_META.not_applicable
  const evidence = ctrl.evidence ?? {}
  const narrative = SUPPORT_NARRATIVE[ctrl.control_id] ?? ctrl.objective ?? ctrl.description ?? ''

  // Separate raw counts from derived percentages for grouping
  const rawMetrics  = Object.entries(evidence).filter(([k]) => !k.endsWith('_pct'))
  const pctMetrics  = Object.entries(evidence).filter(([k]) =>  k.endsWith('_pct'))

  // Gap analysis: derived metrics below threshold (partial / not_applicable only)
  const gaps = Object.entries(evidence).filter(([k, v]) => {
    const t = FULL_THRESHOLDS[k]
    return t !== undefined && v < t
  })

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        style={{ background: 'rgba(0,0,0,0.55)' }}
        onClick={onClose}
      />

      {/* Panel */}
      <div
        ref={panelRef}
        className="fixed right-0 top-0 h-screen z-50 flex flex-col"
        style={{
          width: 500,
          background: 'var(--black)',
          borderLeft: '1px solid var(--border)',
          boxShadow: '-8px 0 32px rgba(0,0,0,0.5)',
          overflowY: 'auto',
        }}
      >
        {/* ── Panel header ── */}
        <div
          className="flex items-start justify-between px-6 py-5 flex-shrink-0"
          style={{ borderBottom: '1px solid var(--border)', background: m.bg ?? 'var(--surface)' }}
        >
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              <FrameworkPill framework={ctrl.framework} size="lg" />
              <StatusChip status={ctrl.status} />
            </div>
            <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontWeight: 800, fontSize: 15, color: m.color ?? 'var(--text)' }}>
              {ctrl.control_id}
            </span>
            <span style={{ fontSize: 14, color: 'var(--text)', fontWeight: 600, lineHeight: 1.4 }}>
              {ctrl.name}
            </span>
          </div>
          <button
            onClick={onClose}
            className="flex-shrink-0 ml-4 p-1.5 rounded transition-colors hover:bg-[var(--surface-2)]"
            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--muted)', fontSize: 18, lineHeight: 1 }}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* ── Inline disclaimer ── */}
        <div
          className="flex items-start gap-2 px-6 py-3 flex-shrink-0"
          style={{ background: 'rgba(255,196,13,0.05)', borderBottom: '1px solid rgba(255,196,13,0.2)' }}
        >
          <span style={{ color: 'var(--amber)', fontSize: 13, marginTop: 1 }}>⚠</span>
          <p style={{ fontSize: 11, color: 'var(--amber)', lineHeight: 1.5, fontStyle: 'italic' }}>
            VRA produces evidence <strong>supporting</strong> this control; this is not a certification claim.
          </p>
        </div>

        {/* ── Scrollable body ── */}
        <div className="flex-1 px-6 py-5 flex flex-col gap-6" style={{ overflowY: 'auto' }}>

          {/* Support narrative */}
          <section>
            <SectionLabel>What VRA Measures</SectionLabel>
            <p style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7 }}>{narrative}</p>
          </section>

          {/* Coverage status */}
          <section>
            <SectionLabel>Coverage Status</SectionLabel>
            <div
              className="flex items-center gap-3 rounded px-4 py-3"
              style={{ background: sm.bg, border: `1px solid ${sm.border}` }}
            >
              <span className="w-3 h-3 rounded-full flex-shrink-0" style={{ background: sm.color }} />
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: sm.color }}>{sm.label}</div>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                  {ctrl.status === 'full' && 'All evidence thresholds are met. This control is fully evidenced by VRA.'}
                  {ctrl.status === 'partial' && 'Some evidence is present but one or more thresholds are not yet met. See gap analysis below.'}
                  {ctrl.status === 'supporting' && 'VRA provides supporting evidence only. The control itself is implemented at the organisational level.'}
                  {ctrl.status === 'not_applicable' && 'Insufficient evidence in VRA to assess this control.'}
                </div>
              </div>
            </div>
          </section>

          {/* Live evidence snapshot */}
          {Object.keys(evidence).length > 0 && (
            <section>
              <SectionLabel>Live Evidence Snapshot</SectionLabel>
              {pctMetrics.length > 0 && (
                <>
                  <p style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Coverage Percentages
                  </p>
                  <div className="grid gap-2 mb-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(180px,1fr))' }}>
                    {pctMetrics.map(([k, v]) => (
                      <MetricCard key={k} metricKey={k} label={EVIDENCE_LABELS[k] ?? k} value={v} showHealth />
                    ))}
                  </div>
                </>
              )}
              {rawMetrics.length > 0 && (
                <>
                  <p style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Raw Counts
                  </p>
                  <div className="grid gap-2" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(180px,1fr))' }}>
                    {rawMetrics.map(([k, v]) => (
                      <MetricCard key={k} metricKey={k} label={EVIDENCE_LABELS[k] ?? k} value={v} showHealth />
                    ))}
                  </div>
                </>
              )}
            </section>
          )}

          {Object.keys(evidence).length === 0 && (
            <section>
              <SectionLabel>Evidence</SectionLabel>
              <p style={{ fontSize: 12, color: 'var(--muted)', fontStyle: 'italic' }}>
                No automated evidence queries — this is an organisational control.
                VRA's audit trail and SLA records serve as supporting documentation.
              </p>
            </section>
          )}

          {/* Gap analysis — only for partial */}
          {ctrl.status === 'partial' && gaps.length > 0 && (
            <section>
              <SectionLabel color="var(--amber)">Gap Analysis</SectionLabel>
              <div className="flex flex-col gap-2">
                {gaps.map(([k, v]) => {
                  const threshold = FULL_THRESHOLDS[k]
                  const unit = k.endsWith('_pct') ? '%' : ''
                  return (
                    <div
                      key={k}
                      className="flex items-center gap-3 rounded px-3 py-2.5"
                      style={{ background: 'rgba(255,196,13,0.06)', border: '1px solid rgba(255,196,13,0.25)' }}
                    >
                      <span style={{ color: 'var(--amber)', fontSize: 16, lineHeight: 1 }}>△</span>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>
                          {EVIDENCE_LABELS[k] ?? k}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--muted)' }}>
                          Current: <span style={{ color: 'var(--amber)', fontWeight: 700, fontFamily: '"IBM Plex Mono", monospace' }}>
                            {fmt(k, v)}
                          </span>
                          {' · '}
                          Target: <span style={{ fontFamily: '"IBM Plex Mono", monospace' }}>
                            {threshold}{unit}
                          </span>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </section>
          )}

          {/* Deep links */}
          {ctrl.deep_links?.length > 0 && (
            <section>
              <SectionLabel>Jump To</SectionLabel>
              <div className="flex flex-wrap gap-2">
                {ctrl.deep_links.map((lnk) => (
                  <button
                    key={lnk.path}
                    onClick={() => { onClose(); navigate(lnk.path) }}
                    className="rounded px-3 py-2 transition-colors hover:opacity-80 text-left"
                    style={{
                      fontSize: 12, fontWeight: 600,
                      background: 'var(--surface)',
                      border: '1px solid var(--border)',
                      color: 'var(--amber)',
                      cursor: 'pointer',
                    }}
                  >
                    {lnk.label} →
                  </button>
                ))}
              </div>
            </section>
          )}
        </div>

        {/* ── Panel footer ── */}
        <div
          className="flex-shrink-0 px-6 py-3 flex items-center justify-between"
          style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)' }}
        >
          <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace' }}>
            Evidence queried live · {new Date().toLocaleTimeString()}
          </span>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded text-sm transition-colors hover:opacity-80"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--muted)', cursor: 'pointer' }}
          >
            Close
          </button>
        </div>
      </div>
    </>
  )
}

function SectionLabel({ children, color = 'var(--muted)' }) {
  return (
    <p style={{
      fontSize: 10,
      color,
      marginBottom: 8,
      textTransform: 'uppercase',
      letterSpacing: '0.07em',
      fontWeight: 700,
      fontFamily: '"IBM Plex Mono", monospace',
    }}>
      {children}
    </p>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function Compliance() {
  const { role } = useAuth()
  const isAdmin = role === 'admin'

  const [summary,    setSummary]    = useState(null)
  const [controls,   setControls]   = useState([])
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [framework,  setFramework]  = useState('')
  const [drawer,     setDrawer]     = useState(null)   // control obj or null
  const [reloading,  setReloading]  = useState(false)
  const [reloadMsg,  setReloadMsg]  = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    Promise.all([
      fetchComplianceSummary(),
      fetchComplianceControls(framework ? { framework } : {}),
    ])
      .then(([sRes, cRes]) => {
        setSummary(sRes.data?.data  ?? {})
        setControls(cRes.data?.data ?? [])
      })
      .catch((e) => setError(e.response?.data?.detail || e.message || 'Failed to load compliance data'))
      .finally(() => setLoading(false))
  }, [framework])

  useEffect(() => { load() }, [load])

  const handleReload = () => {
    setReloading(true)
    setReloadMsg(null)
    reloadComplianceCatalog()
      .then((r) => { setReloadMsg(`Reloaded — ${r.data?.data?.controls_loaded} controls.`); load() })
      .catch((e) => setReloadMsg(`Error: ${e.response?.data?.detail || e.message}`))
      .finally(() => setReloading(false))
  }

  const byFramework = summary?.by_framework ?? {}

  // Group controls for the table
  const grouped = groupByFramework(controls)
  const orderedFrameworks = FRAMEWORK_ORDER.filter((fw) => grouped[fw])

  return (
    <div className="p-8" style={{ maxWidth: 1280, margin: '0 auto' }}>

      {/* ── Page header ── */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <h1 style={{ fontFamily: 'Syne, sans-serif', fontWeight: 800, fontSize: 26, color: 'var(--text)' }}>
            Compliance Control Mapping
          </h1>
          <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 4 }}>
            Live evidence mapped to ISO 27001:2022 · CIS Controls v8 · NIST CSF 2.0
          </p>
        </div>
        {isAdmin && (
          <button
            onClick={handleReload}
            disabled={reloading}
            className="px-4 py-2 rounded text-sm font-semibold transition disabled:opacity-40"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--amber)', cursor: 'pointer' }}
          >
            {reloading ? 'Reloading…' : '↺ Reload Catalog'}
          </button>
        )}
      </div>

      {/* ── Disclaimer banner ── */}
      <div
        className="flex items-center gap-3 rounded px-5 py-3 mb-6"
        style={{
          background: 'rgba(255,196,13,0.06)',
          border: '1px solid rgba(255,196,13,0.4)',
          borderLeft: '4px solid var(--amber)',
        }}
      >
        <span style={{ fontSize: 18, color: 'var(--amber)', lineHeight: 1, flexShrink: 0 }}>⚠</span>
        <p style={{ fontSize: 13, color: 'var(--amber)', lineHeight: 1.5, margin: 0 }}>
          <strong>VRA produces evidence SUPPORTING these controls; this is not a certification claim.</strong>
          {' '}Evidence metrics are queried live from VRA's database and reflect the current state of the
          vulnerability management programme. Formal certification requires an accredited third-party audit.
        </p>
      </div>

      {reloadMsg && (
        <div className="mb-4 px-4 py-2 rounded text-sm" style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--muted)' }}>
          {reloadMsg}
        </div>
      )}

      {/* ── Framework tiles ── */}
      {summary && (
        <div className="grid gap-4 mb-6" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
          {FRAMEWORK_ORDER.map((fw) => (
            <FrameworkTile
              key={fw}
              framework={fw}
              counts={byFramework[fw] ?? { full: 0, partial: 0, supporting: 0, total: 0 }}
              active={framework === fw}
              onClick={() => { setFramework(framework === fw ? '' : fw); setDrawer(null) }}
            />
          ))}
        </div>
      )}

      {/* ── Framework filter tabs ── */}
      <div className="flex gap-1 mb-4 flex-wrap">
        {FRAMEWORK_TABS.map((tab) => {
          const active = framework === tab.key
          const fw = FRAMEWORK_META[tab.key]
          const count = tab.key ? (byFramework[tab.key]?.total ?? 0) : (summary?.total ?? 0)
          return (
            <button
              key={tab.key}
              onClick={() => { setFramework(tab.key); setDrawer(null) }}
              className="px-4 py-2 rounded text-sm font-medium transition-colors"
              style={{
                background: active ? (fw?.bg ?? 'rgba(255,196,13,0.1)') : 'var(--surface)',
                border: `1px solid ${active ? (fw?.border ?? 'rgba(255,196,13,0.4)') : 'var(--border)'}`,
                color: active ? (fw?.color ?? 'var(--amber)') : 'var(--muted)',
                cursor: 'pointer',
              }}
            >
              {tab.label}
              <span className="ml-2 font-mono text-xs opacity-70">{count}</span>
            </button>
          )
        })}
      </div>

      {/* ── Controls table ── */}
      {loading ? (
        <Spinner />
      ) : error ? (
        <div className="py-10 text-center" style={{ color: 'var(--red)', fontSize: 14 }}>{error}</div>
      ) : controls.length === 0 ? (
        <div className="py-10 text-center" style={{ color: 'var(--muted)', fontSize: 14 }}>No controls found.</div>
      ) : (
        <div className="rounded overflow-hidden" style={{ border: '1px solid var(--border)' }}>
          <table className="w-full border-collapse" style={{ fontSize: 13 }}>
            <thead>
              <tr style={{ background: 'var(--surface)', borderBottom: '2px solid var(--border)' }}>
                <th className="pl-4 pr-2 py-2.5" style={{ width: 20 }} />
                <th className="px-2 py-2.5 text-left mono-label" style={{ width: 120 }}>Control ID</th>
                <th className="px-3 py-2.5 text-left mono-label">Name</th>
                <th className="px-3 py-2.5 text-left mono-label" style={{ width: 110 }}>Status</th>
                <th className="px-3 py-2.5 text-left mono-label">Evidence Preview</th>
                <th className="px-4 py-2.5" style={{ width: 28 }} />
              </tr>
            </thead>
            <tbody>
              {orderedFrameworks.map((fw) => (
                <FrameworkSectionRows
                  key={fw}
                  framework={fw}
                  controls={grouped[fw]}
                  counts={byFramework[fw]}
                  onOpen={setDrawer}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Legend ── */}
      <div className="mt-6 flex flex-wrap gap-x-6 gap-y-1" style={{ fontSize: 11, color: 'var(--muted)' }}>
        <span><span style={{ color: 'var(--green)', fontWeight: 700 }}>■ Full</span> — all thresholds met</span>
        <span><span style={{ color: 'var(--amber)', fontWeight: 700 }}>■ Partial</span> — evidence present, gaps remain</span>
        <span><span style={{ color: '#818cf8', fontWeight: 700 }}>■ Supporting</span> — organisational control, VRA provides evidence</span>
        <span style={{ marginLeft: 'auto' }}>
          <span style={{ color: 'var(--green)' }}>● </span>at target
          <span style={{ color: 'var(--amber)', marginLeft: 8 }}>● </span>below target
          <span style={{ color: 'var(--red)', marginLeft: 8 }}>● </span>missing
        </span>
      </div>

      {/* ── Drawer ── */}
      {drawer && <ControlDrawer ctrl={drawer} onClose={() => setDrawer(null)} />}
    </div>
  )
}

// Extracted so it can call setDrawer without prop-drilling through ControlRowWrapper
function FrameworkSectionRows({ framework, controls, counts, onOpen }) {
  const m = FRAMEWORK_META[framework]

  return (
    <>
      {/* Section header */}
      <tr>
        <td
          colSpan={6}
          className="px-4 py-2"
          style={{ borderBottom: '1px solid var(--border)', background: m.bg + 'cc' }}
        >
          <div className="flex items-center gap-3 flex-wrap">
            <span style={{
              fontFamily: '"IBM Plex Mono", monospace', fontWeight: 800,
              fontSize: 11, color: m.color, letterSpacing: '0.05em',
            }}>
              {m.label}
            </span>
            <div style={{ width: 72 }}>
              <CoverageBar
                full={counts?.full ?? 0} partial={counts?.partial ?? 0}
                supporting={counts?.supporting ?? 0} total={counts?.total ?? 1}
                height={4}
              />
            </div>
            <span
              className="font-mono rounded px-2 py-0.5 text-xs font-bold"
              style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}
            >
              {counts?.full ?? 0}/{counts?.total ?? 0} full
            </span>
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>
              {counts?.partial ?? 0} partial · {counts?.supporting ?? 0} supporting
            </span>
          </div>
        </td>
      </tr>

      {controls.map((ctrl) => (
        <ControlRow key={ctrl.control_id} ctrl={ctrl} onOpen={onOpen} />
      ))}
    </>
  )
}
