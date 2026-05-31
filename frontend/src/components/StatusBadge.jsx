const S = {
  base: 'inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase tracking-wider',
  font: 'font-family: "IBM Plex Mono", monospace',
}

const STATUS_MAP = {
  TO_DO:               { bg: 'rgba(122,125,156,0.1)',  color: '#7a7d9c', border: 'rgba(122,125,156,0.25)', label: 'To Do' },
  TRIAGED:             { bg: 'rgba(78,143,175,0.1)',   color: '#4e8faf', border: 'rgba(78,143,175,0.28)', label: 'Triaged' },
  PATCHABLE:           { bg: 'rgba(78,143,175,0.1)',   color: '#4e8faf', border: 'rgba(78,143,175,0.28)', label: 'Patchable' },
  WORKAROUND_AVAILABLE:{ bg: 'rgba(155,109,255,0.1)', color: '#9b6dff', border: 'rgba(155,109,255,0.28)', label: 'Workaround' },
  NO_FIX:              { bg: 'rgba(224,82,82,0.1)',    color: '#e05252', border: 'rgba(224,82,82,0.25)', label: 'No Fix' },
  IN_PROGRESS:         { bg: 'rgba(78,143,175,0.12)',  color: '#4e8faf', border: 'rgba(78,143,175,0.3)', label: 'In Progress' },
  PATCHED:             { bg: 'rgba(78,175,124,0.1)',   color: '#4eaf7c', border: 'rgba(78,175,124,0.28)', label: 'Patched' },
  MITIGATED:           { bg: 'rgba(78,175,124,0.1)',   color: '#4eaf7c', border: 'rgba(78,175,124,0.28)', label: 'Mitigated' },
  VERIFIED:            { bg: 'rgba(78,175,124,0.12)',  color: '#4eaf7c', border: 'rgba(78,175,124,0.3)', label: 'Verified' },
  DONE:                { bg: 'rgba(78,175,124,0.12)',  color: '#4eaf7c', border: 'rgba(78,175,124,0.3)', label: 'Done' },
  CLOSED:              { bg: 'rgba(122,125,156,0.07)', color: '#555770', border: 'rgba(122,125,156,0.15)', label: 'Closed' },
  RESURFACED:          { bg: 'rgba(224,82,82,0.12)',   color: '#e05252', border: 'rgba(224,82,82,0.3)', label: 'Resurfaced' },
  CONFIRMED:           { bg: 'rgba(224,82,82,0.1)',    color: '#e05252', border: 'rgba(224,82,82,0.25)', label: 'Confirmed' },
  FALSE_POSITIVE:      { bg: 'rgba(155,109,255,0.12)', color: '#9b6dff', border: 'rgba(155,109,255,0.3)', label: 'False Positive' },
  RISK_ACCEPTED:       { bg: 'rgba(245,166,35,0.1)',   color: '#f5a623', border: 'rgba(245,166,35,0.25)', label: 'Risk Accepted' },
  DEFERRED:            { bg: 'rgba(122,125,156,0.08)', color: '#6b6e88', border: 'rgba(122,125,156,0.18)', label: 'Deferred' },
}

const FALLBACK = { bg: 'rgba(122,125,156,0.08)', color: '#7a7d9c', border: 'rgba(122,125,156,0.2)' }

export default function StatusBadge({ status }) {
  if (!status) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px', borderRadius: 6,
      background: FALLBACK.bg, color: FALLBACK.color,
      border: `1px solid ${FALLBACK.border}`,
      fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
      fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em',
    }}>—</span>
  )

  const key = status.toString().toUpperCase()
  const s   = STATUS_MAP[key] ?? { ...FALLBACK, label: status }

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px', borderRadius: 6,
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}`,
      fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
      fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em',
      whiteSpace: 'nowrap',
    }}>
      {s.label ?? key.replace(/_/g, ' ')}
    </span>
  )
}
