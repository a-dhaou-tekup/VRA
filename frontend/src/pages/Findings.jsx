import { useEffect, useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchFindings, triggerAutoTriage } from '../api/client'
import { useSortable, SortTh } from '../utils/sortable'

// ── Triage pill styling ───────────────────────────────────────────────────────

const TRIAGE_STYLE = {
  likely_valid:         { bg: 'rgba(224,82,82,0.12)',   color: '#e05252', border: 'rgba(224,82,82,0.3)',   label: 'Valid' },
  needs_investigation:  { bg: 'rgba(78,143,175,0.12)',  color: '#4e8faf', border: 'rgba(78,143,175,0.3)',  label: 'Investigate' },
  likely_false_positive:{ bg: 'rgba(122,125,156,0.10)', color: '#7a7d9c', border: 'rgba(122,125,156,0.25)',label: 'False Positive' },
}

function TriagePill({ triageClass, confidence, justification }) {
  const [showTip, setShowTip] = useState(false)
  const ref = useRef(null)

  if (!triageClass) {
    return (
      <span style={{
        fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
        color: 'var(--muted)', padding: '2px 6px',
      }}>
        —
      </span>
    )
  }

  const s = TRIAGE_STYLE[triageClass] ?? TRIAGE_STYLE.needs_investigation
  const pct = confidence != null ? `${Math.round(confidence * 100)}%` : ''

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setShowTip(v => !v)}
        title={justification || ''}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          padding: '2px 8px', borderRadius: 6,
          background: s.bg, color: s.color, border: `1px solid ${s.border}`,
          fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
          fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em',
          cursor: justification ? 'pointer' : 'default',
          whiteSpace: 'nowrap',
        }}
      >
        {s.label}
        {pct && (
          <span style={{ fontSize: 9, opacity: 0.75 }}>{pct}</span>
        )}
      </button>

      {showTip && justification && (
        <div
          style={{
            position: 'absolute', bottom: 'calc(100% + 6px)', left: 0,
            zIndex: 50, width: 280,
            padding: '8px 12px', borderRadius: 8,
            background: 'var(--surface-2)', border: `1px solid ${s.border}`,
            color: 'var(--text)', fontSize: 12, lineHeight: 1.55,
            boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
          }}
          onClick={e => e.stopPropagation()}
        >
          <div style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
            color: s.color, letterSpacing: '0.1em', textTransform: 'uppercase',
            marginBottom: 4,
          }}>
            AI Justification
          </div>
          {justification}
          <button
            onClick={() => setShowTip(false)}
            style={{
              display: 'block', marginTop: 6,
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
              color: 'var(--muted)', background: 'none', border: 'none',
              cursor: 'pointer', padding: 0,
            }}
          >
            ✕ close
          </button>
        </div>
      )}
    </div>
  )
}

// ── Severity badge ────────────────────────────────────────────────────────────

const SEV_STYLE = {
  CRITICAL: { color: '#e05252', bg: 'rgba(224,82,82,0.1)', border: 'rgba(224,82,82,0.25)' },
  HIGH:     { color: '#f5a623', bg: 'rgba(245,166,35,0.1)', border: 'rgba(245,166,35,0.25)' },
  MEDIUM:   { color: '#4e8faf', bg: 'rgba(78,143,175,0.1)', border: 'rgba(78,143,175,0.25)' },
  LOW:      { color: '#4eaf7c', bg: 'rgba(78,175,124,0.1)', border: 'rgba(78,175,124,0.25)' },
  INFO:     { color: '#7a7d9c', bg: 'rgba(122,125,156,0.08)', border: 'rgba(122,125,156,0.2)' },
}

function SevBadge({ severity }) {
  const s = SEV_STYLE[severity?.toUpperCase()] ?? SEV_STYLE.INFO
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 7px', borderRadius: 5,
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
      fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
      fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em',
    }}>
      {severity || '—'}
    </span>
  )
}

// ── Spinner ───────────────────────────────────────────────────────────────────

function Spinner() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}>
      <div style={{
        width: 28, height: 28, borderRadius: '50%',
        border: '2px solid var(--border)', borderTopColor: 'var(--amber)',
        animation: 'spin 0.8s linear infinite',
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const SORT_OPTIONS = [
  { value: 'default',    label: 'Default (newest first)' },
  { value: 'ai_valid',   label: 'AI: High-confidence valid first' },
  { value: 'ai_fp',      label: 'AI: Likely false positive first' },
  { value: 'confidence', label: 'Confidence (high → low)' },
]

export default function Findings() {
  const navigate = useNavigate()
  const [findings,     setFindings]    = useState([])
  const [total,        setTotal]       = useState(0)
  const [loading,      setLoading]     = useState(true)
  const [error,        setError]       = useState(null)
  const [sort,         setSort]        = useState('ai_valid')
  const [fpThreshold,  setFpThreshold] = useState(null)  // null = filter off
  const [running,      setRunning]     = useState({})    // findingId → bool

  const { sorted: colSorted, col: sortCol, dir: sortDir, toggle: toggleSort } =
    useSortable(findings, 'created_at', 'desc')

  const load = useCallback(() => {
    setLoading(true)
    fetchFindings({ limit: 200, offset: 0 })
      .then(r => {
        setFindings(r.data?.data ?? [])
        setTotal(r.data?.total ?? 0)
      })
      .catch(e => setError(e.message || 'Failed to load findings'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const handleRunTriage = async (findingId) => {
    setRunning(prev => ({ ...prev, [findingId]: true }))
    try {
      await triggerAutoTriage(findingId)
      load()
    } catch (e) {
      alert(`Triage failed: ${e.response?.data?.detail || e.message}`)
    } finally {
      setRunning(prev => ({ ...prev, [findingId]: false }))
    }
  }

  // AI-level sort (on top of column sort)
  const sorted = [...colSorted].sort((a, b) => {
    if (sort === 'ai_valid') {
      const av = a.triage_class === 'likely_valid' ? (a.confidence ?? 0) : -1
      const bv = b.triage_class === 'likely_valid' ? (b.confidence ?? 0) : -1
      return bv - av
    }
    if (sort === 'ai_fp') {
      const af = a.triage_class === 'likely_false_positive' ? (a.confidence ?? 0) : -1
      const bf = b.triage_class === 'likely_false_positive' ? (b.confidence ?? 0) : -1
      return bf - af
    }
    if (sort === 'confidence') {
      return (b.confidence ?? -1) - (a.confidence ?? -1)
    }
    return 0  // default: API order (newest first)
  })

  // Filter — hide likely_false_positive below threshold
  const visible = fpThreshold != null
    ? sorted.filter(f => !(f.triage_class === 'likely_false_positive' && (f.confidence ?? 0) < fpThreshold))
    : sorted

  const hiddenCount = sorted.length - visible.length

  const selectStyle = {
    background: 'var(--surface-2)', border: '1px solid var(--border)',
    color: 'var(--text)', borderRadius: 6, padding: '6px 10px',
    fontSize: 12, fontFamily: '"IBM Plex Mono", monospace', cursor: 'pointer',
  }

  return (
    <div style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1 className="page-title">Findings</h1>
          <p style={{ marginTop: 4, fontSize: 13, color: 'var(--muted)' }}>
            Individual CVE–host pairs with AI triage suggestions
          </p>
        </div>
        <button className="btn-ghost text-xs" onClick={load} style={{ fontSize: 11 }}>
          Refresh
        </button>
      </div>

      {/* Controls bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap',
        padding: '12px 16px', borderRadius: 10,
        background: 'var(--surface)', border: '1px solid var(--border)',
      }}>
        {/* Sort */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="mono-label">Sort</span>
          <select style={selectStyle} value={sort} onChange={e => setSort(e.target.value)}>
            {SORT_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>

        <div style={{ width: 1, height: 24, background: 'var(--border)' }} />

        {/* Filter slider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="mono-label">Hide false positives below</span>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={fpThreshold != null}
              onChange={e => setFpThreshold(e.target.checked ? 0.75 : null)}
              style={{ accentColor: 'var(--amber)', cursor: 'pointer' }}
            />
            <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--muted)' }}>
              Enable
            </span>
          </label>
          {fpThreshold != null && (
            <>
              <input
                type="range" min="0.5" max="1.0" step="0.05"
                value={fpThreshold}
                onChange={e => setFpThreshold(parseFloat(e.target.value))}
                style={{ width: 100, accentColor: 'var(--amber)', cursor: 'pointer' }}
              />
              <span style={{
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--amber)',
                minWidth: 32,
              }}>
                {Math.round(fpThreshold * 100)}%
              </span>
            </>
          )}
          {hiddenCount > 0 && (
            <span style={{
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
              color: 'var(--muted)', padding: '2px 8px',
              background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 5,
            }}>
              {hiddenCount} hidden
            </span>
          )}
        </div>

        <div style={{ marginLeft: 'auto', fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
          {visible.length} / {total} findings
        </div>
      </div>

      {/* Table */}
      {loading ? <Spinner /> : error ? (
        <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
          <p style={{ color: 'var(--red)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 13 }}>
            ⚠ {error}
          </p>
        </div>
      ) : visible.length === 0 ? (
        <div className="vra-card" style={{ textAlign: 'center', padding: '48px 0' }}>
          <div style={{ fontSize: 28, marginBottom: 8 }}>🔍</div>
          <p style={{ color: 'var(--muted)', fontSize: 13 }}>
            No findings yet — upload a scan file to populate this list.
          </p>
        </div>
      ) : (
        <div className="vra-card" style={{ padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {[
                  { col: 'cve_id',       label: 'CVE ID'       },
                  { col: 'hostname',     label: 'Host'         },
                  { col: 'component',    label: 'Component'    },
                  { col: 'severity',     label: 'Severity'     },
                  { col: 'triage_class', label: 'AI Suggestion'},
                  { col: 'ingest_method',label: 'Method'       },
                  { col: 'state',        label: 'State'        },
                  { col: null,           label: ''             },
                ].map(({ col: c, label }) =>
                  c ? (
                    <SortTh key={c} col={c} sortCol={sortCol} sortDir={sortDir} onSort={toggleSort}
                      style={{ padding: '10px 16px', fontFamily: '"IBM Plex Mono", monospace',
                               fontSize: 9, letterSpacing: '0.12em', color: sortCol === c ? 'var(--amber)' : 'var(--muted)',
                               fontWeight: 500 }}>
                      {label}
                    </SortTh>
                  ) : (
                    <th key="actions" style={{ padding: '10px 16px', width: 90 }} />
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {visible.map((f, i) => (
                <tr
                  key={f.id}
                  style={{
                    borderBottom: i < visible.length - 1 ? '1px solid var(--border)' : 'none',
                    transition: 'background 0.1s',
                  }}
                  onClick={() => navigate(`/findings/${f.id}`)}
                  style={{ cursor: 'pointer', borderBottom: i < visible.length - 1 ? '1px solid var(--border)' : 'none', transition: 'background 0.1s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  {/* CVE ID */}
                  <td style={{
                    padding: '10px 16px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                    color: 'var(--amber)', whiteSpace: 'nowrap',
                  }}>
                    {f.cve_id || '—'}
                  </td>

                  {/* Host */}
                  <td style={{
                    padding: '10px 16px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                    color: 'var(--text)', maxWidth: 160,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {f.hostname || '—'}
                  </td>

                  {/* Component */}
                  <td style={{
                    padding: '10px 16px', fontSize: 12, color: 'var(--muted)',
                    maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {f.component || '—'}
                  </td>

                  {/* Severity */}
                  <td style={{ padding: '10px 16px' }}>
                    <SevBadge severity={f.severity} />
                  </td>

                  {/* AI Suggestion */}
                  <td style={{ padding: '10px 16px' }}>
                    <TriagePill
                      triageClass={f.triage_class}
                      confidence={f.confidence}
                      justification={f.justification}
                    />
                  </td>

                  {/* Ingest method */}
                  <td style={{
                    padding: '10px 16px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                    color: f.ingest_method === 'llm' ? 'var(--amber)' : 'var(--muted)',
                  }}>
                    {f.ingest_method || '—'}
                  </td>

                  {/* State */}
                  <td style={{
                    padding: '10px 16px',
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                    color: 'var(--muted)',
                  }}>
                    {f.state || 'NEW'}
                  </td>

                  {/* Run triage button */}
                  <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                    <button
                      onClick={() => handleRunTriage(f.id)}
                      disabled={running[f.id]}
                      style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        padding: '3px 10px', borderRadius: 6,
                        background: 'transparent',
                        border: '1px solid var(--border)',
                        color: 'var(--muted)',
                        fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                        cursor: running[f.id] ? 'not-allowed' : 'pointer',
                        opacity: running[f.id] ? 0.5 : 1,
                        transition: 'border-color 0.15s, color 0.15s',
                        whiteSpace: 'nowrap',
                      }}
                      onMouseEnter={e => {
                        if (!running[f.id]) {
                          e.currentTarget.style.borderColor = 'var(--amber)'
                          e.currentTarget.style.color = 'var(--amber)'
                        }
                      }}
                      onMouseLeave={e => {
                        e.currentTarget.style.borderColor = 'var(--border)'
                        e.currentTarget.style.color = 'var(--muted)'
                      }}
                    >
                      {running[f.id] ? '⏳ Running…' : '✨ Triage'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
