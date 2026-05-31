import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { fetchAutoTriage, fetchBlastRadius, fetchSimilarFindings } from '../api/client'

// ── Node kind → colour + radius ───────────────────────────────────────────────

const KIND_CONFIG = {
  cve:       { color: '#e05252', r: 7,  label: 'CVE' },
  component: { color: '#7a7d9c', r: 5,  label: 'Component' },
  asset:     { color: '#f5a623', r: 10, label: 'Asset' },
  owner:     { color: '#4eaf7c', r: 12, label: 'Owner' },
  service:   { color: '#9b6dff', r: 12, label: 'Service' },
}
const DEFAULT_KIND = { color: '#4e8faf', r: 6, label: 'Node' }

function kindCfg(kind) { return KIND_CONFIG[kind] ?? DEFAULT_KIND }

// ── Legend ────────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div style={{
      position: 'absolute', top: 12, left: 12, zIndex: 10,
      background: 'rgba(11,13,23,0.88)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '10px 14px',
      display: 'flex', flexDirection: 'column', gap: 5,
    }}>
      <div className="mono-label" style={{ marginBottom: 4 }}>Node types</div>
      {Object.entries(KIND_CONFIG).map(([kind, cfg]) => (
        <div key={kind} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: cfg.r * 1.6, height: cfg.r * 1.6, borderRadius: '50%',
            background: cfg.color, flexShrink: 0, display: 'inline-block',
          }} />
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
            {cfg.label}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── Node side panel ───────────────────────────────────────────────────────────

function NodePanel({ node, onClose }) {
  if (!node) return null
  const cfg = kindCfg(node.kind)
  const fields = Object.entries(node).filter(
    ([k]) => !['id', '__indexColor', '__threeObj', 'x', 'y', 'vx', 'vy', 'index', 'fx', 'fy'].includes(k)
  )
  return (
    <div style={{
      position: 'absolute', top: 12, right: 12, zIndex: 10, width: 260,
      background: 'var(--surface)', border: `1px solid ${cfg.color}44`,
      borderRadius: 10, padding: '14px 16px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 10, height: 10, borderRadius: '50%',
            background: cfg.color, display: 'inline-block',
          }} />
          <span style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
            color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.1em',
          }}>
            {cfg.label}
          </span>
        </div>
        <button onClick={onClose} style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--muted)', fontSize: 14,
        }}>✕</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {fields.map(([k, v]) => (
          <div key={k} style={{ display: 'flex', gap: 8, fontSize: 11 }}>
            <span style={{ color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace', minWidth: 80, flexShrink: 0 }}>
              {k}
            </span>
            <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
              {String(v ?? '—')}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Triage pill ───────────────────────────────────────────────────────────────

const TRIAGE_STYLE = {
  likely_valid:         { color: '#e05252', label: 'Likely valid' },
  needs_investigation:  { color: '#4e8faf', label: 'Needs investigation' },
  likely_false_positive:{ color: '#7a7d9c', label: 'Likely false positive' },
}

function TriagePill({ t }) {
  if (!t) return <span style={{ color: 'var(--muted)', fontSize: 12 }}>No AI triage yet</span>
  const s = TRIAGE_STYLE[t.triage_class] ?? { color: '#888', label: t.triage_class }
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
      <span style={{
        padding: '2px 10px', borderRadius: 6,
        background: s.color + '18', color: s.color, border: `1px solid ${s.color}44`,
        fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
        fontWeight: 600, textTransform: 'uppercase',
      }}>
        {s.label}
      </span>
      <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--muted)' }}>
        {Math.round((t.confidence ?? 0) * 100)}% confidence
      </span>
      {t.justification && (
        <span style={{ fontSize: 12, color: 'var(--text)', flex: '1 1 100%', marginTop: 2 }}>
          {t.justification}
        </span>
      )}
    </div>
  )
}

// ── Blast radius graph tab ────────────────────────────────────────────────────

function BlastRadiusTab({ findingId }) {
  const [graphData, setGraphData] = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [depth,     setDepth]     = useState(2)
  const [selected,  setSelected]  = useState(null)
  const [ForceGraph, setForceGraph] = useState(null)
  const graphRef = useRef(null)

  // Lazy-load react-force-graph-2d to avoid SSR issues
  useEffect(() => {
    import('react-force-graph-2d').then(m => setForceGraph(() => m.default)).catch(() => {})
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    setSelected(null)
    fetchBlastRadius(findingId, depth)
      .then(r => {
        const d = r.data?.data ?? r.data
        // Transform to react-force-graph format
        setGraphData({
          nodes: d.nodes.map(n => ({
            ...n,
            color: kindCfg(n.kind).color,
            val:   kindCfg(n.kind).r,
          })),
          links: d.edges.map(e => ({
            source: e.source,
            target: e.target,
            kind:   e.kind,
          })),
        })
      })
      .catch(e => setError(e.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }, [findingId, depth])

  useEffect(() => { load() }, [load])

  const containerStyle = {
    position: 'relative', width: '100%', height: 520,
    background: 'var(--black)', borderRadius: 10,
    border: '1px solid var(--border)', overflow: 'hidden',
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span className="mono-label">Depth</span>
        {[1, 2, 3].map(d => (
          <button
            key={d}
            onClick={() => setDepth(d)}
            style={{
              padding: '3px 10px', borderRadius: 6,
              background: depth === d ? 'var(--amber)' : 'var(--surface-2)',
              color: depth === d ? '#000' : 'var(--muted)',
              border: `1px solid ${depth === d ? 'var(--amber)' : 'var(--border)'}`,
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
              cursor: 'pointer',
            }}
          >
            {d}
          </button>
        ))}
        <button onClick={load} style={{
          marginLeft: 'auto', padding: '3px 10px', borderRadius: 6,
          background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace',
          fontSize: 11, cursor: 'pointer',
        }}>
          ↺ Refresh
        </button>
      </div>

      {/* Graph canvas */}
      <div style={containerStyle}>
        {loading && (
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--muted)', fontSize: 13,
          }}>
            Building graph…
          </div>
        )}
        {error && !loading && (
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--red)', fontSize: 13, padding: 24, textAlign: 'center',
          }}>
            ⚠ {error}
          </div>
        )}
        {!loading && !error && graphData && ForceGraph && (
          <>
            <Legend />
            <NodePanel node={selected} onClose={() => setSelected(null)} />
            <ForceGraph
              ref={graphRef}
              width={graphRef.current?.offsetWidth || 800}
              height={520}
              graphData={graphData}
              nodeColor={n => n.color}
              nodeVal={n => n.val}
              nodeLabel={n => `${n.kind}: ${n.label || n.id}`}
              linkColor={() => 'rgba(255,255,255,0.12)'}
              linkDirectionalArrowLength={4}
              linkDirectionalArrowRelPos={1}
              backgroundColor="transparent"
              onNodeClick={node => setSelected({ ...node })}
              nodeCanvasObjectMode={() => 'after'}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = (node.label || node.id || '').toString().slice(0, 20)
                const fontSize = Math.max(9, 12 / globalScale)
                ctx.font = `${fontSize}px "IBM Plex Mono",monospace`
                ctx.fillStyle = 'rgba(226,224,237,0.7)'
                ctx.textAlign = 'center'
                ctx.fillText(label, node.x, node.y + (node.val || 6) + fontSize + 1)
              }}
            />
          </>
        )}
        {!loading && !error && graphData && !ForceGraph && (
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--muted)', fontSize: 13,
          }}>
            Loading visualisation…
          </div>
        )}
      </div>

      {graphData && (
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
          {graphData.nodes.length} nodes · {graphData.links.length} edges
        </div>
      )}
    </div>
  )
}

// ── Similar findings section ──────────────────────────────────────────────────

function SimilarFindings({ findingId }) {
  const [similar, setSimilar]  = useState([])
  const [loading, setLoading]  = useState(true)

  useEffect(() => {
    fetchSimilarFindings(findingId, 5)
      .then(r => setSimilar(r.data?.data ?? []))
      .catch(() => setSimilar([]))
      .finally(() => setLoading(false))
  }, [findingId])

  if (loading) return <div style={{ color: 'var(--muted)', fontSize: 12 }}>Loading…</div>
  if (!similar.length) return (
    <div style={{ color: 'var(--muted)', fontSize: 12 }}>No similar findings found.</div>
  )

  const TRIAGE_COLOR = { likely_valid: '#e05252', needs_investigation: '#4e8faf', likely_false_positive: '#7a7d9c' }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {similar.map((s, i) => (
        <Link
          key={s.finding_id}
          to={`/findings/${s.finding_id}`}
          style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '9px 14px', borderRadius: 8,
            background: 'var(--surface-2)', border: '1px solid var(--border)',
            textDecoration: 'none',
            transition: 'border-color 0.15s',
          }}
          onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--amber)')}
          onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
        >
          <span style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
            color: 'var(--muted)', minWidth: 16,
          }}>#{i + 1}</span>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--amber)' }}>
              {s.cve_id || '—'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 1 }}>
              {s.hostname} · {s.component}
            </div>
          </div>

          {/* Score bar */}
          <div style={{ textAlign: 'right', flexShrink: 0 }}>
            <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: 'var(--text)' }}>
              {Math.round(s.score * 100)}%
            </div>
            <div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace' }}>
              e:{Math.round((s.breakdown?.embed ?? 0) * 100)}
              {' '}g:{Math.round((s.breakdown?.graph ?? 0) * 100)}
            </div>
          </div>
        </Link>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FindingDetail() {
  const { id } = useParams()
  const [triage,  setTriage]  = useState(null)
  const [tab,     setTab]     = useState('blast')   // 'blast'

  useEffect(() => {
    fetchAutoTriage(id).then(r => setTriage(r.data?.data ?? null)).catch(() => {})
  }, [id])

  const tabStyle = (active) => ({
    padding: '6px 16px', borderRadius: '6px 6px 0 0',
    background: active ? 'var(--surface)' : 'transparent',
    border: active ? '1px solid var(--border)' : '1px solid transparent',
    borderBottom: active ? '1px solid var(--surface)' : '1px solid var(--border)',
    color: active ? 'var(--amber)' : 'var(--muted)',
    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
    cursor: 'pointer', marginBottom: -1,
    textTransform: 'uppercase', letterSpacing: '0.08em',
  })

  return (
    <div style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--muted)' }}>
        <Link to="/findings" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Findings</Link>
        <span>/</span>
        <span style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)', fontSize: 11 }}>
          {id}
        </span>
      </div>

      <h1 className="page-title">Finding Detail</h1>

      {/* AI triage summary */}
      {triage && (
        <div style={{
          padding: '14px 18px', borderRadius: 10,
          background: 'var(--surface)', border: '1px solid var(--border)',
        }}>
          <div className="mono-label" style={{ marginBottom: 8 }}>AI Triage Suggestion</div>
          <TriagePill t={triage} />
        </div>
      )}

      {/* Similar findings */}
      <div style={{
        padding: '14px 18px', borderRadius: 10,
        background: 'var(--surface)', border: '1px solid var(--border)',
      }}>
        <div className="mono-label" style={{ marginBottom: 12 }}>Similar Findings (top 5)</div>
        <SimilarFindings findingId={id} />
      </div>

      {/* Tabs */}
      <div>
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 0 }}>
          <button style={tabStyle(tab === 'blast')} onClick={() => setTab('blast')}>
            Blast Radius
          </button>
        </div>
        <div style={{
          padding: '20px 0',
          background: 'var(--surface)', borderRadius: '0 8px 8px 8px',
          border: '1px solid var(--border)', borderTop: 'none',
          padding: '20px',
        }}>
          {tab === 'blast' && <BlastRadiusTab findingId={id} />}
        </div>
      </div>
    </div>
  )
}
