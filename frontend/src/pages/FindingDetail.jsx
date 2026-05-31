import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { fetchAutoTriage, fetchBlastRadius, fetchSimilarFindings } from '../api/client'

// ── Node kind → colour + radius ───────────────────────────────────────────────

const KIND_CONFIG = {
  cve:       { color: '#e05252', r: 8,  label: 'CVE' },
  component: { color: '#7a7d9c', r: 6,  label: 'Component' },
  asset:     { color: '#f5a623', r: 12, label: 'Asset' },
  owner:     { color: '#4eaf7c', r: 14, label: 'Owner' },
  service:   { color: '#9b6dff', r: 14, label: 'Service' },
}
const DEFAULT_KIND = { color: '#4e8faf', r: 7, label: 'Node' }
function kindCfg(kind) { return KIND_CONFIG[kind] ?? DEFAULT_KIND }

// ── Legend ────────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div style={{
      position: 'absolute', top: 12, left: 12, zIndex: 10,
      background: 'rgba(11,13,23,0.88)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '10px 14px',
      display: 'flex', flexDirection: 'column', gap: 5, pointerEvents: 'none',
    }}>
      <div className="mono-label" style={{ marginBottom: 4 }}>Node types</div>
      {Object.entries(KIND_CONFIG).map(([kind, cfg]) => (
        <div key={kind} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: cfg.r * 1.4, height: cfg.r * 1.4, borderRadius: '50%',
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
  const skip = new Set(['x', 'y', 'vx', 'vy', 'fx', 'fy'])
  return (
    <div style={{
      position: 'absolute', top: 12, right: 12, zIndex: 10, width: 240,
      background: 'var(--surface)', border: `1px solid ${cfg.color}55`,
      borderRadius: 10, padding: '14px 16px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.55)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span style={{ width: 9, height: 9, borderRadius: '50%', background: cfg.color, display: 'inline-block' }} />
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            {cfg.label}
          </span>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--muted)', fontSize: 14 }}>✕</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {Object.entries(node).filter(([k]) => !skip.has(k)).map(([k, v]) => (
          <div key={k} style={{ display: 'flex', gap: 8, fontSize: 11 }}>
            <span style={{ color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace', minWidth: 72, flexShrink: 0 }}>{k}</span>
            <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{String(v ?? '—')}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Canvas force-directed graph ───────────────────────────────────────────────

/**
 * Pure-Canvas force simulation. No external dependencies.
 * Algorithm: repulsion (Coulomb) + spring attraction (edges) + center gravity + damping.
 */
function useForceGraph(canvasRef, graphData, onNodeClick) {
  const simRef = useRef(null)
  const rafRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !graphData) return

    const W = canvas.width  = canvas.offsetWidth
    const H = canvas.height = canvas.offsetHeight
    const ctx = canvas.getContext('2d')
    const dpr = window.devicePixelRatio || 1
    canvas.width  = W * dpr
    canvas.height = H * dpr
    ctx.scale(dpr, dpr)

    // Initialise node positions
    const nodes = graphData.nodes.map((n, i) => ({
      ...n,
      x: W / 2 + (Math.random() - 0.5) * W * 0.6,
      y: H / 2 + (Math.random() - 0.5) * H * 0.6,
      vx: 0,
      vy: 0,
    }))
    const nodeIndex = Object.fromEntries(nodes.map((n, i) => [n.id, i]))
    const links = graphData.links
      .map(e => ({ source: nodeIndex[e.source], target: nodeIndex[e.target], kind: e.kind }))
      .filter(e => e.source != null && e.target != null)

    simRef.current = nodes

    const REPULSION  = 2200
    const SPRING_LEN = 120
    const SPRING_K   = 0.04
    const GRAVITY    = 0.012
    const DAMPING    = 0.85
    const ALPHA      = { v: 1.0 }

    function tick() {
      const n = nodes.length
      // Repulsion
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const dx = nodes[j].x - nodes[i].x
          const dy = nodes[j].y - nodes[i].y
          const d2 = dx * dx + dy * dy + 1
          const f  = REPULSION / d2
          nodes[i].vx -= f * dx
          nodes[i].vy -= f * dy
          nodes[j].vx += f * dx
          nodes[j].vy += f * dy
        }
      }
      // Spring (edges)
      for (const l of links) {
        const a = nodes[l.source], b = nodes[l.target]
        const dx = b.x - a.x, dy = b.y - a.y
        const d  = Math.sqrt(dx * dx + dy * dy) || 1
        const f  = (d - SPRING_LEN) * SPRING_K
        const fx = f * dx / d, fy = f * dy / d
        a.vx += fx; a.vy += fy
        b.vx -= fx; b.vy -= fy
      }
      // Center gravity
      for (const nd of nodes) {
        nd.vx += (W / 2 - nd.x) * GRAVITY * ALPHA.v
        nd.vy += (H / 2 - nd.y) * GRAVITY * ALPHA.v
        nd.vx *= DAMPING; nd.vy *= DAMPING
        nd.x  += nd.vx;   nd.y  += nd.vy
        // Boundary clamp
        nd.x = Math.max(20, Math.min(W - 20, nd.x))
        nd.y = Math.max(20, Math.min(H - 20, nd.y))
      }
      ALPHA.v = Math.max(0.05, ALPHA.v * 0.995)
    }

    function draw() {
      ctx.clearRect(0, 0, W, H)

      // Edges
      for (const l of links) {
        const a = nodes[l.source], b = nodes[l.target]
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.strokeStyle = 'rgba(255,255,255,0.12)'
        ctx.lineWidth = 1
        ctx.stroke()

        // Arrowhead
        const dx = b.x - a.x, dy = b.y - a.y
        const d  = Math.sqrt(dx * dx + dy * dy) || 1
        const ux = dx / d, uy = dy / d
        const cfg = kindCfg(b.kind)
        const ex = b.x - ux * cfg.r, ey = b.y - uy * cfg.r
        ctx.beginPath()
        ctx.moveTo(ex, ey)
        ctx.lineTo(ex - ux * 8 + uy * 4, ey - uy * 8 - ux * 4)
        ctx.lineTo(ex - ux * 8 - uy * 4, ey - uy * 8 + ux * 4)
        ctx.fillStyle = 'rgba(255,255,255,0.18)'
        ctx.fill()
      }

      // Nodes
      for (const nd of nodes) {
        const { color, r } = kindCfg(nd.kind)
        ctx.beginPath()
        ctx.arc(nd.x, nd.y, r, 0, Math.PI * 2)
        ctx.fillStyle = color + 'cc'
        ctx.fill()
        ctx.strokeStyle = color
        ctx.lineWidth = 1.5
        ctx.stroke()

        // Label
        const label = (nd.label || nd.id || '').toString()
        const maxLen = 18
        const display = label.length > maxLen ? label.slice(0, maxLen) + '…' : label
        ctx.font = '9px "IBM Plex Mono",monospace'
        ctx.fillStyle = 'rgba(226,224,237,0.75)'
        ctx.textAlign = 'center'
        ctx.fillText(display, nd.x, nd.y + r + 11)
      }
    }

    function loop() {
      tick()
      draw()
      rafRef.current = requestAnimationFrame(loop)
    }
    rafRef.current = requestAnimationFrame(loop)

    // Click handler
    function handleClick(e) {
      const rect = canvas.getBoundingClientRect()
      const mx = (e.clientX - rect.left)
      const my = (e.clientY - rect.top)
      for (const nd of nodes) {
        const { r } = kindCfg(nd.kind)
        const dx = nd.x - mx, dy = nd.y - my
        if (dx * dx + dy * dy <= (r + 4) ** 2) {
          onNodeClick && onNodeClick(nd)
          return
        }
      }
      onNodeClick && onNodeClick(null)
    }
    canvas.addEventListener('click', handleClick)

    return () => {
      cancelAnimationFrame(rafRef.current)
      canvas.removeEventListener('click', handleClick)
    }
  }, [graphData])
}

// ── Blast Radius tab ──────────────────────────────────────────────────────────

function BlastRadiusTab({ findingId }) {
  const [graphData, setGraphData] = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [depth,     setDepth]     = useState(2)
  const [selected,  setSelected]  = useState(null)
  const canvasRef = useRef(null)

  useForceGraph(canvasRef, graphData, node => setSelected(node))

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    setSelected(null)
    setGraphData(null)
    fetchBlastRadius(findingId, depth)
      .then(r => {
        const d = r.data?.data ?? r.data
        setGraphData({
          nodes: d.nodes ?? [],
          links: (d.edges ?? []).map(e => ({ source: e.source, target: e.target, kind: e.kind })),
        })
      })
      .catch(e => setError(e.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }, [findingId, depth])

  useEffect(() => { load() }, [load])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Depth selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="mono-label">Depth</span>
        {[1, 2, 3].map(d => (
          <button key={d} onClick={() => setDepth(d)} style={{
            padding: '3px 12px', borderRadius: 6,
            background: depth === d ? 'var(--amber)' : 'var(--surface-2)',
            color: depth === d ? '#000' : 'var(--muted)',
            border: `1px solid ${depth === d ? 'var(--amber)' : 'var(--border)'}`,
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, cursor: 'pointer',
            transition: 'all 0.15s',
          }}>
            {d}
          </button>
        ))}
        <button onClick={load} style={{
          marginLeft: 'auto', padding: '3px 12px', borderRadius: 6,
          background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace',
          fontSize: 11, cursor: 'pointer',
        }}>
          ↺ Refresh
        </button>
      </div>

      {/* Canvas container */}
      <div style={{
        position: 'relative', width: '100%', height: 500,
        background: 'var(--black)', borderRadius: 10,
        border: '1px solid var(--border)', overflow: 'hidden',
      }}>
        {loading && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--muted)', fontSize: 13 }}>
            Building graph…
          </div>
        )}
        {error && !loading && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--red)', fontSize: 13, padding: 24, textAlign: 'center' }}>
            ⚠ {error}
          </div>
        )}
        {!loading && !error && graphData && graphData.nodes.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10, color: 'var(--muted)', fontSize: 13 }}>
            <div style={{ fontSize: 28 }}>🕸</div>
            No graph data for this finding yet.<br />
            <span style={{ fontSize: 11, fontFamily: '"IBM Plex Mono", monospace' }}>Upload a scan or run the seed script first.</span>
          </div>
        )}
        {!loading && !error && graphData && graphData.nodes.length > 0 && (
          <>
            <Legend />
            <NodePanel node={selected} onClose={() => setSelected(null)} />
            <canvas
              ref={canvasRef}
              style={{ width: '100%', height: '100%', display: 'block', cursor: 'pointer' }}
            />
          </>
        )}
      </div>

      {graphData && graphData.nodes.length > 0 && (
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)' }}>
          {graphData.nodes.length} nodes · {graphData.links.length} edges · click a node for details
        </div>
      )}
    </div>
  )
}

// ── Triage pill ───────────────────────────────────────────────────────────────

const TRIAGE_STYLE = {
  likely_valid:          { color: '#e05252', label: 'Likely valid' },
  needs_investigation:   { color: '#4e8faf', label: 'Needs investigation' },
  likely_false_positive: { color: '#7a7d9c', label: 'Likely false positive' },
}

function TriagePill({ t }) {
  if (!t) return <span style={{ color: 'var(--muted)', fontSize: 12 }}>No AI triage yet</span>
  const s = TRIAGE_STYLE[t.triage_class] ?? { color: '#888', label: t.triage_class }
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, flexWrap: 'wrap' }}>
      <span style={{
        padding: '2px 10px', borderRadius: 6, flexShrink: 0,
        background: s.color + '18', color: s.color, border: `1px solid ${s.color}44`,
        fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
        fontWeight: 600, textTransform: 'uppercase',
      }}>
        {s.label}
      </span>
      <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--muted)', paddingTop: 2 }}>
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

// ── Similar findings ──────────────────────────────────────────────────────────

function SimilarFindings({ findingId }) {
  const [similar, setSimilar] = useState([])
  const [loading, setLoading] = useState(true)

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {similar.map((s, i) => (
        <Link key={s.finding_id} to={`/findings/${s.finding_id}`} style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '9px 14px', borderRadius: 8,
          background: 'var(--surface-2)', border: '1px solid var(--border)',
          textDecoration: 'none', transition: 'border-color 0.15s',
        }}
          onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--amber)')}
          onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
        >
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', minWidth: 16 }}>
            #{i + 1}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--amber)' }}>
              {s.cve_id || '—'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 1 }}>
              {s.hostname} · {s.component}
            </div>
          </div>
          <div style={{ textAlign: 'right', flexShrink: 0 }}>
            <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: 'var(--text)' }}>
              {Math.round(s.score * 100)}%
            </div>
            <div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace' }}>
              e:{Math.round((s.breakdown?.embed ?? 0) * 100)} g:{Math.round((s.breakdown?.graph ?? 0) * 100)}
            </div>
          </div>
        </Link>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FindingDetail() {
  const { id }  = useParams()
  const [triage, setTriage] = useState(null)

  useEffect(() => {
    fetchAutoTriage(id).then(r => setTriage(r.data?.data ?? null)).catch(() => {})
  }, [id])

  return (
    <div style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--muted)' }}>
        <Link to="/findings" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Findings</Link>
        <span>/</span>
        <span style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)', fontSize: 11 }}>{id}</span>
      </div>

      <h1 className="page-title">Finding Detail</h1>

      {/* AI triage */}
      <div style={{ padding: '14px 18px', borderRadius: 10, background: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div className="mono-label" style={{ marginBottom: 8 }}>AI Triage Suggestion</div>
        <TriagePill t={triage} />
      </div>

      {/* Similar findings */}
      <div style={{ padding: '14px 18px', borderRadius: 10, background: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div className="mono-label" style={{ marginBottom: 12 }}>Similar Findings (top 5)</div>
        <SimilarFindings findingId={id} />
      </div>

      {/* Blast radius */}
      <div style={{ padding: '20px', borderRadius: 10, background: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div className="mono-label" style={{ marginBottom: 14 }}>Blast Radius</div>
        <BlastRadiusTab findingId={id} />
      </div>
    </div>
  )
}
