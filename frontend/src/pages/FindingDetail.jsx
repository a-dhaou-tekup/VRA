import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { fetchAutoTriage, fetchBlastRadius, fetchSimilarFindings } from '../api/client'

// ── Node kind config ──────────────────────────────────────────────────────────

const KIND_CONFIG = {
  cve:       { color: '#e05252', r: 8,  label: 'CVE',       desc: 'Common Vulnerability & Exposure identifier linked to this finding.' },
  component: { color: '#7a7d9c', r: 7,  label: 'Component', desc: 'Software component or library containing the vulnerable code.' },
  asset:     { color: '#f5a623', r: 12, label: 'Asset',     desc: 'Infrastructure asset (server, VM, container) running the affected component.' },
  owner:     { color: '#4eaf7c', r: 13, label: 'Owner',     desc: 'Business owner or team responsible for this asset or service.' },
  service:   { color: '#9b6dff', r: 13, label: 'Service',   desc: 'Business service that depends on one or more affected assets.' },
}
const DEFAULT_KIND = { color: '#4e8faf', r: 7, label: 'Node', desc: 'Graph node.' }
function kindCfg(kind) { return KIND_CONFIG[(kind || '').toLowerCase()] ?? DEFAULT_KIND }

// ── Graph coordinate helpers ──────────────────────────────────────────────────

function toWorld(mx, my, t) {
  return { x: (mx - t.x) / t.scale, y: (my - t.y) / t.scale }
}

function hitTest(mx, my, nodes, t) {
  const { x: wx, y: wy } = toWorld(mx, my, t)
  for (let i = nodes.length - 1; i >= 0; i--) {
    const nd = nodes[i]
    const r = kindCfg(nd.kind).r + 7
    const dx = nd.x - wx, dy = nd.y - wy
    if (dx * dx + dy * dy <= r * r) return i
  }
  return -1
}

// ── Force-directed graph hook ─────────────────────────────────────────────────

function useBlastGraph({ canvasRef, graphData, onSelect, onZoomChange }) {
  const nodesRef      = useRef([])
  const linksRef      = useRef([])
  const rafRef        = useRef(null)
  const transformRef  = useRef({ x: 0, y: 0, scale: 1 })
  const dragRef       = useRef(null)       // { type:'pan'|'node', nodeIdx, startMX, startMY, startTX, startTY }
  const hoveredRef    = useRef(-1)
  const selectedRef   = useRef(-1)
  const alphaRef      = useRef(1.0)
  const dimRef        = useRef({ W: 0, H: 0 })
  const cbSelectRef   = useRef(onSelect);  cbSelectRef.current   = onSelect
  const cbZoomRef     = useRef(onZoomChange); cbZoomRef.current  = onZoomChange

  // ── Public controls (stable refs) ────────────────────────────────────────────
  const fitToView = useCallback(() => {
    const nodes = nodesRef.current
    const { W, H } = dimRef.current
    if (!nodes.length || !W) return
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y)
    const minX = Math.min(...xs), maxX = Math.max(...xs)
    const minY = Math.min(...ys), maxY = Math.max(...ys)
    const pad = 90
    const s = Math.min((W - pad * 2) / (maxX - minX || 1), (H - pad * 2) / (maxY - minY || 1), 3)
    transformRef.current = {
      x: W / 2 - ((minX + maxX) / 2) * s,
      y: H / 2 - ((minY + maxY) / 2) * s,
      scale: s,
    }
    cbZoomRef.current?.(Math.round(s * 100))
  }, [])

  const resetView = useCallback(() => {
    const { W, H } = dimRef.current
    transformRef.current = { x: W / 2, y: H / 2, scale: 1 }
    cbZoomRef.current?.(100)
  }, [])

  const zoomBy = useCallback((factor) => {
    const { W, H } = dimRef.current
    const t = transformRef.current
    const ns = Math.min(6, Math.max(0.1, t.scale * factor))
    transformRef.current = {
      x: W / 2 - (W / 2 - t.x) * (ns / t.scale),
      y: H / 2 - (H / 2 - t.y) * (ns / t.scale),
      scale: ns,
    }
    cbZoomRef.current?.(Math.round(ns * 100))
  }, [])

  // ── Main effect — runs when graphData changes ─────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !graphData) return
    cancelAnimationFrame(rafRef.current)
    hoveredRef.current  = -1
    selectedRef.current = -1
    cbSelectRef.current?.(null)

    // DPR-aware sizing
    const dpr = window.devicePixelRatio || 1
    const W = canvas.offsetWidth
    const H = canvas.offsetHeight
    canvas.width  = W * dpr
    canvas.height = H * dpr
    const ctx = canvas.getContext('2d')
    ctx.scale(dpr, dpr)
    dimRef.current = { W, H }

    // Fibonacci spiral — compact, avoids huge initial ring with many nodes
    const nodes = graphData.nodes.map((n, i) => {
      const total = graphData.nodes.length
      const theta = i * 2.399  // golden-angle spiral
      const rr    = Math.sqrt(i + 1) * (total < 15 ? 30 : total < 40 ? 18 : 12)
      return { ...n, x: W / 2 + Math.cos(theta) * rr, y: H / 2 + Math.sin(theta) * rr, vx: 0, vy: 0, pinned: false }
    })
    const nodeIndex = Object.fromEntries(nodes.map((n, i) => [n.id, i]))
    const links = (graphData.links || [])
      .map(e => ({ source: nodeIndex[e.source], target: nodeIndex[e.target], kind: e.kind }))
      .filter(e => e.source != null && e.target != null)

    nodesRef.current  = nodes
    linksRef.current  = links
    alphaRef.current  = 1.0
    transformRef.current = { x: W / 2, y: H / 2, scale: 1 }
    cbZoomRef.current?.(100)

    // ── Simulation constants ────────────────────────────────────────────────
    const REPULSION  = 600    // compact charge — nodes cluster, not scatter
    const SPRING_LEN = 45     // shorter rest length → tighter layout
    const SPRING_K   = 0.06   // stiffer spring → faster convergence
    const GRAVITY    = 0.025  // stronger centre pull → cluster near middle
    const DAMPING    = 0.85   // high damping → settles quickly, no wobble
    const ALPHA_STOP = 0.005

    function tick() {
      const alpha = alphaRef.current
      if (alpha <= 0) return
      const n = nodes.length
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y
          const d2 = dx * dx + dy * dy + 1
          const f  = REPULSION / d2
          nodes[i].vx -= f * dx; nodes[i].vy -= f * dy
          nodes[j].vx += f * dx; nodes[j].vy += f * dy
        }
      }
      for (const l of links) {
        const a = nodes[l.source], b = nodes[l.target]
        const dx = b.x - a.x, dy = b.y - a.y
        const d  = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (d - SPRING_LEN) * SPRING_K
        const fx = force * dx / d, fy = force * dy / d
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy
      }
      for (const nd of nodes) {
        if (nd.pinned) { nd.vx = 0; nd.vy = 0; continue }
        nd.vx += (W / 2 - nd.x) * GRAVITY * alpha
        nd.vy += (H / 2 - nd.y) * GRAVITY * alpha
        nd.vx *= DAMPING; nd.vy *= DAMPING
        // clamp velocity so dense graphs don't explode numerically
        if (nd.vx > 50) nd.vx = 50; else if (nd.vx < -50) nd.vx = -50
        if (nd.vy > 50) nd.vy = 50; else if (nd.vy < -50) nd.vy = -50
        nd.x  += nd.vx;   nd.y  += nd.vy
        if (!isFinite(nd.x) || !isFinite(nd.y)) { nd.x = W / 2; nd.y = H / 2; nd.vx = 0; nd.vy = 0 }
      }
      // Decay alpha — reaches ALPHA_STOP in ≈ 180 frames (3 s at 60 fps)
      const next = alpha * 0.975
      alphaRef.current = next < ALPHA_STOP ? 0 : next
    }

    // ── Drawing ─────────────────────────────────────────────────────────────
    function draw() {
      ctx.clearRect(0, 0, W, H)
      const t = transformRef.current
      const sel = selectedRef.current
      const hov = hoveredRef.current

      // Connected-node set for dimming
      const conn = new Set()
      if (sel >= 0) {
        conn.add(sel)
        for (const l of links) {
          if (l.source === sel) conn.add(l.target)
          if (l.target === sel) conn.add(l.source)
        }
      }

      ctx.save()
      ctx.translate(t.x, t.y)
      ctx.scale(t.scale, t.scale)

      // ── Edges ─────────────────────────────────────────────────────────────
      for (const l of links) {
        const a = nodes[l.source], b = nodes[l.target]
        const isSel = sel >= 0 && (l.source === sel || l.target === sel)
        const dx = b.x - a.x, dy = b.y - a.y
        const d  = Math.sqrt(dx * dx + dy * dy) || 1
        const ux = dx / d, uy = dy / d
        const srcR = kindCfg(a.kind).r, dstR = kindCfg(b.kind).r
        const sx = a.x + ux * srcR, sy = a.y + uy * srcR
        const ex = b.x - ux * (dstR + 2), ey = b.y - uy * (dstR + 2)

        ctx.beginPath()
        ctx.moveTo(sx, sy)
        ctx.lineTo(ex, ey)
        ctx.strokeStyle = isSel ? 'rgba(255,196,13,0.70)' : 'rgba(255,255,255,0.09)'
        ctx.lineWidth   = isSel ? 1.8 : 0.9
        ctx.stroke()

        // Arrowhead
        const headLen = 7, headW = 4
        ctx.beginPath()
        ctx.moveTo(ex, ey)
        ctx.lineTo(ex - ux * headLen + uy * headW, ey - uy * headLen - ux * headW)
        ctx.lineTo(ex - ux * headLen - uy * headW, ey - uy * headLen + ux * headW)
        ctx.closePath()
        ctx.fillStyle = isSel ? 'rgba(255,196,13,0.55)' : 'rgba(255,255,255,0.13)'
        ctx.fill()

        // Edge label (only when zoomed in enough to read)
        if (l.kind && t.scale > 0.3) {
          const midX = (sx + ex) / 2, midY = (sy + ey) / 2
          const angle = Math.atan2(ey - sy, ex - sx)
          const flipped = angle > Math.PI / 2 || angle < -Math.PI / 2
          const eSz = Math.max(5.5, 6.5 / t.scale)
          const labelText = l.kind.replace(/_/g, ' ').toUpperCase()
          ctx.save()
          ctx.translate(midX, midY)
          ctx.rotate(flipped ? angle + Math.PI : angle)
          ctx.font = `${eSz}px "IBM Plex Mono",monospace`
          ctx.textAlign = 'center'
          const tw = ctx.measureText(labelText).width
          const px = 3 / t.scale, py = 2 / t.scale
          ctx.fillStyle = 'rgba(8,10,20,0.80)'
          ctx.fillRect(-tw / 2 - px, -eSz - py, tw + px * 2, eSz + py * 2 + eSz * 0.25)
          ctx.fillStyle = isSel ? 'rgba(255,196,13,0.90)' : 'rgba(255,255,255,0.42)'
          ctx.fillText(labelText, 0, 0)
          ctx.restore()
        }
      }

      // ── Nodes ──────────────────────────────────────────────────────────────
      // Label font size constant in screen space (world size = screen-size / scale)
      const labelSize = Math.max(7, Math.min(12, 10 / t.scale))

      for (let i = 0; i < nodes.length; i++) {
        const nd = nodes[i]
        const { color, r } = kindCfg(nd.kind)
        const isHov = hov === i
        const isSel = sel === i
        const isDim = sel >= 0 && !conn.has(i)

        ctx.globalAlpha = isDim ? 0.20 : 1

        // Shadow / glow
        if (isHov || isSel) {
          ctx.shadowColor = color
          ctx.shadowBlur  = isSel ? 20 : 12
        }

        // Selection ring
        if (isSel) {
          ctx.beginPath()
          ctx.arc(nd.x, nd.y, r + 5, 0, Math.PI * 2)
          ctx.strokeStyle = color
          ctx.lineWidth = 1.5
          ctx.stroke()
          ctx.shadowBlur = 0
        }

        // Node fill
        ctx.beginPath()
        ctx.arc(nd.x, nd.y, r, 0, Math.PI * 2)
        ctx.fillStyle   = color + (isSel ? 'ff' : isHov ? 'ee' : 'aa')
        ctx.fill()
        ctx.strokeStyle = color
        ctx.lineWidth   = isSel ? 2 : 1.2
        ctx.stroke()
        ctx.shadowBlur  = 0

        // Label
        ctx.font = `${labelSize}px "IBM Plex Mono",monospace`
        ctx.textAlign = 'center'
        const rawLabel = (nd.label || nd.id || '').toString()
        const display  = rawLabel.length > 22 ? rawLabel.slice(0, 21) + '…' : rawLabel
        const tw  = ctx.measureText(display).width
        const lx  = nd.x
        const ly  = nd.y + r + labelSize + 3

        // Backdrop pill
        ctx.fillStyle = 'rgba(8,10,20,0.75)'
        const px = 4, py = 2
        ctx.beginPath()
        ctx.roundRect?.(lx - tw / 2 - px, ly - labelSize - py, tw + px * 2, labelSize + py * 2, 3)
        ctx.fill?.()

        ctx.fillStyle = isDim ? 'rgba(226,224,237,0.25)' : isHov ? '#ffffff' : 'rgba(226,224,237,0.85)'
        ctx.fillText(display, lx, ly)

        // Pin dot
        if (nd.pinned) {
          ctx.fillStyle = 'rgba(255,255,255,0.6)'
          ctx.font = `${Math.max(6, 9 / t.scale)}px sans-serif`
          ctx.fillText('⚑', nd.x + r + 2, nd.y - r)
        }

        ctx.globalAlpha = 1
      }

      ctx.restore()

      // ── Zoom level overlay ───────────────────────────────────────────────────
      const pct = Math.round(t.scale * 100)
      ctx.font = '10px "IBM Plex Mono",monospace'
      ctx.textAlign = 'right'
      ctx.fillStyle = 'rgba(255,255,255,0.20)'
      ctx.fillText(`${pct}%`, W - 10, H - 10)
    }

    let hasAutoFit = false
    function loop() {
      if (alphaRef.current > 0) tick()
      draw()
      // Auto-fit once the simulation has fully settled
      if (alphaRef.current === 0 && !hasAutoFit) {
        hasAutoFit = true
        fitToView()
      }
      rafRef.current = requestAnimationFrame(loop)
    }
    rafRef.current = requestAnimationFrame(loop)

    // ── Pointer events ───────────────────────────────────────────────────────
    function xy(e) {
      const r = canvas.getBoundingClientRect()
      return [e.clientX - r.left, e.clientY - r.top]
    }

    function onWheel(e) {
      e.preventDefault()
      const [mx, my] = xy(e)
      const t = transformRef.current
      const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12
      const ns = Math.min(6, Math.max(0.1, t.scale * factor))
      transformRef.current = {
        x: mx - (mx - t.x) * (ns / t.scale),
        y: my - (my - t.y) * (ns / t.scale),
        scale: ns,
      }
      cbZoomRef.current?.(Math.round(ns * 100))
    }

    function onMouseDown(e) {
      const [mx, my] = xy(e)
      const ni = hitTest(mx, my, nodes, transformRef.current)
      if (ni >= 0) {
        dragRef.current = { type: 'node', nodeIdx: ni, startMX: mx, startMY: my }
      } else {
        const t = transformRef.current
        dragRef.current = { type: 'pan', startMX: mx, startMY: my, startTX: t.x, startTY: t.y }
        canvas.style.cursor = 'grabbing'
      }
    }

    function onMouseMove(e) {
      const [mx, my] = xy(e)
      const drag = dragRef.current
      if (drag?.type === 'pan') {
        const t = transformRef.current
        transformRef.current = { ...t, x: drag.startTX + (mx - drag.startMX), y: drag.startTY + (my - drag.startMY) }
      } else if (drag?.type === 'node') {
        const { x: wx, y: wy } = toWorld(mx, my, transformRef.current)
        const nd = nodes[drag.nodeIdx]
        nd.x = wx; nd.y = wy; nd.vx = 0; nd.vy = 0; nd.pinned = true
      }
      if (!drag) {
        const ni = hitTest(mx, my, nodes, transformRef.current)
        hoveredRef.current = ni
        canvas.style.cursor = ni >= 0 ? 'pointer' : 'grab'
      }
    }

    function onMouseUp(e) {
      const [mx, my] = xy(e)
      const drag = dragRef.current
      dragRef.current = null
      if (drag?.type === 'node') {
        const dist = Math.hypot(mx - drag.startMX, my - drag.startMY)
        if (dist < 5) {
          // Treat as click — toggle selection
          const ni = drag.nodeIdx
          const next = ni === selectedRef.current ? -1 : ni
          selectedRef.current = next
          cbSelectRef.current?.(next >= 0 ? nodes[next] : null)
        }
      }
      canvas.style.cursor = hoveredRef.current >= 0 ? 'pointer' : 'grab'
    }

    function onDblClick(e) {
      const [mx, my] = xy(e)
      const ni = hitTest(mx, my, nodes, transformRef.current)
      if (ni >= 0) {
        nodes[ni].pinned = false
        alphaRef.current = 0.35
      } else {
        fitToView()
      }
    }

    function onMouseLeave() {
      hoveredRef.current = -1
      dragRef.current    = null
      canvas.style.cursor = 'grab'
    }

    canvas.style.cursor = 'grab'
    canvas.addEventListener('wheel',      onWheel,     { passive: false })
    canvas.addEventListener('mousedown',  onMouseDown)
    canvas.addEventListener('mousemove',  onMouseMove)
    canvas.addEventListener('mouseup',    onMouseUp)
    canvas.addEventListener('dblclick',   onDblClick)
    canvas.addEventListener('mouseleave', onMouseLeave)

    return () => {
      cancelAnimationFrame(rafRef.current)
      canvas.removeEventListener('wheel',      onWheel)
      canvas.removeEventListener('mousedown',  onMouseDown)
      canvas.removeEventListener('mousemove',  onMouseMove)
      canvas.removeEventListener('mouseup',    onMouseUp)
      canvas.removeEventListener('dblclick',   onDblClick)
      canvas.removeEventListener('mouseleave', onMouseLeave)
    }
  }, [graphData, fitToView])

  return { fitToView, resetView, zoomBy }
}

// ── Node detail panel ─────────────────────────────────────────────────────────

function NodePanel({ node, onClose }) {
  if (!node) return null
  const cfg  = kindCfg(node.kind)
  const skip = new Set(['x', 'y', 'vx', 'vy', 'fx', 'fy', 'pinned', 'index'])
  return (
    <div style={{
      position: 'absolute', top: 12, right: 12, zIndex: 20, width: 248,
      background: 'var(--surface)', border: `1px solid ${cfg.color}55`,
      borderRadius: 10, padding: '14px 16px',
      boxShadow: `0 0 32px ${cfg.color}22, 0 8px 24px rgba(0,0,0,0.6)`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span style={{ width: 9, height: 9, borderRadius: '50%', background: cfg.color, display: 'inline-block', boxShadow: `0 0 6px ${cfg.color}` }} />
          <span style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 10, color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            {cfg.label}
          </span>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--muted)', fontSize: 15, lineHeight: 1 }}>✕</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
        {Object.entries(node).filter(([k]) => !skip.has(k)).map(([k, v]) => (
          <div key={k} style={{ display: 'flex', gap: 8, fontSize: 11 }}>
            <span style={{ color: 'var(--muted)', fontFamily: '"IBM Plex Mono",monospace', minWidth: 70, flexShrink: 0 }}>{k}</span>
            <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{String(v ?? '—')}</span>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 10, fontSize: 10, color: 'var(--muted)', fontFamily: '"IBM Plex Mono",monospace', borderTop: '1px solid var(--border)', paddingTop: 8 }}>
        {cfg.desc}
      </div>
    </div>
  )
}

// ── Legend ────────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div style={{
      position: 'absolute', top: 12, left: 12, zIndex: 20,
      background: 'rgba(8,10,20,0.88)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '10px 14px',
      display: 'flex', flexDirection: 'column', gap: 6, pointerEvents: 'none',
    }}>
      <div className="mono-label" style={{ marginBottom: 2, fontSize: 9 }}>Node types</div>
      {Object.entries(KIND_CONFIG).map(([kind, cfg]) => (
        <div key={kind} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: cfg.r * 1.5, height: cfg.r * 1.5, borderRadius: '50%', background: cfg.color, flexShrink: 0, boxShadow: `0 0 4px ${cfg.color}88` }} />
          <span style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 10, color: 'var(--muted)' }}>{cfg.label}</span>
        </div>
      ))}
    </div>
  )
}

// ── Zoom controls ─────────────────────────────────────────────────────────────

function ZoomControls({ zoom, onZoomIn, onZoomOut, onFit, onReset }) {
  const btn = (label, onClick, title) => (
    <button onClick={onClick} title={title} style={{
      padding: '5px 10px', border: '1px solid var(--border)', borderRadius: 6,
      background: 'rgba(8,10,20,0.85)', color: 'var(--muted)',
      fontFamily: '"IBM Plex Mono",monospace', fontSize: 11,
      cursor: 'pointer', transition: 'color 0.15s, border-color 0.15s',
    }}
      onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)'; e.currentTarget.style.borderColor = 'var(--amber)' }}
      onMouseLeave={e => { e.currentTarget.style.color = 'var(--muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}
    >{label}</button>
  )
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {btn('−', onZoomOut, 'Zoom out (scroll down)')}
      <span style={{
        padding: '4px 10px', border: '1px solid var(--border)', borderRadius: 6,
        fontFamily: '"IBM Plex Mono",monospace', fontSize: 11, color: 'var(--amber)',
        background: 'rgba(8,10,20,0.85)', minWidth: 52, textAlign: 'center',
      }}>{zoom}%</span>
      {btn('+', onZoomIn, 'Zoom in (scroll up)')}
      {btn('⊡ Fit', onFit, 'Fit all nodes into view (double-click canvas)')}
      {btn('↺ Reset', onReset, 'Reset view to 100%')}
    </div>
  )
}

// ── Explanation tab ───────────────────────────────────────────────────────────

function ExplanationTab({ graphData, depth }) {
  if (!graphData || !graphData.nodes.length) {
    return (
      <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
        No graph data loaded yet — click <b>Load Graph</b> on the Graph tab first.
      </div>
    )
  }

  // Aggregate stats
  const byKind = {}
  for (const n of graphData.nodes) {
    const k = (n.kind || 'unknown').toLowerCase()
    byKind[k] = (byKind[k] ?? 0) + 1
  }
  const degree = {}
  for (const l of graphData.links) {
    degree[l.source] = (degree[l.source] ?? 0) + 1
    degree[l.target] = (degree[l.target] ?? 0) + 1
  }
  const topEntry = Object.entries(degree).sort((a, b) => b[1] - a[1])[0]
  const topNode  = topEntry ? graphData.nodes.find(n => n.id === topEntry[0]) : null
  const topDeg   = topEntry?.[1] ?? 0

  const assetCount   = byKind.asset    ?? 0
  const cveCount     = byKind.cve      ?? 0
  const svcCount     = byKind.service  ?? 0
  const ownerCount   = byKind.owner    ?? 0
  const compCount    = byKind.component ?? 0

  const S = { color: 'var(--text)', fontSize: 12, lineHeight: 1.75 }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0, fontSize: 12 }}>

      {/* ── What is blast radius ── */}
      <Section title="What is the Blast Radius?">
        <p style={{ ...S, color: 'var(--muted)', marginBottom: 8 }}>
          The blast radius graph maps the potential <b style={{ color: 'var(--text)' }}>scope of impact</b> if this
          finding is exploited. Starting from the vulnerable component, it traverses the infrastructure
          dependency graph — component → asset → service/owner — up to <b style={{ color: 'var(--amber)' }}>{depth} hop{depth > 1 ? 's' : ''}</b> out.
        </p>
        <p style={{ ...S, color: 'var(--muted)' }}>
          It answers: <em>"If this CVE is actively exploited, what infrastructure and business
          services are at risk, and who is responsible?"</em>
        </p>
      </Section>

      {/* ── Graph stats ── */}
      <Section title="Current Graph Overview">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginBottom: 14 }}>
          {[
            { label: 'Total nodes',        value: graphData.nodes.length, accent: 'var(--text)' },
            { label: 'Edges (deps)',        value: graphData.links.length, accent: 'var(--text)' },
            { label: 'Assets at risk',      value: assetCount,   accent: '#f5a623' },
            { label: 'Services exposed',    value: svcCount,     accent: '#9b6dff' },
            { label: 'CVEs involved',       value: cveCount,     accent: '#e05252' },
            { label: 'Owners to notify',    value: ownerCount,   accent: '#4eaf7c' },
          ].map(({ label, value, accent }) => (
            <div key={label} style={{ padding: '10px 14px', borderRadius: 8, background: 'var(--dark)', border: '1px solid var(--border)' }}>
              <div style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 9, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: accent, marginTop: 4, fontFamily: 'Syne, sans-serif' }}>{value}</div>
            </div>
          ))}
        </div>
        {topNode && (
          <div style={{ padding: '8px 12px', borderRadius: 7, background: 'rgba(255,196,13,0.07)', border: '1px solid rgba(255,196,13,0.2)', fontSize: 11, color: 'var(--muted)' }}>
            <span style={{ color: 'var(--amber)' }}>Most connected node: </span>
            <span style={{ color: 'var(--text)' }}>{topNode.label || topNode.id}</span>
            <span> ({topDeg} connection{topDeg !== 1 ? 's' : ''}) — likely a critical hub in the dependency chain.</span>
          </div>
        )}
      </Section>

      {/* ── Node types ── */}
      <Section title="Node Types & Meaning">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
          {Object.entries(KIND_CONFIG).map(([kind, cfg]) => {
            const count = byKind[kind] ?? 0
            return (
              <div key={kind} style={{
                display: 'flex', alignItems: 'flex-start', gap: 12,
                padding: '10px 0', borderBottom: '1px solid var(--border)',
              }}>
                <span style={{
                  marginTop: 3, width: cfg.r * 2, height: cfg.r * 2, borderRadius: '50%',
                  background: cfg.color, flexShrink: 0,
                  boxShadow: `0 0 6px ${cfg.color}66`,
                }} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, color: 'var(--text)', fontSize: 12 }}>{cfg.label}</div>
                  <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 2 }}>{cfg.desc}</div>
                </div>
                <div style={{
                  fontFamily: '"IBM Plex Mono",monospace', fontSize: 11, marginTop: 2,
                  color: count > 0 ? cfg.color : 'var(--muted)', flexShrink: 0,
                }}>
                  {count > 0 ? `×${count}` : '—'}
                </div>
              </div>
            )
          })}
        </div>
      </Section>

      {/* ── Impact ── */}
      {(assetCount > 0 || cveCount > 0) && (
        <Section title="Impact Assessment">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, color: 'var(--muted)' }}>
            {cveCount   > 0 && <Row dot="#e05252">{cveCount} CVE{cveCount > 1 ? 's are' : ' is'} associated with this finding.</Row>}
            {compCount  > 0 && <Row dot="#7a7d9c">{compCount} software component{compCount > 1 ? 's are' : ' is'} affected.</Row>}
            {assetCount > 0 && <Row dot="#f5a623"><b style={{ color: '#f5a623' }}>{assetCount} infrastructure asset{assetCount > 1 ? 's' : ''}</b> could be compromised if exploited.</Row>}
            {svcCount   > 0 && <Row dot="#9b6dff"><b style={{ color: '#9b6dff' }}>{svcCount} business service{svcCount > 1 ? 's' : ''}</b> depend on affected assets and may be disrupted.</Row>}
            {ownerCount > 0 && <Row dot="#4eaf7c"><b style={{ color: '#4eaf7c' }}>{ownerCount} owner{ownerCount > 1 ? 's' : ''}</b> should be notified and assigned remediation tasks.</Row>}
            {assetCount === 0 && <div style={{ color: 'var(--muted)', fontStyle: 'italic' }}>No assets found at depth {depth}. Try increasing the depth or running the service graph seed script.</div>}
          </div>
        </Section>
      )}

      {/* ── Navigation guide ── */}
      <Section title="How to Navigate the Graph">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {[
            ['Scroll wheel',        'Zoom in / out toward cursor'],
            ['Drag canvas',         'Pan the view freely'],
            ['Drag a node',         'Reposition and pin it in place'],
            ['Click a node',        'Select and inspect its properties'],
            ['Dbl-click node',      'Unpin it — resumes physics simulation'],
            ['Dbl-click canvas',    'Fit all nodes into view'],
            ['⊡ Fit button',        'Auto-scale to show the full graph'],
            ['↺ Reset button',      'Return to 100% zoom, centered'],
            ['Depth 1 / 2 / 3',     'Control how many hops to traverse'],
          ].map(([key, val]) => (
            <div key={key} style={{ display: 'flex', gap: 8, padding: '6px 10px', borderRadius: 6, background: 'var(--dark)' }}>
              <span style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 10, color: 'var(--amber)', flexShrink: 0, minWidth: 130 }}>{key}</span>
              <span style={{ fontSize: 11, color: 'var(--muted)' }}>{val}</span>
            </div>
          ))}
        </div>
      </Section>

    </div>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ padding: '18px 0', borderBottom: '1px solid var(--border)' }}>
      <div className="mono-label" style={{ marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  )
}

function Row({ dot, children }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 9 }}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: dot, flexShrink: 0, marginTop: 4 }} />
      <span>{children}</span>
    </div>
  )
}

// ── Blast-radius section (graph + tabs) ────────────────────────────────────────

function BlastRadiusSection({ findingId }) {
  const [graphData,     setGraphData]     = useState(null)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [depth,         setDepth]         = useState(2)
  const [selected,      setSelected]      = useState(null)
  const [zoomLevel,     setZoomLevel]     = useState(100)
  const [tab,           setTab]           = useState('graph') // 'graph' | 'explanation'
  const [truncated,     setTruncated]     = useState(false)
  const [nodeCountFull, setNodeCountFull] = useState(0)
  const canvasRef = useRef(null)

  const { fitToView, resetView, zoomBy } = useBlastGraph({
    canvasRef,
    graphData,
    onSelect:     setSelected,
    onZoomChange: setZoomLevel,
  })

  const load = useCallback(() => {
    setLoading(true); setError(null); setSelected(null); setGraphData(null)
    setTruncated(false); setNodeCountFull(0)
    fetchBlastRadius(findingId, depth)
      .then(r => {
        const d = r.data?.data ?? r.data
        setGraphData({
          nodes: d.nodes ?? [],
          links: (d.edges ?? []).map(e => ({ source: e.source, target: e.target, kind: e.kind })),
        })
        setTruncated(d.truncated ?? false)
        setNodeCountFull(d.node_count_full ?? 0)
      })
      .catch(e => setError(e.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }, [findingId, depth])

  useEffect(() => { load() }, [load])

  const tabBtn = (id, label) => (
    <button key={id} onClick={() => setTab(id)} style={{
      padding: '7px 18px', borderRadius: '8px 8px 0 0',
      background: tab === id ? 'var(--surface)' : 'transparent',
      color: tab === id ? 'var(--text)' : 'var(--muted)',
      border: '1px solid var(--border)',
      borderBottom: tab === id ? '1px solid var(--surface)' : '1px solid var(--border)',
      fontFamily: '"IBM Plex Mono",monospace', fontSize: 11,
      cursor: 'pointer', marginBottom: -1, position: 'relative',
      transition: 'color 0.15s',
    }}>{label}</button>
  )

  const nodeCount = graphData?.nodes.length ?? 0
  const edgeCount = graphData?.links.length ?? 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>

      {/* ── Toolbar ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
        {/* Depth */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="mono-label">Depth</span>
          {[1, 2, 3].map(d => (
            <button key={d} onClick={() => setDepth(d)} style={{
              padding: '4px 13px', borderRadius: 6,
              background: depth === d ? 'var(--amber)' : 'var(--surface-2)',
              color: depth === d ? '#000' : 'var(--muted)',
              border: `1px solid ${depth === d ? 'var(--amber)' : 'var(--border)'}`,
              fontFamily: '"IBM Plex Mono",monospace', fontSize: 11, cursor: 'pointer',
            }}>{d}</button>
          ))}
        </div>

        <div style={{ width: 1, height: 20, background: 'var(--border)' }} />

        {/* Zoom controls */}
        <ZoomControls
          zoom={zoomLevel}
          onZoomIn={() => zoomBy(1.20)}
          onZoomOut={() => zoomBy(1 / 1.20)}
          onFit={fitToView}
          onReset={resetView}
        />

        <button onClick={load} style={{
          marginLeft: 'auto', padding: '4px 13px', borderRadius: 6,
          background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--muted)', fontFamily: '"IBM Plex Mono",monospace',
          fontSize: 11, cursor: 'pointer',
        }}>↺ Refresh</button>
      </div>

      {/* ── Tab bar ── */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)', marginBottom: 0 }}>
        {tabBtn('graph',       '⬡ Graph')}
        {tabBtn('explanation', '? Explanation')}
      </div>

      {/* ── Graph tab ── */}
      <div style={{ display: tab === 'graph' ? 'block' : 'none' }}>
        <div style={{
          position: 'relative', width: '100%', height: 680,
          background: 'var(--black)', borderRadius: '0 8px 8px 8px',
          border: '1px solid var(--border)', borderTop: 'none', overflow: 'hidden',
        }}>
          {loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10, color: 'var(--muted)' }}>
              <div style={{ width: 28, height: 28, border: '2px solid var(--border)', borderTopColor: 'var(--amber)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
              <span style={{ fontSize: 12, fontFamily: '"IBM Plex Mono",monospace' }}>Building graph…</span>
            </div>
          )}
          {error && !loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#e05252', fontSize: 13, padding: 32, textAlign: 'center' }}>
              ⚠ {error}
            </div>
          )}
          {!loading && !error && graphData && nodeCount === 0 && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10, color: 'var(--muted)' }}>
              <div style={{ fontSize: 32 }}>🕸</div>
              <div style={{ fontSize: 13 }}>No graph data for this finding.</div>
              <div style={{ fontSize: 11, fontFamily: '"IBM Plex Mono",monospace' }}>Run the seed script or upload a scan first.</div>
            </div>
          )}
          {!loading && !error && graphData && nodeCount > 0 && (
            <>
              <Legend />
              <NodePanel node={selected} onClose={() => setSelected(null)} />
              <canvas
                ref={canvasRef}
                style={{ width: '100%', height: '100%', display: 'block' }}
              />
            </>
          )}
        </div>

        {/* Status bar */}
        {graphData && nodeCount > 0 && (
          <div style={{ display: 'flex', gap: 16, padding: '6px 2px', fontFamily: '"IBM Plex Mono",monospace', fontSize: 10, color: 'var(--muted)', flexWrap: 'wrap', alignItems: 'center' }}>
            <span>{nodeCount} nodes · {edgeCount} edges</span>
            {truncated && (
              <span style={{
                color: 'var(--amber)', background: 'rgba(255,196,13,0.08)',
                border: '1px solid rgba(255,196,13,0.25)', borderRadius: 4,
                padding: '1px 7px',
              }}>
                ⚠ graph capped — showing {nodeCount} of {nodeCountFull} nodes (closest to asset)
              </span>
            )}
            <span style={{ color: 'var(--border)' }}>|</span>
            <span>Scroll to zoom · Drag canvas to pan · Click node for details · Dbl-click to unpin / fit</span>
          </div>
        )}
      </div>

      {/* ── Explanation tab ── */}
      {tab === 'explanation' && (
        <div style={{ borderRadius: '0 8px 8px 8px', border: '1px solid var(--border)', borderTop: 'none', padding: '20px 24px' }}>
          <ExplanationTab graphData={graphData} depth={depth} />
        </div>
      )}
    </div>
  )
}

// ── AI triage pill ────────────────────────────────────────────────────────────

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
        fontFamily: '"IBM Plex Mono",monospace', fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
      }}>{s.label}</span>
      <span style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 11, color: 'var(--muted)', paddingTop: 2 }}>
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
  if (!similar.length) return <div style={{ color: 'var(--muted)', fontSize: 12 }}>No similar findings found.</div>

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
          <span style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 9, color: 'var(--muted)', minWidth: 16 }}>#{i + 1}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 11, color: 'var(--amber)' }}>{s.cve_id || '—'}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 1 }}>{s.hostname} · {s.component}</div>
          </div>
          <div style={{ textAlign: 'right', flexShrink: 0 }}>
            <div style={{ fontFamily: '"IBM Plex Mono",monospace', fontSize: 12, color: 'var(--text)' }}>{Math.round(s.score * 100)}%</div>
            <div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: '"IBM Plex Mono",monospace' }}>
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
  const { id } = useParams()
  const [triage, setTriage] = useState(null)

  useEffect(() => {
    fetchAutoTriage(id).then(r => setTriage(r.data?.data ?? null)).catch(() => {})
  }, [id])

  return (
    <div style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: 22 }}>

      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--muted)' }}>
        <Link to="/findings" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Findings</Link>
        <span>/</span>
        <span style={{ fontFamily: '"IBM Plex Mono",monospace', color: 'var(--amber)', fontSize: 11 }}>{id}</span>
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

      {/* Blast radius + explanation tabs */}
      <div style={{ padding: '20px 20px 16px', borderRadius: 10, background: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div className="mono-label" style={{ marginBottom: 16 }}>Blast Radius</div>
        <BlastRadiusSection findingId={id} />
      </div>

      {/* CSS for spinner */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
