/**
 * ChatPanel — conversational interface for a single Finding/Job.
 *
 * Layout
 * ------
 * ┌─ Conversations list (collapsible) ───────────────────────────────────┐
 * │  [+ New conversation]   [conv_abc123 | 2 turns | 2026-05-31]  …     │
 * └──────────────────────────────────────────────────────────────────────┘
 * ┌─ Active conversation ────────────────────────────────────────────────┐
 * │  [User]  Does this patch apply to RHEL 9?                            │
 * │  [AI  ]  Yes, according to [cve_descriptions:CVE-2024-3400] …       │
 * │           Citations: ┌──────────────────────┐                       │
 * │                       │ cve_descriptions     │                       │
 * │                       │ CVE-2024-3400        │                       │
 * │                       └──────────────────────┘                       │
 * │  ┌── input ────────────────────────────────────────────────────────┐ │
 * │  │ Ask a follow-up…                                           Send │ │
 * │  └─────────────────────────────────────────────────────────────────┘ │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 * Props
 * -----
 * jobId    string   — the job/finding this panel is attached to
 * role     string   — current user role (auditor = read-only)
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  fetchFindingConversations,
  fetchConversation,
  streamFindingChat,
} from '../api/client'

// ── Colour helpers ────────────────────────────────────────────────────────────

const SOURCE_COLORS = {
  cve_descriptions:  { bg: 'rgba(78,143,175,0.15)',  border: 'rgba(78,143,175,0.4)',  text: '#4e8faf' },
  vendor_advisories: { bg: 'rgba(155,109,255,0.15)', border: 'rgba(155,109,255,0.4)', text: '#9b6dff' },
  internal_runbooks: { bg: 'rgba(78,175,124,0.15)',  border: 'rgba(78,175,124,0.4)',  text: '#4eaf7c' },
}
function sourceColor(sc) {
  return SOURCE_COLORS[sc] ?? { bg: 'rgba(136,136,136,0.1)', border: 'rgba(136,136,136,0.3)', text: '#888' }
}

// ── Citation chip ─────────────────────────────────────────────────────────────

function CitationChip({ sourceClass, sourceId, snippet }) {
  const [open, setOpen] = useState(false)
  const col = sourceColor(sourceClass)
  return (
    <span style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 4,
          padding: '1px 8px', borderRadius: 4,
          background: col.bg, border: `1px solid ${col.border}`,
          color: col.text,
          fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
          cursor: 'pointer', marginRight: 4,
        }}
        title={snippet}
      >
        {sourceClass.replace('_', ' ')} · {sourceId}
      </button>
      {open && (
        <div
          style={{
            position: 'absolute', bottom: 'calc(100% + 4px)', left: 0,
            zIndex: 100, width: 280, padding: 10, borderRadius: 6,
            background: 'var(--surface)', border: '1px solid var(--border)',
            boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
          }}
        >
          <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: col.text, marginBottom: 4 }}>
            {sourceClass} / {sourceId}
          </div>
          <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)', lineHeight: 1.5 }}>
            {snippet ?? '(no snippet)'}
          </p>
          <button
            onClick={() => setOpen(false)}
            style={{ marginTop: 6, fontSize: 10, color: 'var(--muted)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            ✕ close
          </button>
        </div>
      )}
    </span>
  )
}

// ── Render citation tags [source_class:source_id] inside text ─────────────────

function AnnotatedText({ text, citations }) {
  if (!citations?.length) return <span>{text}</span>

  // Build lookup: "source_class:source_id" -> citation object
  const lookup = Object.fromEntries(
    citations.map(c => [`${c.source_class}:${c.source_id}`, c])
  )

  // Split on [source_class:source_id] patterns
  const parts = text.split(/(\[[^\]]+:[^\]]+\])/g)
  return (
    <span>
      {parts.map((part, i) => {
        const inner = part.match(/^\[([^\]]+:[^\]]+)\]$/)
        if (inner) {
          const key = inner[1]
          const cit = lookup[key]
          if (cit) {
            return (
              <CitationChip
                key={i}
                sourceClass={cit.source_class}
                sourceId={cit.source_id}
                snippet={cit.snippet}
              />
            )
          }
        }
        return <span key={i}>{part}</span>
      })}
    </span>
  )
}

// ── Single message bubble ─────────────────────────────────────────────────────

function MessageBubble({ turn }) {
  const isUser = turn.role === 'user'
  const lines  = (turn.content || '').split('\n')
  const docs   = turn.retrieved_docs ?? []

  return (
    <div style={{ display: 'flex', justifyContent: isUser ? 'flex-end' : 'flex-start', marginBottom: 12 }}>
      <div
        style={{
          maxWidth: '85%',
          padding: '10px 14px',
          borderRadius: 8,
          background: isUser ? 'rgba(255,196,13,0.1)' : 'var(--surface)',
          border: isUser ? '1px solid rgba(255,196,13,0.3)' : '1px solid var(--border)',
        }}
      >
        {/* Role label */}
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.12em' }}>
          {isUser ? 'You' : 'VRA Assistant'}
        </div>

        {/* Message text with citation chips rendered inline */}
        <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.6 }}>
          {lines.map((line, i) => (
            <span key={i}>
              <AnnotatedText text={line} citations={docs} />
              {i < lines.length - 1 && <br />}
            </span>
          ))}
        </div>

        {/* Citation chips row (when sources available) */}
        {docs.length > 0 && (
          <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', alignSelf: 'center', marginRight: 4 }}>Sources:</span>
            {docs.map((d, i) => (
              <CitationChip
                key={i}
                sourceClass={d.source_class}
                sourceId={d.source_id}
                snippet={d.snippet}
              />
            ))}
          </div>
        )}

        {turn.created_at && (
          <div style={{ marginTop: 6, fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', opacity: 0.5 }}>
            {new Date(turn.created_at).toLocaleTimeString()}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Typing indicator ──────────────────────────────────────────────────────────

function TypingBubble({ streamingText }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-start', marginBottom: 12 }}>
      <div style={{ maxWidth: '85%', padding: '10px 14px', borderRadius: 8, background: 'var(--surface)', border: '1px solid var(--border)' }}>
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.12em' }}>
          VRA Assistant
        </div>
        {streamingText ? (
          <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
            {streamingText}
            <span style={{ display: 'inline-block', width: 8, height: 14, background: 'var(--amber)', marginLeft: 2, animation: 'blink 1s step-end infinite' }} />
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 4, padding: '4px 0' }}>
            {[0,1,2].map(i => (
              <div key={i} style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--amber)', animation: 'bounce 1s ease-in-out infinite', animationDelay: `${i*0.15}s` }} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Conversation list row ─────────────────────────────────────────────────────

function ConvRow({ conv, active, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: '100%', textAlign: 'left',
        padding: '8px 12px', borderRadius: 6,
        background: active ? 'rgba(255,196,13,0.1)' : 'transparent',
        border: active ? '1px solid rgba(255,196,13,0.3)' : '1px solid transparent',
        cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        transition: 'background 0.15s',
      }}
    >
      <div>
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: active ? 'var(--amber)' : 'var(--text)' }}>
          {conv.id}
        </div>
        <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', marginTop: 2 }}>
          by {conv.started_by} · {conv.turn_count ?? 0} turn{conv.turn_count !== 1 ? 's' : ''}
        </div>
      </div>
      <div style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)' }}>
        {conv.started_at ? new Date(conv.started_at).toLocaleDateString() : ''}
      </div>
    </button>
  )
}

// ── Main ChatPanel ────────────────────────────────────────────────────────────

export default function ChatPanel({ jobId, role }) {
  const isReadOnly = role === 'auditor'

  const [conversations, setConversations] = useState([])
  const [activeConvId,  setActiveConvId]  = useState(null)
  const [turns,         setTurns]         = useState([])
  const [input,         setInput]         = useState('')
  const [streaming,     setStreaming]      = useState(false)
  const [streamText,    setStreamText]     = useState('')
  const [listOpen,      setListOpen]       = useState(false)
  const [error,         setError]          = useState(null)

  const bottomRef   = useRef(null)
  const abortRef    = useRef(null)
  const textareaRef = useRef(null)

  // Load conversation list
  const loadConversations = useCallback(() => {
    fetchFindingConversations(jobId)
      .then(r => setConversations(r.data?.data ?? []))
      .catch(() => {})
  }, [jobId])

  useEffect(() => { loadConversations() }, [loadConversations])

  // Auto-scroll on new content
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [turns, streamText])

  // Load a specific conversation transcript
  const openConversation = useCallback((convId) => {
    setActiveConvId(convId)
    setStreamText('')
    fetchConversation(convId)
      .then(r => {
        const t = r.data?.data
        setTurns(t?.turns ?? [])
      })
      .catch(() => setTurns([]))
    setListOpen(false)
  }, [])

  // Send a message
  const sendMessage = useCallback(() => {
    const msg = input.trim()
    if (!msg || streaming) return

    setInput('')
    setStreaming(true)
    setStreamText('')
    setError(null)
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }

    // Optimistically add user turn to display
    const optimisticUser = {
      role: 'user', content: msg,
      created_at: new Date().toISOString(), retrieved_docs: [],
    }
    setTurns(prev => [...prev, optimisticUser])

    const { abort } = streamFindingChat({
      jobId,
      message: msg,
      conversationId: activeConvId,
      onToken: (token) => setStreamText(prev => prev + token),
      onDone: ({ conversation_id }) => {
        // Fetch the final transcript to get persisted turns + citations
        fetchConversation(conversation_id).then(r => {
          setTurns(r.data?.data?.turns ?? [])
          setStreamText('')
          setStreaming(false)
          if (!activeConvId) {
            setActiveConvId(conversation_id)
          }
          loadConversations()
        })
      },
      onError: (detail) => {
        setError(detail)
        setStreaming(false)
        setStreamText('')
      },
    })
    abortRef.current = abort
  }, [input, streaming, jobId, activeConvId, loadConversations])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() }
  }

  const startNewConversation = () => {
    setActiveConvId(null)
    setTurns([])
    setStreamText('')
    setError(null)
    setListOpen(false)
  }

  return (
    <div className="vra-card" style={{ borderColor: 'rgba(78,143,175,0.4)', borderLeftWidth: 3, padding: 0, overflow: 'hidden' }}>
      <style>{`
        @keyframes blink { 50% { opacity: 0; } }
        @keyframes bounce { 0%,80%,100% { transform: translateY(0); } 40% { transform: translateY(-5px); } }
      `}</style>

      {/* Header */}
      <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#4e8faf', boxShadow: '0 0 6px #4e8faf', display: 'inline-block' }} />
          <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, fontWeight: 600, color: 'var(--text)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            Chat with Finding
          </span>
          {isReadOnly && (
            <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', padding: '1px 6px', border: '1px solid var(--border)', borderRadius: 3 }}>
              READ-ONLY
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {!isReadOnly && (
            <button
              onClick={startNewConversation}
              style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--amber)', background: 'rgba(255,196,13,0.1)', border: '1px solid rgba(255,196,13,0.25)', borderRadius: 4, padding: '3px 10px', cursor: 'pointer' }}
            >
              + New
            </button>
          )}
          <button
            onClick={() => setListOpen(v => !v)}
            style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)', background: 'none', border: '1px solid var(--border)', borderRadius: 4, padding: '3px 10px', cursor: 'pointer' }}
          >
            {listOpen ? 'Hide' : 'History'} ({conversations.length})
          </button>
        </div>
      </div>

      {/* Conversation list (collapsible) */}
      {listOpen && (
        <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', background: 'var(--surface-2)', maxHeight: 180, overflowY: 'auto' }}>
          {conversations.length === 0 ? (
            <p style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10, color: 'var(--muted)', padding: '8px 0' }}>No conversations yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {conversations.map(c => (
                <ConvRow
                  key={c.id}
                  conv={c}
                  active={c.id === activeConvId}
                  onClick={() => openConversation(c.id)}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Message thread */}
      <div style={{ minHeight: 200, maxHeight: 420, overflowY: 'auto', padding: '16px 18px' }}>
        {turns.length === 0 && !streaming && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 180, gap: 8, opacity: 0.5 }}>
            <div style={{ fontSize: 32 }}>💬</div>
            <p style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--muted)', textAlign: 'center' }}>
              {activeConvId ? 'Loading…' : 'Ask a question about this finding.'}
            </p>
          </div>
        )}

        {turns.map((t, i) => <MessageBubble key={t.id ?? i} turn={t} />)}
        {streaming && <TypingBubble streamingText={streamText} />}

        {error && (
          <div style={{ padding: '8px 12px', borderRadius: 6, background: 'rgba(224,82,82,0.1)', border: '1px solid rgba(224,82,82,0.3)', color: 'var(--red)', fontSize: 12, fontFamily: '"IBM Plex Mono", monospace', marginBottom: 8 }}>
            ⚠ {error}
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      {!isReadOnly && (
        <div style={{ padding: '10px 14px', borderTop: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
            <textarea
              ref={textareaRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              onInput={e => {
                e.target.style.height = 'auto'
                e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px'
              }}
              rows={1}
              disabled={streaming}
              placeholder="Ask a follow-up… (Enter to send, Shift+Enter for new line)"
              style={{
                flex: 1, resize: 'none', padding: '8px 12px', borderRadius: 6,
                background: 'var(--surface)', border: '1px solid var(--border)',
                color: 'var(--text)', fontSize: 13, fontFamily: 'Inter, sans-serif',
                lineHeight: 1.5, outline: 'none', minHeight: 36, maxHeight: 120,
              }}
              onFocus={e  => (e.target.style.borderColor = 'rgba(78,143,175,0.5)')}
              onBlur={e   => (e.target.style.borderColor = 'var(--border)')}
            />
            <button
              onClick={sendMessage}
              disabled={streaming || !input.trim()}
              style={{
                flexShrink: 0, width: 36, height: 36, borderRadius: 6,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: input.trim() && !streaming ? '#4e8faf' : 'var(--surface)',
                border: input.trim() && !streaming ? 'none' : '1px solid var(--border)',
                color: input.trim() && !streaming ? '#fff' : 'var(--muted)',
                cursor: streaming || !input.trim() ? 'not-allowed' : 'pointer',
                fontSize: 16,
              }}
              title="Send"
            >
              ➤
            </button>
          </div>
          <div style={{ marginTop: 5, fontFamily: '"IBM Plex Mono", monospace', fontSize: 9, color: 'var(--muted)', opacity: 0.6 }}>
            Responses grounded in retrieved sources · Citations are clickable
          </div>
        </div>
      )}
    </div>
  )
}
