/**
 * AgentChat — global AI assistant panel.
 *
 * Floating action button (bottom-right) toggles a slide-in panel that:
 *  - Calls POST /api/agent/chat with full conversation history (multi-turn).
 *  - Renders the answer with a collapsible tool-trace and RAG citation cards.
 *  - Shows thumbs up/down per assistant turn, wired to POST /api/agent/feedback.
 *  - Provides a "Posture summary" quick-action that pre-fires the posture question.
 *  - Is role-aware: role is shown in the header; the backend enforces per-role scoping.
 */

import { useState, useRef, useEffect, useCallback } from 'react'
import {
  ChatBubbleOvalLeftEllipsisIcon,
  XMarkIcon,
  PaperAirplaneIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  BoltIcon,
  TrashIcon,
} from '@heroicons/react/24/outline'
import {
  HandThumbUpIcon,
  HandThumbDownIcon,
} from '@heroicons/react/24/outline'
import { agentChat, agentFeedback } from '../api/client'
import { useAuth } from '../context/AuthContext'

// ── Constants ─────────────────────────────────────────────────────────────────

const POSTURE_Q =
  "What's our overall security posture right now, and where should we focus?"

/** Accent colour per tool name (mirrors the registry). */
const TOOL_COLOR = {
  get_metrics:           '#ffc40d',
  get_sla_compliance:    '#ffc40d',
  list_jobs:             '#4e8faf',
  get_job_detail:        '#4e8faf',
  search_cves:           '#e05252',
  get_enrichment_status: '#9b6dff',
  get_threat_alerts:     '#e05252',
  get_risk_acceptances:  '#4eaf7c',
  query_controls:        '#4eaf7c',
  search_knowledge:      '#9b6dff',
}

const DEFAULT_COLOR = '#888888'

// ── Sub-components ────────────────────────────────────────────────────────────

/** Collapsible tool-call trace shown under each assistant message. */
function ToolTrace({ tools }) {
  const [open, setOpen] = useState(false)
  if (!tools?.length) return null

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          background: 'none', border: 'none', padding: 0, cursor: 'pointer',
          fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
          color: 'var(--muted)',
        }}
      >
        {open
          ? <ChevronDownIcon  style={{ width: 10, height: 10 }} />
          : <ChevronRightIcon style={{ width: 10, height: 10 }} />}
        {tools.length} tool{tools.length !== 1 ? 's' : ''} called
      </button>

      {open && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
          {tools.map((tc, i) => {
            const col = TOOL_COLOR[tc.name] ?? DEFAULT_COLOR
            return (
              <span
                key={i}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  padding: '2px 8px', borderRadius: 4,
                  background: col + '18',
                  border: `1px solid ${col}44`,
                  color: col,
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                }}
                title={tc.ok ? 'ok' : 'error'}
              >
                <span
                  style={{
                    width: 5, height: 5, borderRadius: '50%',
                    background: tc.ok ? '#4eaf7c' : '#e05252',
                    flexShrink: 0,
                  }}
                />
                {tc.name}
              </span>
            )
          })}
        </div>
      )}
    </div>
  )
}

/** Collapsible RAG citation cards shown when search_knowledge was called. */
function Citations({ contexts }) {
  const [open, setOpen] = useState(false)
  if (!contexts?.length) return null

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          background: 'none', border: 'none', padding: 0, cursor: 'pointer',
          fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
          color: 'var(--muted)',
        }}
      >
        {open
          ? <ChevronDownIcon  style={{ width: 10, height: 10 }} />
          : <ChevronRightIcon style={{ width: 10, height: 10 }} />}
        {contexts.length} source{contexts.length !== 1 ? 's' : ''}
      </button>

      {open && (
        <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {contexts.slice(0, 4).map((ctx, i) => {
            const text   = typeof ctx === 'string' ? ctx : (ctx?.text ?? '')
            const source = typeof ctx === 'object'
              ? (ctx?.source ?? ctx?.metadata?.source ?? null)
              : null

            return (
              <div
                key={i}
                style={{
                  borderRadius: 6, padding: '8px 10px', fontSize: 11,
                  background: 'rgba(155, 109, 255, 0.07)',
                  border: '1px solid rgba(155, 109, 255, 0.22)',
                }}
              >
                {source && (
                  <div
                    style={{
                      fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
                      color: '#9b6dff', marginBottom: 4, textTransform: 'uppercase',
                      letterSpacing: '0.1em',
                    }}
                  >
                    {source}
                  </div>
                )}
                <p style={{ margin: 0, color: 'var(--muted)', lineHeight: 1.55 }}>
                  {text.length > 220 ? text.slice(0, 220) + '…' : text}
                </p>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

/** A single assistant message bubble with trace, citations, meta, and feedback. */
function AssistantBubble({ msg, feedbackSent, onFeedback }) {
  // Render answer — split on newlines for readability
  const lines = (msg.content ?? '').split('\n')

  return (
    <div
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 12,
        padding: '10px 14px',
        maxWidth: '95%',
      }}
    >
      {/* Answer text */}
      <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.6 }}>
        {lines.map((line, i) => (
          <span key={i}>
            {line}
            {i < lines.length - 1 && <br />}
          </span>
        ))}
      </div>

      {/* Tool trace */}
      <ToolTrace tools={msg.data?.tools_called} />

      {/* RAG citations */}
      <Citations contexts={msg.data?.contexts} />

      {/* Inference meta */}
      {(msg.data?.mode || msg.data?.iterations) && (
        <div
          style={{
            marginTop: 6,
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
            color: 'var(--muted)', opacity: 0.55,
          }}
        >
          {msg.data.mode}
          {msg.data.iterations != null && ` · ${msg.data.iterations} iter${msg.data.iterations !== 1 ? 's' : ''}`}
          {msg.data.model && ` · ${msg.data.model.split(':')[0]}`}
        </div>
      )}

      {/* Feedback row */}
      <div
        style={{
          marginTop: 8, paddingTop: 8,
          borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: 6,
        }}
      >
        <span
          style={{
            fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
            color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.1em',
          }}
        >
          Feedback
        </span>

        {feedbackSent != null ? (
          <span style={{ fontSize: 11, color: 'var(--green)' }}>
            Thanks {feedbackSent === 1 ? '👍' : '👎'}
          </span>
        ) : (
          <>
            <button
              onClick={() => onFeedback(1)}
              title="Helpful"
              style={{
                background: 'none', border: 'none', padding: 2, cursor: 'pointer',
                color: 'var(--muted)', borderRadius: 4,
                display: 'flex', alignItems: 'center',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#4eaf7c')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--muted)')}
            >
              <HandThumbUpIcon style={{ width: 13, height: 13 }} />
            </button>
            <button
              onClick={() => onFeedback(-1)}
              title="Not helpful"
              style={{
                background: 'none', border: 'none', padding: 2, cursor: 'pointer',
                color: 'var(--muted)', borderRadius: 4,
                display: 'flex', alignItems: 'center',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#e05252')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--muted)')}
            >
              <HandThumbDownIcon style={{ width: 13, height: 13 }} />
            </button>
          </>
        )}
      </div>
    </div>
  )
}

/** Animated typing indicator while the agent is working. */
function TypingDots() {
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
      <div
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          padding: '10px 16px',
          display: 'flex', gap: 5, alignItems: 'center',
        }}
      >
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            style={{
              width: 6, height: 6, borderRadius: '50%',
              background: 'var(--amber)',
              display: 'inline-block',
              animation: 'vra-bounce 1s ease-in-out infinite',
              animationDelay: `${i * 160}ms`,
            }}
          />
        ))}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

let _msgId = 0
const nextId = () => ++_msgId

export default function AgentChat() {
  const { role } = useAuth()

  const [open,     setOpen]     = useState(false)
  const [messages, setMessages] = useState([])   // {id, role, content, data?}
  const [history,  setHistory]  = useState([])   // API history [{role, content}]
  const [input,    setInput]    = useState('')
  const [loading,  setLoading]  = useState(false)
  const [feedback, setFeedback] = useState({})   // msgId → 1|-1

  const bottomRef  = useRef(null)
  const inputRef   = useRef(null)
  const textareaRef = useRef(null)

  // Scroll to bottom on new content
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Focus input when panel opens
  useEffect(() => {
    if (open) {
      const t = setTimeout(() => inputRef.current?.focus(), 120)
      return () => clearTimeout(t)
    }
  }, [open])

  /** Send a question through the agent and append the reply to the message list. */
  const send = useCallback(
    async (question) => {
      const q = question.trim()
      if (!q || loading) return

      const userMsg = { id: nextId(), role: 'user', content: q }
      setMessages((prev) => [...prev, userMsg])
      setInput('')

      // Reset textarea height
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto'
      }

      setLoading(true)
      try {
        const res  = await agentChat({ question: q, history })
        const data = res.data?.data ?? res.data
        const answer = data?.answer ?? '(no answer)'

        const asstMsg = { id: nextId(), role: 'assistant', content: answer, data }
        setMessages((prev) => [...prev, asstMsg])
        setHistory((prev) => [
          ...prev,
          { role: 'user',      content: q },
          { role: 'assistant', content: answer },
        ])
      } catch (err) {
        const detail = err.response?.data?.detail ?? err.message ?? 'Unknown error'
        setMessages((prev) => [
          ...prev,
          { id: nextId(), role: 'assistant', content: `Error: ${detail}`, data: null },
        ])
      } finally {
        setLoading(false)
      }
    },
    [loading, history],
  )

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send(input)
    }
  }

  const handleTextareaInput = (e) => {
    // Auto-grow up to ~5 lines
    e.target.style.height = 'auto'
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px'
  }

  const handleFeedback = async (msgId, question, answer, rating) => {
    setFeedback((prev) => ({ ...prev, [msgId]: rating }))
    try {
      await agentFeedback({ feedback: rating, question, answer })
    } catch {
      /* silent — feedback is best-effort */
    }
  }

  const clearChat = () => {
    setMessages([])
    setHistory([])
    setFeedback({})
  }

  /** Find the user turn that preceded an assistant message at index idx. */
  const precedingQuestion = (idx) => {
    for (let i = idx - 1; i >= 0; i--) {
      if (messages[i].role === 'user') return messages[i].content
    }
    return ''
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Keyframe for typing dots — injected once */}
      <style>{`
        @keyframes vra-bounce {
          0%, 80%, 100% { transform: translateY(0);    opacity: 0.4; }
          40%            { transform: translateY(-5px); opacity: 1;   }
        }
      `}</style>

      {/* ── Floating Action Button ── */}
      <button
        onClick={() => setOpen((v) => !v)}
        title="VRA AI Assistant"
        style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
          width: 48, height: 48, borderRadius: '50%',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer',
          background: open ? 'var(--surface)' : 'var(--amber)',
          border: open ? '1px solid var(--border)' : 'none',
          color: open ? 'var(--muted)' : 'var(--black)',
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
          transition: 'background 0.2s, color 0.2s, border 0.2s',
        }}
      >
        {open
          ? <XMarkIcon style={{ width: 20, height: 20 }} />
          : <ChatBubbleOvalLeftEllipsisIcon style={{ width: 24, height: 24 }} />}
      </button>

      {/* ── Slide-in Panel ── */}
      <div
        style={{
          position: 'fixed',
          top: 24, right: 24, bottom: 24,
          width: 440,
          zIndex: 9998,
          display: 'flex', flexDirection: 'column',
          background: 'var(--black)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          boxShadow: '0 24px 64px rgba(0,0,0,0.75)',
          transform: open ? 'translateX(0)' : 'translateX(calc(100% + 40px))',
          transition: 'transform 0.28s cubic-bezier(0.4, 0, 0.2, 1)',
          overflow: 'hidden',
        }}
      >
        {/* ── Header ── */}
        <div
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '12px 16px', flexShrink: 0,
            borderBottom: '1px solid var(--border)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {/* Pulsing amber dot */}
            <span
              style={{
                width: 8, height: 8, borderRadius: '50%',
                background: 'var(--amber)',
                display: 'inline-block',
                boxShadow: '0 0 6px var(--amber)',
              }}
            />
            <span
              style={{
                fontFamily: 'Syne, sans-serif', fontWeight: 700, fontSize: 14,
                color: 'white',
              }}
            >
              VRA Assistant
            </span>
            {/* Role chip */}
            <span
              style={{
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
                padding: '2px 6px', borderRadius: 4,
                background: 'rgba(255,196,13,0.1)',
                border: '1px solid rgba(255,196,13,0.22)',
                color: 'var(--amber)',
                textTransform: 'uppercase', letterSpacing: '0.08em',
              }}
            >
              {role}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {messages.length > 0 && (
              <button
                onClick={clearChat}
                title="Clear conversation"
                style={{
                  background: 'none',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  padding: '3px 6px',
                  cursor: 'pointer',
                  color: 'var(--muted)',
                  display: 'flex', alignItems: 'center', gap: 4,
                  fontSize: 10,
                  fontFamily: '"IBM Plex Mono", monospace',
                }}
              >
                <TrashIcon style={{ width: 10, height: 10 }} />
                Clear
              </button>
            )}
            <button
              onClick={() => setOpen(false)}
              title="Close"
              style={{
                background: 'none', border: 'none',
                borderRadius: 6, padding: 4,
                cursor: 'pointer', color: 'var(--muted)',
                display: 'flex', alignItems: 'center',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
            >
              <XMarkIcon style={{ width: 16, height: 16 }} />
            </button>
          </div>
        </div>

        {/* ── Quick actions ── */}
        <div
          style={{
            padding: '8px 12px', flexShrink: 0,
            borderBottom: '1px solid var(--border)',
          }}
        >
          <button
            onClick={() => send(POSTURE_Q)}
            disabled={loading}
            style={{
              width: '100%',
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '7px 12px', borderRadius: 6,
              background: 'rgba(255,196,13,0.08)',
              border: '1px solid rgba(255,196,13,0.22)',
              color: 'var(--amber)',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.45 : 1,
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
              textTransform: 'uppercase', letterSpacing: '0.08em',
              transition: 'opacity 0.2s',
            }}
          >
            <BoltIcon style={{ width: 12, height: 12, flexShrink: 0 }} />
            Posture summary
          </button>
        </div>

        {/* ── Message list ── */}
        <div
          style={{
            flex: 1, overflowY: 'auto',
            padding: '16px 12px',
            display: 'flex', flexDirection: 'column', gap: 12,
          }}
        >
          {/* Empty state */}
          {messages.length === 0 && (
            <div
              style={{
                flex: 1, display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center',
                gap: 12, opacity: 0.45, padding: '0 16px',
              }}
            >
              <ChatBubbleOvalLeftEllipsisIcon
                style={{ width: 40, height: 40, color: 'var(--muted)' }}
              />
              <p
                style={{
                  fontSize: 13, color: 'var(--muted)',
                  textAlign: 'center', lineHeight: 1.6, margin: 0,
                }}
              >
                Ask anything about jobs, metrics, CVEs,<br />
                controls, or your security posture.
              </p>
            </div>
          )}

          {/* Messages */}
          {messages.map((msg, idx) =>
            msg.role === 'user' ? (
              /* User bubble — right-aligned amber */
              <div key={msg.id} style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <div
                  style={{
                    maxWidth: '80%',
                    padding: '8px 14px', borderRadius: 12,
                    background: 'rgba(255,196,13,0.12)',
                    border: '1px solid rgba(255,196,13,0.28)',
                    color: 'var(--text)', fontSize: 13, lineHeight: 1.5,
                  }}
                >
                  {msg.content}
                </div>
              </div>
            ) : (
              /* Assistant bubble — left-aligned dark */
              <div key={msg.id} style={{ display: 'flex', justifyContent: 'flex-start' }}>
                <AssistantBubble
                  msg={msg}
                  feedbackSent={feedback[msg.id] ?? null}
                  onFeedback={(rating) =>
                    handleFeedback(
                      msg.id,
                      precedingQuestion(idx),
                      msg.content,
                      rating,
                    )
                  }
                />
              </div>
            ),
          )}

          {/* Typing indicator */}
          {loading && <TypingDots />}

          <div ref={bottomRef} />
        </div>

        {/* ── Input area ── */}
        <div
          style={{
            flexShrink: 0, padding: '12px 12px 14px',
            borderTop: '1px solid var(--border)',
          }}
        >
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
            <textarea
              ref={(el) => { inputRef.current = el; textareaRef.current = el }}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              onInput={handleTextareaInput}
              rows={1}
              disabled={loading}
              placeholder="Ask a question… (Enter to send)"
              style={{
                flex: 1, resize: 'none',
                padding: '8px 12px', borderRadius: 8,
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                color: 'var(--text)', fontSize: 13,
                fontFamily: 'Inter, sans-serif', lineHeight: 1.5,
                outline: 'none', minHeight: 36, maxHeight: 120,
                transition: 'border-color 0.15s',
              }}
              onFocus={(e)  => (e.target.style.borderColor = 'rgba(255,196,13,0.4)')}
              onBlur={(e)   => (e.target.style.borderColor = 'var(--border)')}
            />
            <button
              onClick={() => send(input)}
              disabled={loading || !input.trim()}
              title="Send"
              style={{
                flexShrink: 0, width: 36, height: 36, borderRadius: 8,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                background: input.trim() && !loading ? 'var(--amber)' : 'var(--surface)',
                border: input.trim() && !loading ? 'none' : '1px solid var(--border)',
                color: input.trim() && !loading ? 'var(--black)' : 'var(--muted)',
                transition: 'background 0.15s, color 0.15s',
              }}
            >
              <PaperAirplaneIcon style={{ width: 16, height: 16 }} />
            </button>
          </div>
          <div
            style={{
              marginTop: 6,
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
              color: 'var(--muted)', opacity: 0.6,
            }}
          >
            Shift+Enter for newline · Read-only tools · Local model
          </div>
        </div>
      </div>
    </>
  )
}
