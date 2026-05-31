import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const ROLE_COLORS = {
  admin:             '#f87171',
  analyst:           '#60a5fa',
  remediation_owner: '#34d399',
  risk_owner:        '#a78bfa',
  auditor:           '#94a3b8',
}

const DEMO_ACCOUNTS = [
  ['admin',             'Admin1234!'],
  ['analyst',           'Analyst1234!'],
  ['remediation_owner', 'RemOwner1234!'],
  ['risk_owner',        'RiskOwner1234!'],
  ['auditor',           'Auditor1234!'],
]

function HexLogo({ size = 52 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none">
      <polygon points="24,3 43,13.5 43,34.5 24,45 5,34.5 5,13.5"
        fill="none" stroke="#f5a623" strokeWidth="2.5" />
      <polygon points="24,11 36,18 36,32 24,39 12,32 12,18"
        fill="none" stroke="#f5a623" strokeWidth="1.5" strokeOpacity="0.5" />
      <polygon points="24,18 30,21.5 30,28.5 24,32 18,28.5 18,21.5"
        fill="rgba(245,166,35,0.12)" stroke="#f5a623" strokeWidth="1" strokeOpacity="0.3" />
    </svg>
  )
}

export default function Login() {
  const { login }  = useAuth()
  const navigate   = useNavigate()
  const location   = useLocation()
  const from       = location.state?.from?.pathname ?? '/'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err?.response?.data?.detail ?? 'Login failed — check your credentials.')
    } finally {
      setLoading(false)
    }
  }

  const inputStyle = {
    width: '100%', padding: '10px 14px',
    borderRadius: 8, border: '1px solid var(--border-2)',
    background: 'var(--surface-2)', color: 'var(--text)',
    fontFamily: '"IBM Plex Mono", monospace', fontSize: 13, outline: 'none',
    transition: 'border-color 0.15s',
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      minHeight: '100vh',
      background: 'radial-gradient(ellipse at 50% 0%, rgba(245,166,35,0.06) 0%, var(--dark) 60%)',
    }}>
      <div style={{
        width: 400,
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 16,
        overflow: 'hidden',
        boxShadow: '0 32px 80px rgba(0,0,0,0.6)',
      }}>
        {/* Brand header */}
        <div style={{
          padding: '36px 36px 28px',
          borderBottom: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12,
          background: 'linear-gradient(180deg, rgba(245,166,35,0.04) 0%, transparent 100%)',
        }}>
          <HexLogo />
          <div>
            <div style={{
              fontFamily: 'Syne, sans-serif', fontWeight: 800, fontSize: 28,
              color: '#f5a623', letterSpacing: '-0.02em', textAlign: 'center', lineHeight: 1,
            }}>VRA</div>
            <div style={{
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
              color: 'var(--muted)', letterSpacing: '0.12em', textTransform: 'uppercase',
              textAlign: 'center', marginTop: 5,
            }}>
              Vulnerability Remediation Assistant
            </div>
          </div>
        </div>

        {/* Form */}
        <div style={{ padding: '28px 32px' }}>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={{
                display: 'block', marginBottom: 6,
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                color: 'var(--muted)', letterSpacing: '0.1em', textTransform: 'uppercase',
              }}>Username</label>
              <input
                type="text" required autoFocus
                placeholder="e.g. analyst"
                value={username}
                onChange={e => setUsername(e.target.value)}
                style={inputStyle}
                onFocus={e  => (e.target.style.borderColor = 'rgba(245,166,35,0.5)')}
                onBlur={e   => (e.target.style.borderColor = 'var(--border-2)')}
              />
            </div>

            <div>
              <label style={{
                display: 'block', marginBottom: 6,
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                color: 'var(--muted)', letterSpacing: '0.1em', textTransform: 'uppercase',
              }}>Password</label>
              <input
                type="password" required
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={inputStyle}
                onFocus={e  => (e.target.style.borderColor = 'rgba(245,166,35,0.5)')}
                onBlur={e   => (e.target.style.borderColor = 'var(--border-2)')}
              />
            </div>

            {error && (
              <div style={{
                padding: '9px 14px', borderRadius: 8,
                background: 'rgba(224,82,82,0.1)', border: '1px solid rgba(224,82,82,0.28)',
                color: 'var(--red)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12,
              }}>
                {error}
              </div>
            )}

            <button
              type="submit" disabled={loading}
              style={{
                width: '100%', padding: '11px',
                borderRadius: 8, border: 'none', cursor: loading ? 'not-allowed' : 'pointer',
                background: loading ? 'var(--surface-3)' : '#f5a623',
                color: loading ? 'var(--muted)' : '#000',
                fontFamily: 'Inter, sans-serif', fontWeight: 700, fontSize: 14,
                transition: 'background 0.15s',
              }}
            >
              {loading ? 'Signing in…' : 'Sign in →'}
            </button>
          </form>

          {/* Demo accounts */}
          <div style={{ marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
            <div className="mono-label" style={{ marginBottom: 10 }}>Demo accounts</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {DEMO_ACCOUNTS.map(([u, p]) => (
                <button
                  key={u} type="button"
                  onClick={() => { setUsername(u); setPassword(p) }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '6px 10px', borderRadius: 7,
                    background: 'transparent', border: 'none', cursor: 'pointer',
                    textAlign: 'left', width: '100%',
                    transition: 'background 0.12s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <span style={{
                    width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
                    background: ROLE_COLORS[u] ?? '#888',
                  }} />
                  <span style={{
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--text)',
                    flex: 1,
                  }}>
                    {u}
                  </span>
                  <span style={{
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--muted)',
                  }}>
                    {p}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
