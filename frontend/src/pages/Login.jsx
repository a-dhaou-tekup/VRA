/**
 * Login page — styled to match the VRA dark theme.
 * On success, redirects to the page the user was trying to reach (or /).
 */
import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

function HexLogo() {
  return (
    <svg width="56" height="56" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <polygon points="24,3 43,13.5 43,34.5 24,45 5,34.5 5,13.5"
        fill="none" stroke="#FFC40D" strokeWidth="2" />
      <polygon points="24,9 38,17 38,33 24,41 10,33 10,17"
        fill="none" stroke="#FFC40D" strokeWidth="1.5" strokeOpacity="0.65" />
      <polygon points="24,15 33,20.5 33,31.5 24,37 15,31.5 15,20.5"
        fill="none" stroke="#FFC40D" strokeWidth="1" strokeOpacity="0.35" />
    </svg>
  )
}

const ROLE_COLORS = {
  admin:             '#f87171',
  analyst:           '#60a5fa',
  remediation_owner: '#34d399',
  risk_owner:        '#a78bfa',
  auditor:           '#94a3b8',
}

export default function Login() {
  const { login } = useAuth()
  const navigate  = useNavigate()
  const location  = useLocation()
  const from      = location.state?.from?.pathname ?? '/'

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
      const detail = err?.response?.data?.detail
      setError(detail ?? 'Login failed. Check your credentials.')
    } finally {
      setLoading(false)
    }
  }

  const inputStyle = {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 6,
    border: '1px solid var(--border)',
    background: 'var(--surface-2)',
    color: 'var(--text)',
    fontFamily: '"IBM Plex Mono", monospace',
    fontSize: 13,
    outline: 'none',
  }

  return (
    <div
      className="flex items-center justify-center min-h-screen"
      style={{ background: 'var(--dark)' }}
    >
      <div
        style={{
          width: 380,
          background: 'var(--black)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          padding: '40px 36px',
        }}
      >
        {/* Header */}
        <div className="flex flex-col items-center mb-8">
          <HexLogo />
          <div
            className="mt-4"
            style={{ fontFamily: 'Syne, sans-serif', fontWeight: 800, fontSize: 26, color: '#FFC40D' }}
          >
            VRA
          </div>
          <div
            style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                     color: 'var(--muted)', letterSpacing: '0.1em', marginTop: 2 }}
          >
            Vulnerability Remediation Assistant
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              className="block mb-1.5"
              style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                       color: 'var(--muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
            >
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="e.g. analyst"
              required
              autoFocus
              style={inputStyle}
            />
          </div>

          <div>
            <label
              className="block mb-1.5"
              style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                       color: 'var(--muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              style={inputStyle}
            />
          </div>

          {error && (
            <div
              className="px-3 py-2 rounded text-sm"
              style={{ background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.3)',
                       color: '#f87171', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded font-semibold text-sm transition-opacity"
            style={{
              background: '#FFC40D',
              color: '#000',
              fontFamily: 'Inter, sans-serif',
              opacity: loading ? 0.6 : 1,
              cursor: loading ? 'not-allowed' : 'pointer',
              border: 'none',
            }}
          >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        {/* Demo credential hints */}
        <div className="mt-6" style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
          <div
            className="mb-2"
            style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                     color: 'var(--muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
          >
            Demo accounts
          </div>
          <div className="space-y-1">
            {[
              ['admin',             'Admin1234!'],
              ['analyst',           'Analyst1234!'],
              ['remediation_owner', 'RemOwner1234!'],
              ['risk_owner',        'RiskOwner1234!'],
              ['auditor',           'Auditor1234!'],
            ].map(([u, p]) => (
              <button
                key={u}
                type="button"
                onClick={() => { setUsername(u); setPassword(p) }}
                className="flex items-center gap-2 w-full px-2 py-1 rounded text-left transition-colors hover:bg-[var(--surface)]"
                style={{ background: 'transparent', border: 'none', cursor: 'pointer' }}
              >
                <span
                  className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                  style={{ background: ROLE_COLORS[u] ?? '#888' }}
                />
                <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--text)' }}>
                  {u}
                </span>
                <span style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'var(--muted)', marginLeft: 'auto' }}>
                  {p}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
