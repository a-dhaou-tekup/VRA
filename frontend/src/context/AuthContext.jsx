/**
 * AuthContext — manages login state, JWT token, username, and role.
 *
 * Persists to localStorage so the session survives a page refresh.
 * All axios calls pick up the token via the interceptor in api/client.js.
 */
import { createContext, useContext, useState, useCallback } from 'react'
import { loginUser } from '../api/client'

const AuthContext = createContext(null)

const STORAGE_KEY = 'vra_auth'

function loadStored() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(() => loadStored())

  const login = useCallback(async (username, password) => {
    // loginUser sends the form-encoded POST to /api/auth/login
    const res = await loginUser(username, password)
    const data = res.data
    const session = {
      token:    data.access_token,
      username: data.username,
      role:     data.role,
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
    setAuth(session)
    return session
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY)
    setAuth(null)
  }, [])

  const value = {
    user:            auth,                          // null if not logged in
    token:           auth?.token ?? null,
    username:        auth?.username ?? null,
    role:            auth?.role ?? null,
    isAuthenticated: auth !== null,
    login,
    logout,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
