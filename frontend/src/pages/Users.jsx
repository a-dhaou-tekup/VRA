/**
 * Users page — admin-only user management.
 * Lists all users; allows creating new ones and toggling active/role.
 */
import { useEffect, useState } from 'react'
import { fetchUsers, createUser, updateUser, deleteUser } from '../api/client'
import { useAuth } from '../context/AuthContext'

const ROLES = ['admin', 'analyst', 'remediation_owner', 'risk_owner', 'auditor']

const ROLE_COLORS = {
  admin:             '#f87171',
  analyst:           '#60a5fa',
  remediation_owner: '#34d399',
  risk_owner:        '#a78bfa',
  auditor:           '#94a3b8',
}

function RoleBadge({ role }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium"
      style={{
        background: `${ROLE_COLORS[role] ?? '#888'}1a`,
        color: ROLE_COLORS[role] ?? '#888',
        fontFamily: '"IBM Plex Mono", monospace',
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: ROLE_COLORS[role] ?? '#888' }} />
      {role}
    </span>
  )
}

const inputCls = {
  padding: '7px 10px',
  borderRadius: 6,
  border: '1px solid var(--border)',
  background: 'var(--surface-2)',
  color: 'var(--text)',
  fontFamily: '"IBM Plex Mono", monospace',
  fontSize: 12,
  outline: 'none',
}

export default function Users() {
  const { username: me } = useAuth()
  const [users,   setUsers]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  // New-user form
  const [form, setForm] = useState({ username: '', password: '', role: 'analyst' })
  const [creating, setCreating] = useState(false)
  const [formError, setFormError] = useState('')

  async function load() {
    try {
      setLoading(true)
      const res = await fetchUsers()
      setUsers(res.data.data)
    } catch (err) {
      setError(err?.response?.data?.detail ?? 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleCreate(e) {
    e.preventDefault()
    setFormError('')
    setCreating(true)
    try {
      await createUser(form)
      setForm({ username: '', password: '', role: 'analyst' })
      await load()
    } catch (err) {
      setFormError(err?.response?.data?.detail ?? 'Failed to create user')
    } finally {
      setCreating(false)
    }
  }

  async function toggleActive(user) {
    try {
      await updateUser(user.id, { active: !user.active })
      await load()
    } catch (err) {
      alert(err?.response?.data?.detail ?? 'Failed to update user')
    }
  }

  async function changeRole(user, newRole) {
    try {
      await updateUser(user.id, { role: newRole })
      await load()
    } catch (err) {
      alert(err?.response?.data?.detail ?? 'Failed to update role')
    }
  }

  async function handleDelete(user) {
    if (!confirm(`Delete user '${user.username}'? This cannot be undone.`)) return
    try {
      await deleteUser(user.id)
      await load()
    } catch (err) {
      alert(err?.response?.data?.detail ?? 'Failed to delete user')
    }
  }

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <h1
        className="mb-1"
        style={{ fontFamily: 'Syne, sans-serif', fontWeight: 800, fontSize: 26, color: 'var(--text)' }}
      >
        User Management
      </h1>
      <p className="mb-8" style={{ color: 'var(--muted)', fontSize: 13 }}>
        Admin-only · manage accounts and role assignments.
      </p>

      {/* Create user form */}
      <div
        className="mb-8 p-5 rounded-lg"
        style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="mono-label mb-3">Create new user</div>
        <form onSubmit={handleCreate} className="flex gap-3 flex-wrap items-end">
          <div>
            <label className="block mono-label mb-1">Username</label>
            <input
              style={{ ...inputCls, width: 160 }}
              value={form.username}
              onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              placeholder="username"
              required
              minLength={3}
            />
          </div>
          <div>
            <label className="block mono-label mb-1">Password</label>
            <input
              type="password"
              style={{ ...inputCls, width: 160 }}
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              placeholder="min 8 chars"
              required
              minLength={8}
            />
          </div>
          <div>
            <label className="block mono-label mb-1">Role</label>
            <select
              style={{ ...inputCls, width: 180 }}
              value={form.role}
              onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
            >
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <button
            type="submit"
            disabled={creating}
            className="px-4 py-1.5 rounded text-sm font-semibold transition-opacity"
            style={{ background: '#FFC40D', color: '#000', border: 'none',
                     cursor: creating ? 'not-allowed' : 'pointer', opacity: creating ? 0.6 : 1 }}
          >
            {creating ? 'Creating…' : '+ Add user'}
          </button>
        </form>
        {formError && (
          <p className="mt-2 text-xs" style={{ color: '#f87171', fontFamily: '"IBM Plex Mono", monospace' }}>
            {formError}
          </p>
        )}
      </div>

      {/* User list */}
      {loading ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading users…</div>
      ) : error ? (
        <div style={{ color: '#f87171', fontSize: 13 }}>{error}</div>
      ) : (
        <div
          className="rounded-lg overflow-hidden"
          style={{ border: '1px solid var(--border)' }}
        >
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
                {['ID', 'Username', 'Role', 'Active', 'Created', 'Actions'].map(h => (
                  <th
                    key={h}
                    className="px-4 py-2.5 text-left"
                    style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                             color: 'var(--muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((u, i) => (
                <tr
                  key={u.id}
                  style={{
                    background: i % 2 === 0 ? 'var(--black)' : 'var(--surface)',
                    borderBottom: '1px solid var(--border)',
                    opacity: u.active ? 1 : 0.5,
                  }}
                >
                  <td className="px-4 py-2.5" style={{ color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 }}>
                    {u.id}
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--text)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 12 }}>
                    {u.username}
                    {u.username === me && (
                      <span className="ml-2" style={{ color: '#FFC40D', fontSize: 10 }}>(you)</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <select
                      value={u.role}
                      onChange={e => changeRole(u, e.target.value)}
                      disabled={u.username === me}
                      style={{
                        ...inputCls,
                        padding: '3px 6px',
                        fontSize: 11,
                        color: ROLE_COLORS[u.role] ?? 'var(--text)',
                      }}
                    >
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => toggleActive(u)}
                      disabled={u.username === me}
                      className="px-2 py-0.5 rounded text-xs font-medium transition-colors"
                      style={{
                        background: u.active ? 'rgba(52,211,153,0.12)' : 'rgba(239,68,68,0.12)',
                        color: u.active ? '#34d399' : '#f87171',
                        border: `1px solid ${u.active ? 'rgba(52,211,153,0.3)' : 'rgba(239,68,68,0.3)'}`,
                        fontFamily: '"IBM Plex Mono", monospace',
                        cursor: u.username === me ? 'not-allowed' : 'pointer',
                      }}
                    >
                      {u.active ? 'active' : 'inactive'}
                    </button>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace', fontSize: 11 }}>
                    {u.created_at ? u.created_at.slice(0, 10) : '—'}
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => handleDelete(u)}
                      disabled={u.username === me}
                      className="px-2 py-0.5 rounded text-xs transition-colors hover:bg-red-900/20"
                      style={{
                        color: u.username === me ? 'var(--muted)' : '#f87171',
                        fontFamily: '"IBM Plex Mono", monospace',
                        border: '1px solid transparent',
                        cursor: u.username === me ? 'not-allowed' : 'pointer',
                        background: 'transparent',
                      }}
                    >
                      delete
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
