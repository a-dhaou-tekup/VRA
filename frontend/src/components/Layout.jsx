import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  HomeIcon,
  ClipboardDocumentListIcon,
  ChartBarIcon,
  TicketIcon,
  ArrowUpTrayIcon,
  ServerStackIcon,
  PencilSquareIcon,
  BoltIcon,
  UsersIcon,
  ArrowRightStartOnRectangleIcon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/outline'
import { fetchRescanStatus } from '../api/client'
import { useAuth } from '../context/AuthContext'

function HexLogo() {
  return (
    <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <polygon
        points="24,3 43,13.5 43,34.5 24,45 5,34.5 5,13.5"
        fill="none"
        stroke="#FFC40D"
        strokeWidth="2"
      />
      <polygon
        points="24,9 38,17 38,33 24,41 10,33 10,17"
        fill="none"
        stroke="#FFC40D"
        strokeWidth="1.5"
        strokeOpacity="0.65"
      />
      <polygon
        points="24,15 33,20.5 33,31.5 24,37 15,31.5 15,20.5"
        fill="none"
        stroke="#FFC40D"
        strokeWidth="1"
        strokeOpacity="0.35"
      />
    </svg>
  )
}

// roles: undefined = visible to all authenticated users
// roles: [...]     = only visible if user.role is in the array
const NAV_ITEMS = [
  { to: '/',            label: 'Overview',     Icon: HomeIcon,                    end: true },
  { to: '/jobs',        label: 'Jobs',         Icon: ClipboardDocumentListIcon },
  { to: '/metrics',     label: 'Metrics',      Icon: ChartBarIcon },
  { to: '/tickets',     label: 'Tickets',      Icon: TicketIcon },
  { to: '/assets',      label: 'Assets',       Icon: ServerStackIcon },
  { to: '/upload',      label: 'Upload',       Icon: ArrowUpTrayIcon,
    roles: ['analyst', 'remediation_owner', 'admin'] },
  { to: '/findings/new',label: 'Manual Entry', Icon: PencilSquareIcon,
    roles: ['analyst', 'remediation_owner', 'admin'] },
  { to: '/enrichment',     label: 'Enrichment',    Icon: BoltIcon },
  { to: '/risk-register',  label: 'Risk Register', Icon: ShieldExclamationIcon },
  { to: '/users',          label: 'Users',         Icon: UsersIcon,
    roles: ['admin'] },
]

const ROLE_COLORS = {
  admin:             '#f87171',
  analyst:           '#60a5fa',
  remediation_owner: '#34d399',
  risk_owner:        '#a78bfa',
  auditor:           '#94a3b8',
}

export default function Layout() {
  const { username, role, logout } = useAuth()
  const navigate = useNavigate()
  const [rescanStatus, setRescanStatus] = useState(null)

  const loadRescanStatus = () => {
    fetchRescanStatus()
      .then((r) => setRescanStatus(r.data))
      .catch(() => setRescanStatus(null))
  }

  useEffect(() => {
    loadRescanStatus()
    const interval = setInterval(loadRescanStatus, 60_000)
    return () => clearInterval(interval)
  }, [])

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  const resurfaced = rescanStatus?.resurfaced_jobs ?? 0

  return (
    <div className="flex min-h-screen">
      {/* ── Sidebar ── */}
      <aside
        className="fixed top-0 left-0 h-screen flex flex-col z-50"
        style={{ width: 220, background: 'var(--black)', borderRight: '1px solid var(--border)' }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-6">
          <HexLogo />
          <div>
            <div
              className="leading-none"
              style={{
                fontFamily: 'Syne, sans-serif',
                fontWeight: 800,
                fontSize: 22,
                color: '#FFC40D',
              }}
            >
              VRA
            </div>
            <div
              className="mt-0.5"
              style={{
                fontFamily: '"IBM Plex Mono", monospace',
                fontSize: 9,
                color: 'var(--muted)',
                letterSpacing: '0.08em',
              }}
            >
              Remediation Assistant
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 space-y-0.5">
          {NAV_ITEMS.filter(item => !item.roles || item.roles.includes(role)).map(({ to, label, Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded text-sm transition-colors ${
                  isActive
                    ? 'text-[#FFC40D] border-l-2 border-[#FFC40D] bg-[rgba(255,196,13,0.07)] pl-[10px]'
                    : 'text-[#888] hover:text-[var(--text)] hover:bg-[var(--surface)]'
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span style={{ fontFamily: 'Inter, sans-serif', fontWeight: 500 }}>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Rescan status widget */}
        <div className="px-4 py-3 mx-3 mb-3 rounded" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
          <div className="mono-label mb-2">Re-scan Status</div>
          {rescanStatus === null ? (
            <div className="text-xs" style={{ color: 'var(--muted)' }}>Unavailable</div>
          ) : resurfaced === 0 ? (
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--green)' }}>
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: 'var(--green)' }} />
              All clear
            </div>
          ) : (
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--red)' }}>
              <span className="w-2 h-2 rounded-full flex-shrink-0 animate-pulse" style={{ background: 'var(--red)' }} />
              {resurfaced} resurfaced
            </div>
          )}
        </div>

        {/* User identity + logout */}
        <div className="px-4 pb-5">
          <div
            className="flex items-center justify-between px-3 py-2 rounded"
            style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
          >
            <div className="flex flex-col min-w-0">
              <span
                className="truncate"
                style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 12, color: 'var(--text)' }}
              >
                {username}
              </span>
              <span
                className="inline-flex items-center gap-1 mt-0.5"
                style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                         color: ROLE_COLORS[role] ?? 'var(--muted)' }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ background: ROLE_COLORS[role] ?? 'var(--muted)' }}
                />
                {role}
              </span>
            </div>
            <button
              onClick={handleLogout}
              title="Sign out"
              className="ml-2 p-1 rounded transition-colors hover:bg-[var(--surface-2)] flex-shrink-0"
              style={{ background: 'transparent', border: 'none', cursor: 'pointer',
                       color: 'var(--muted)' }}
            >
              <ArrowRightStartOnRectangleIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main content ── */}
      <main
        className="flex-1 overflow-y-auto min-h-screen"
        style={{ marginLeft: 220, background: 'var(--dark)' }}
      >
        <Outlet />
      </main>
    </div>
  )
}
