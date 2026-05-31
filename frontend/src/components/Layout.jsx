import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom'
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
  ExclamationTriangleIcon,
  ClipboardDocumentCheckIcon,
  Bars3Icon,
  XMarkIcon,
} from '@heroicons/react/24/outline'
import { fetchRescanStatus } from '../api/client'
import { useAuth } from '../context/AuthContext'
import AgentChat from './AgentChat'

// ── Nav groups ───────────────────────────────────────────────────────────────

const NAV_GROUPS = [
  {
    label: 'Main',
    items: [
      { to: '/',        label: 'Overview',  Icon: HomeIcon,                   end: true },
      { to: '/jobs',    label: 'Remediation Jobs', Icon: ClipboardDocumentListIcon },
      { to: '/metrics', label: 'Metrics',   Icon: ChartBarIcon },
      { to: '/tickets', label: 'Tickets',   Icon: TicketIcon },
    ],
  },
  {
    label: 'Security',
    items: [
      { to: '/assets',        label: 'Assets',        Icon: ServerStackIcon },
      { to: '/findings',      label: 'Findings',      Icon: ClipboardDocumentCheckIcon },
      { to: '/threat-alerts', label: 'Threat Alerts', Icon: ExclamationTriangleIcon },
      { to: '/risk-register', label: 'Risk Register', Icon: ShieldExclamationIcon },
      { to: '/enrichment',    label: 'Enrichment',    Icon: BoltIcon },
      { to: '/compliance',    label: 'Compliance',    Icon: ClipboardDocumentCheckIcon },
    ],
  },
  {
    label: 'Manage',
    items: [
      { to: '/upload',       label: 'Upload',        Icon: ArrowUpTrayIcon,
        roles: ['analyst', 'remediation_owner', 'admin'] },
      { to: '/findings/new', label: 'Manual Entry',  Icon: PencilSquareIcon,
        roles: ['analyst', 'remediation_owner', 'admin'] },
      { to: '/users',        label: 'Users',         Icon: UsersIcon,
        roles: ['admin'] },
    ],
  },
]

const ROLE_COLORS = {
  admin:             '#f87171',
  analyst:           '#60a5fa',
  remediation_owner: '#34d399',
  risk_owner:        '#a78bfa',
  auditor:           '#94a3b8',
}

// Map route → page title for topbar
const PAGE_TITLES = {
  '/':              'Overview',
  '/jobs':          'Remediation Jobs',
  '/metrics':       'Metrics',
  '/tickets':       'Tickets',
  '/assets':        'Assets',
  '/threat-alerts': 'Threat Alerts',
  '/risk-register': 'Risk Register',
  '/enrichment':    'Enrichment',
  '/compliance':    'Compliance',
  '/upload':        'Upload',
  '/findings/new':  'Manual Entry',
  '/findings':      'Findings',
  '/users':         'Users',
}

// ── VRA Hex logo ─────────────────────────────────────────────────────────────

function VraLogo() {
  return (
    <svg width="32" height="32" viewBox="0 0 48 48" fill="none">
      <polygon points="24,3 43,13.5 43,34.5 24,45 5,34.5 5,13.5"
        fill="none" stroke="#f5a623" strokeWidth="2.5" />
      <polygon points="24,11 36,18 36,32 24,39 12,32 12,18"
        fill="none" stroke="#f5a623" strokeWidth="1.5" strokeOpacity="0.55" />
      <polygon points="24,18 30,21.5 30,28.5 24,32 18,28.5 18,21.5"
        fill="rgba(245,166,35,0.15)" stroke="#f5a623" strokeWidth="1" strokeOpacity="0.35" />
    </svg>
  )
}

// ── NavItem ──────────────────────────────────────────────────────────────────

function NavItem({ to, label, Icon, end, alert }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `group flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150 relative ${
          isActive ? 'sb-nav-active' : 'sb-nav-idle'
        }`
      }
    >
      <Icon className="w-4 h-4 flex-shrink-0" />
      <span className="flex-1 truncate">{label}</span>
      {alert && (
        <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full animate-pulse"
          style={{ background: 'var(--red)' }} />
      )}
    </NavLink>
  )
}

// ── Layout ───────────────────────────────────────────────────────────────────

export default function Layout() {
  const { username, role, logout } = useAuth()
  const navigate  = useNavigate()
  const location  = useLocation()
  const [rescanStatus, setRescanStatus] = useState(null)
  const [sidebarOpen, setSidebarOpen]   = useState(true)

  useEffect(() => {
    const load = () =>
      fetchRescanStatus().then(r => setRescanStatus(r.data)).catch(() => setRescanStatus(null))
    load()
    const t = setInterval(load, 60_000)
    return () => clearInterval(t)
  }, [])

  const resurfaced = rescanStatus?.resurfaced_jobs ?? 0

  // Best-effort page title from current path
  const pageTitle = Object.entries(PAGE_TITLES)
    .sort((a, b) => b[0].length - a[0].length)
    .find(([path]) => location.pathname === path || location.pathname.startsWith(path + '/'))
    ?.[1] ?? 'VRA'

  return (
    <>
      {/* ── Global nav-item styles (injected once) ─────────────────────────── */}
      <style>{`
        .sb-nav-active {
          background: rgba(245,166,35,0.10);
          color: #f5a623;
          box-shadow: inset 3px 0 0 #f5a623;
          padding-left: calc(0.75rem + 1px);
        }
        .sb-nav-idle {
          color: #7a7d9c;
        }
        .sb-nav-idle:hover {
          background: rgba(245,166,35,0.06);
          color: #e2e0ed;
        }
      `}</style>

      <div className="flex min-h-screen">

        {/* ════ SIDEBAR ════════════════════════════════════════════════════════ */}
        <aside
          style={{
            width: 'var(--sidebar-w)',
            background: 'linear-gradient(180deg, #0d0f1e 0%, #0b0d17 100%)',
            borderRight: '1px solid var(--border)',
            position: 'fixed', top: 0, left: 0, height: '100vh',
            display: 'flex', flexDirection: 'column',
            zIndex: 50,
          }}
        >
          {/* Brand header */}
          <div style={{
            padding: '20px 16px 16px',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <VraLogo />
            <div>
              <div style={{
                fontFamily: 'Syne, sans-serif', fontWeight: 800,
                fontSize: 20, color: '#f5a623', letterSpacing: '-0.02em', lineHeight: 1,
              }}>
                VRA
              </div>
              <div style={{
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 8,
                color: 'var(--muted)', letterSpacing: '0.1em', marginTop: 3,
                textTransform: 'uppercase',
              }}>
                Remediation Assistant
              </div>
            </div>

            {/* Rescan indicator dot */}
            {resurfaced > 0 && (
              <div style={{ marginLeft: 'auto' }}
                title={`${resurfaced} resurfaced job${resurfaced > 1 ? 's' : ''}`}>
                <span style={{
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  width: 18, height: 18, borderRadius: '50%',
                  background: 'rgba(224,82,82,0.15)',
                  border: '1px solid rgba(224,82,82,0.4)',
                  color: 'var(--red)', fontSize: 9,
                  fontFamily: '"IBM Plex Mono", monospace', fontWeight: 700,
                }}>
                  {resurfaced > 9 ? '9+' : resurfaced}
                </span>
              </div>
            )}
          </div>

          {/* Navigation groups */}
          <nav style={{ flex: 1, overflowY: 'auto', padding: '12px 10px' }}>
            {NAV_GROUPS.map((group) => {
              const visible = group.items.filter(
                (item) => !item.roles || item.roles.includes(role)
              )
              if (!visible.length) return null
              return (
                <div key={group.label} style={{ marginBottom: 20 }}>
                  <div style={{
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
                    letterSpacing: '0.14em', textTransform: 'uppercase',
                    color: 'var(--muted)', opacity: 0.65,
                    padding: '0 12px', marginBottom: 6,
                  }}>
                    {group.label}
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {visible.map(({ to, label, Icon, end }) => (
                      <NavItem
                        key={to}
                        to={to}
                        label={label}
                        Icon={Icon}
                        end={end}
                        alert={to === '/threat-alerts' && resurfaced > 0}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
          </nav>

          {/* User footer */}
          <div style={{
            padding: '12px 10px',
            borderTop: '1px solid var(--border)',
          }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 12px', borderRadius: 10,
              background: 'var(--surface)', border: '1px solid var(--border)',
            }}>
              {/* Avatar circle */}
              <div style={{
                width: 30, height: 30, borderRadius: '50%', flexShrink: 0,
                background: `${ROLE_COLORS[role] ?? '#7a7d9c'}22`,
                border: `1.5px solid ${ROLE_COLORS[role] ?? '#7a7d9c'}55`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, fontWeight: 700,
                color: ROLE_COLORS[role] ?? '#7a7d9c',
              }}>
                {(username?.[0] ?? '?').toUpperCase()}
              </div>

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                  color: 'var(--text)', fontWeight: 600,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {username}
                </div>
                <div style={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
                  color: ROLE_COLORS[role] ?? 'var(--muted)',
                  textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 1,
                }}>
                  {role}
                </div>
              </div>

              <button
                onClick={() => { logout(); navigate('/login', { replace: true }) }}
                title="Sign out"
                style={{
                  background: 'none', border: 'none', padding: 4, cursor: 'pointer',
                  color: 'var(--muted)', borderRadius: 6, flexShrink: 0,
                  display: 'flex', alignItems: 'center',
                  transition: 'color 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.color = 'var(--red)'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--muted)'}
              >
                <ArrowRightStartOnRectangleIcon className="w-4 h-4" />
              </button>
            </div>
          </div>
        </aside>

        {/* ════ MAIN ═══════════════════════════════════════════════════════════ */}
        <div
          style={{
            marginLeft: 'var(--sidebar-w)',
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            minHeight: '100vh',
            background: 'var(--dark)',
          }}
        >
          {/* Topbar */}
          <header style={{
            height: 52,
            background: 'var(--black)',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center',
            padding: '0 28px',
            position: 'sticky', top: 0, zIndex: 40,
            gap: 12,
          }}>
            {/* Breadcrumb-style page title */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
              color: 'var(--muted)', letterSpacing: '0.06em',
            }}>
              <span style={{ color: 'var(--muted)', opacity: 0.5 }}>VRA</span>
              <span style={{ opacity: 0.4 }}>/</span>
              <span style={{ color: 'var(--text)', fontWeight: 600 }}>{pageTitle}</span>
            </div>

            <div style={{ flex: 1 }} />

            {/* Rescan alert pill */}
            {resurfaced > 0 && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '3px 10px', borderRadius: 20,
                background: 'rgba(224,82,82,0.1)',
                border: '1px solid rgba(224,82,82,0.3)',
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 10,
                color: 'var(--red)',
              }}>
                <span className="w-1.5 h-1.5 rounded-full animate-pulse inline-block"
                  style={{ background: 'var(--red)' }} />
                {resurfaced} resurfaced
              </div>
            )}

            {/* Env badge */}
            <div style={{
              padding: '2px 8px', borderRadius: 6,
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 9,
              color: 'var(--muted)', letterSpacing: '0.1em', textTransform: 'uppercase',
            }}>
              demo
            </div>
          </header>

          {/* Page content */}
          <main style={{ flex: 1, overflowY: 'auto' }}>
            <Outlet />
          </main>
        </div>
      </div>

      {/* ── Global AI assistant ── */}
      <AgentChat />
    </>
  )
}
