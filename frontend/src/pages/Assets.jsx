import { useEffect, useState, useCallback } from 'react'
import {
  fetchAssets, createAsset, updateAsset, deleteAsset, bulkImportAssets,
  fetchFleetSummary, fetchAssetSoftware, addAssetSoftware,
  replaceAssetSoftware, deleteAssetSoftware, fetchAssetThreats,
  fetchThreatAlerts, classifyAssets,
} from '../api/client'
import { useAuth } from '../context/AuthContext'
import { useSortable, SortTh } from '../utils/sortable'

const CRITICALITY  = ['low', 'medium', 'high', 'critical']
const ENVIRONMENTS = ['production', 'staging', 'dev', 'test']

// ── Cascade dropdown taxonomy ──────────────────────────────────────────────────

const ASSET_TYPE_OPTIONS = [
  'workstation', 'laptop', 'server', 'network_device',
  'virtual_machine', 'container', 'cloud_instance', 'iot_device', 'mobile', 'other',
]

const PLATFORM_BY_TYPE = {
  workstation:     ['Windows', 'macOS', 'Linux', 'ChromeOS'],
  laptop:          ['Windows', 'macOS', 'Linux', 'ChromeOS'],
  server:          ['Windows Server', 'Linux', 'VMware ESXi', 'FreeBSD'],
  network_device:  ['Cisco IOS', 'Juniper JunOS', 'Palo Alto PAN-OS', 'Fortinet FortiOS', 'Generic'],
  virtual_machine: ['Windows', 'Linux', 'VMware', 'Other'],
  container:       ['Docker', 'Kubernetes'],
  cloud_instance:  ['AWS', 'Azure', 'GCP', 'Other'],
  iot_device:      ['Embedded Linux', 'RTOS', 'Other'],
  mobile:          ['iOS', 'Android'],
  other:           ['Other'],
}

const OS_BY_PLATFORM = {
  'Windows':           ['Windows 11', 'Windows 10', 'Windows 8.1', 'Windows 7'],
  'macOS':             ['macOS Sonoma 14', 'macOS Ventura 13', 'macOS Monterey 12'],
  'Linux':             ['Ubuntu 24.04 LTS', 'Ubuntu 22.04 LTS', 'Ubuntu 20.04 LTS', 'RHEL 9', 'RHEL 8', 'Debian 12', 'Debian 11', 'CentOS 7', 'AlmaLinux 9', 'Fedora 40'],
  'ChromeOS':          ['ChromeOS (latest)'],
  'Windows Server':    ['Windows Server 2022', 'Windows Server 2019', 'Windows Server 2016', 'Windows Server 2012 R2'],
  'VMware ESXi':       ['ESXi 8.0', 'ESXi 7.0', 'ESXi 6.7'],
  'FreeBSD':           ['FreeBSD 14', 'FreeBSD 13'],
  'Cisco IOS':         ['IOS XE', 'IOS XR', 'NX-OS'],
  'Juniper JunOS':     ['JunOS 22.x', 'JunOS 21.x'],
  'Palo Alto PAN-OS':  ['PAN-OS 11.x', 'PAN-OS 10.x'],
  'Fortinet FortiOS':  ['FortiOS 7.x', 'FortiOS 6.x'],
  'Generic':           ['Other'],
  'VMware':            ['Windows VM', 'Linux VM'],
  'Other':             ['Other'],
  'Docker':            ['Docker CE', 'Docker EE'],
  'Kubernetes':        ['Kubernetes 1.30+', 'Kubernetes 1.29', 'Kubernetes 1.28'],
  'AWS':               ['Amazon Linux 2023', 'Amazon Linux 2', 'Windows Server (AWS)'],
  'Azure':             ['Azure (Windows)', 'Azure (Linux)'],
  'GCP':               ['GCP (Linux)', 'GCP (Windows)'],
  'Embedded Linux':    ['Embedded Linux'],
  'RTOS':              ['FreeRTOS', 'VxWorks', 'Zephyr'],
  'iOS':               ['iOS 17', 'iOS 16', 'iOS 15'],
  'Android':           ['Android 14', 'Android 13', 'Android 12'],
}

const EMPTY_FORM = {
  hostname: '', ip_address: '', business_unit: 'IT', business_owner: '',
  criticality: 'medium', internet_exposed: false, environment: 'production',
  asset_type: '', platform: '', os_version: '', site: '', owning_team: '',
}

// ── Badges ────────────────────────────────────────────────────────────────────

function CritBadge({ value }) {
  const map = {
    low:      'text-[var(--green)]  bg-[rgba(78,175,124,0.1)]  border-[rgba(78,175,124,0.3)]',
    medium:   'text-[var(--blue)]   bg-[rgba(78,143,175,0.1)]  border-[rgba(78,143,175,0.3)]',
    high:     'text-[var(--amber)]  bg-[rgba(255,196,13,0.1)]  border-[rgba(255,196,13,0.3)]',
    critical: 'text-[var(--red)]    bg-[rgba(224,82,82,0.1)]   border-[rgba(224,82,82,0.3)]',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono uppercase tracking-wider border ${map[value] || map.medium}`}>
      {value}
    </span>
  )
}

// ── Fleet summary strip ───────────────────────────────────────────────────────

function FleetSummary({ summary, canWrite, onClassify, classifying }) {
  if (!summary) return null

  return (
    <div className="space-y-3 mb-6">
      {/* Row 1 — key counts */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Assets',     value: summary.total },
          { label: 'Internet Exposed', value: summary.internet_exposed, warn: true },
          { label: 'Environments',     value: summary.by_environment?.length ?? 0 },
          { label: 'Business Units',   value: summary.by_business_unit?.length ?? 0 },
        ].map(({ label, value, warn }) => (
          <div key={label} className="vra-card py-3 text-center">
            <div className="text-2xl font-bold font-mono"
              style={{ color: warn && value > 0 ? 'var(--amber)' : 'var(--text)' }}>
              {value ?? 0}
            </div>
            <div className="mono-label mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Row 2 — asset type + platform breakdown pills */}
      {((summary.by_asset_type?.length ?? 0) + (summary.by_platform?.length ?? 0)) > 0 && (
        <div className="vra-card flex flex-wrap gap-4">
          {summary.by_asset_type?.length > 0 && (
            <div className="flex-1">
              <div className="mono-label mb-2">Asset Types</div>
              <div className="flex flex-wrap gap-2">
                {summary.by_asset_type.map(({ asset_type, cnt }) => (
                  <span key={asset_type}
                    className="px-2 py-0.5 rounded text-xs font-mono"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text)' }}>
                    {asset_type} <span style={{ color: 'var(--amber)' }}>{cnt}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
          {summary.by_platform?.length > 0 && (
            <div className="flex-1">
              <div className="mono-label mb-2">Platforms</div>
              <div className="flex flex-wrap gap-2">
                {summary.by_platform.map(({ platform, cnt }) => (
                  <span key={platform}
                    className="px-2 py-0.5 rounded text-xs font-mono"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text)' }}>
                    {platform} <span style={{ color: 'var(--blue)' }}>{cnt}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
          {canWrite && (
            <div className="flex items-end">
              <button
                onClick={onClassify}
                disabled={classifying}
                className="px-3 py-1.5 rounded text-xs font-semibold border transition"
                style={{ borderColor: 'var(--border)', color: 'var(--amber)', background: 'var(--surface-2)' }}
              >
                {classifying ? 'Classifying…' : '↺ Re-classify'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Software panel (expandable per asset row) ─────────────────────────────────

function SoftwarePanel({ assetId, canWrite, onKevClick }) {
  const [items, setItems]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [newProd, setNewProd] = useState('')
  const [newVer, setNewVer]   = useState('')
  const [newVendor, setNewVendor] = useState('')
  const [newCpe, setNewCpe]   = useState('')
  const [threats, setThreats] = useState([])

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([
      fetchAssetSoftware(assetId),
      fetchAssetThreats(assetId),
    ]).then(([swRes, thrRes]) => {
      setItems(swRes.data?.data ?? [])
      setThreats(thrRes.data?.data ?? [])
    }).finally(() => setLoading(false))
  }, [assetId])

  useEffect(() => { load() }, [load])

  const addOne = async () => {
    if (!newProd.trim()) return
    await addAssetSoftware(assetId, {
      product: newProd.trim(), version: newVer.trim() || null,
      vendor: newVendor.trim() || null, cpe: newCpe.trim() || null,
    })
    setNewProd(''); setNewVer(''); setNewVendor(''); setNewCpe('')
    load()
  }

  const removeOne = async (swId) => {
    await deleteAssetSoftware(assetId, swId)
    load()
  }

  const inputCls = "px-2 py-1 rounded text-xs bg-[var(--surface)] border border-[var(--border)] text-white font-mono"
  const alertMap = Object.fromEntries(threats.map(t => [t.cve_id, t]))

  if (loading) return <div className="px-4 py-3 text-xs text-[var(--muted)]">Loading software…</div>

  return (
    <div className="px-4 pt-2 pb-4 bg-[var(--surface)] border-t border-[var(--border)]">
      {/* Threat summary */}
      {threats.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-3">
          {threats.filter(t => t.is_kev).length > 0 && (
            <button
              onClick={() => onKevClick?.(assetId)}
              className="px-2 py-0.5 rounded text-xs font-mono font-bold transition-opacity hover:opacity-80"
              style={{ background:'rgba(224,82,82,0.15)', color:'var(--red)', border:'1px solid rgba(224,82,82,0.4)', cursor:'pointer' }}>
              🔴 {threats.filter(t => t.is_kev).length} KEV match{threats.filter(t=>t.is_kev).length>1?'es':''}
            </button>
          )}
          {threats.filter(t => !t.is_kev && t.alert_type==='high_epss').length > 0 && (
            <span className="px-2 py-0.5 rounded text-xs font-mono"
              style={{ background:'rgba(255,196,13,0.12)', color:'var(--amber)', border:'1px solid rgba(255,196,13,0.3)' }}>
              ⚡ {threats.filter(t=>t.alert_type==='high_epss').length} High-EPSS
            </span>
          )}
          {threats.filter(t => t.alert_type==='cpe_match' && !t.is_kev).length > 0 && (
            <span className="px-2 py-0.5 rounded text-xs font-mono"
              style={{ background:'rgba(78,143,175,0.12)', color:'var(--blue)', border:'1px solid rgba(78,143,175,0.3)' }}>
              🔍 {threats.filter(t=>t.alert_type==='cpe_match'&&!t.is_kev).length} CPE match
            </span>
          )}
        </div>
      )}

      {/* Software table */}
      <div className="mono-label mb-2">Installed Software ({items?.length ?? 0})</div>
      {!items || items.length === 0 ? (
        <p className="text-xs text-[var(--muted)] mb-3">No software recorded.</p>
      ) : (
        <table className="w-full text-xs mb-3">
          <thead>
            <tr className="text-[var(--muted)]">
              <th className="text-left pb-1">Product</th>
              <th className="text-left pb-1">Version</th>
              <th className="text-left pb-1">Vendor</th>
              <th className="text-left pb-1">CPE</th>
              <th className="text-left pb-1">Alerts</th>
              {canWrite && <th></th>}
            </tr>
          </thead>
          <tbody>
            {items.map(sw => {
              // Find alert for any CVE matching this product
              const relatedAlerts = threats.filter(t =>
                t.matched_product?.toLowerCase() === sw.product?.toLowerCase()
              )
              const hasKev = relatedAlerts.some(t => t.is_kev)
              return (
                <tr key={sw.id} className="border-t border-[var(--border)]">
                  <td className="py-1 pr-3 text-white font-mono">{sw.product}</td>
                  <td className="py-1 pr-3 text-[var(--muted)]">{sw.version || '—'}</td>
                  <td className="py-1 pr-3 text-[var(--muted)]">{sw.vendor || '—'}</td>
                  <td className="py-1 pr-3 font-mono text-[10px] text-[var(--muted)] max-w-[200px] truncate" title={sw.cpe}>{sw.cpe || '—'}</td>
                  <td className="py-1 pr-3">
                    {relatedAlerts.length > 0 ? (
                      <span style={{ color: hasKev ? 'var(--red)' : 'var(--amber)' }}>
                        {hasKev ? '🔴' : '⚡'} {relatedAlerts.length} alert{relatedAlerts.length>1?'s':''}
                      </span>
                    ) : <span className="text-[var(--muted)]">—</span>}
                  </td>
                  {canWrite && (
                    <td className="py-1">
                      <button onClick={() => removeOne(sw.id)} className="text-[var(--red)] hover:underline text-[10px]">remove</button>
                    </td>
                  )}
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      {/* Add software form */}
      {canWrite && (
        <div className="flex flex-wrap gap-2 items-end">
          <div>
            <div className="text-[10px] text-[var(--muted)] mb-1">Product *</div>
            <input className={inputCls} placeholder="e.g. OpenSSL" value={newProd} onChange={e=>setNewProd(e.target.value)} />
          </div>
          <div>
            <div className="text-[10px] text-[var(--muted)] mb-1">Version</div>
            <input className={inputCls} placeholder="e.g. 3.0.2" value={newVer} onChange={e=>setNewVer(e.target.value)} />
          </div>
          <div>
            <div className="text-[10px] text-[var(--muted)] mb-1">Vendor</div>
            <input className={inputCls} placeholder="e.g. OpenSSL Foundation" value={newVendor} onChange={e=>setNewVendor(e.target.value)} />
          </div>
          <div>
            <div className="text-[10px] text-[var(--muted)] mb-1">CPE (optional)</div>
            <input className={`${inputCls} w-56`} placeholder="cpe:2.3:a:openssl:openssl:3.0.2:*…" value={newCpe} onChange={e=>setNewCpe(e.target.value)} />
          </div>
          <button onClick={addOne} disabled={!newProd.trim()}
            className="px-3 py-1 rounded text-xs font-semibold bg-[var(--amber)] text-black disabled:opacity-40">
            + Add
          </button>
        </div>
      )}
    </div>
  )
}

// ── KEV Matches tab ───────────────────────────────────────────────────────────

function KevMatchesTab({ assets, focusAssetId }) {
  const [alerts,  setAlerts]  = useState([])
  const [loading, setLoading] = useState(true)

  // Filter state — all 11 columns
  const [fSearch,   setFSearch]   = useState('')
  const [fType,     setFType]     = useState('')
  const [fPlatform, setFPlatform] = useState('')
  const [fOs,       setFOs]       = useState('')
  const [fSite,     setFSite]     = useState('')
  const [fTeam,     setFTeam]     = useState('')
  const [fBu,       setFBu]       = useState('')
  const [fCrit,     setFCrit]     = useState('')
  const [fExposed,  setFExposed]  = useState('')
  const [fEnv,      setFEnv]      = useState('')

  // Pre-fill search when arriving from a badge click
  useEffect(() => {
    if (focusAssetId) {
      const a = assets.find(x => x.asset_id === focusAssetId)
      if (a) setFSearch(a.hostname)
    }
  }, [focusAssetId, assets])

  useEffect(() => {
    fetchThreatAlerts({ alert_type: 'kev_match', limit: 2000 })
      .then(r => setAlerts(r.data?.data ?? []))
      .finally(() => setLoading(false))
  }, [])

  // Build asset lookup and group KEV alerts by asset_id
  const assetMap = Object.fromEntries(assets.map(a => [a.asset_id, a]))
  const kevByAsset = {}
  alerts.forEach(alert => {
    if (!alert.is_kev && alert.alert_type !== 'kev_match') return
    const id = alert.asset_id
    if (!kevByAsset[id]) kevByAsset[id] = []
    kevByAsset[id].push(alert)
  })

  // Full rows: merge alert asset fields with the richer asset record
  let rows = Object.entries(kevByAsset).map(([assetId, kevAlerts]) => {
    const asset = assetMap[assetId] ?? {}
    const first = kevAlerts[0]
    return {
      asset_id:        assetId,
      hostname:        asset.hostname        ?? first.hostname    ?? '—',
      ip_address:      asset.ip_address      ?? first.ip_address  ?? '—',
      asset_type:      asset.asset_type      ?? '—',
      platform:        asset.platform        ?? '—',
      os_version:      asset.os_version      ?? '—',
      site:            asset.site            ?? '—',
      owning_team:     asset.owning_team     ?? '—',
      business_unit:   asset.business_unit   ?? first.business_unit ?? '—',
      criticality:     asset.criticality     ?? '—',
      internet_exposed: asset.internet_exposed ?? false,
      environment:     asset.environment     ?? first.environment ?? '—',
      kev_alerts:      kevAlerts,
    }
  })

  // Apply filters
  const q = fSearch.toLowerCase()
  if (q)        rows = rows.filter(r => r.hostname.toLowerCase().includes(q) || r.ip_address.includes(q))
  if (fType)    rows = rows.filter(r => r.asset_type === fType)
  if (fPlatform)rows = rows.filter(r => r.platform?.toLowerCase().includes(fPlatform.toLowerCase()))
  if (fOs)      rows = rows.filter(r => r.os_version?.toLowerCase().includes(fOs.toLowerCase()))
  if (fSite)    rows = rows.filter(r => r.site?.toLowerCase().includes(fSite.toLowerCase()))
  if (fTeam)    rows = rows.filter(r => r.owning_team?.toLowerCase().includes(fTeam.toLowerCase()))
  // Apply column sort to KEV rows
  if (kevSort.col) {
    rows = [...rows].sort((a, b) => {
      const cmp = String(a[kevSort.col] ?? '').localeCompare(String(b[kevSort.col] ?? ''), undefined, { numeric: true, sensitivity: 'base' })
      return kevSort.dir === 'asc' ? cmp : -cmp
    })
  }
  if (fBu)      rows = rows.filter(r => r.business_unit?.toLowerCase().includes(fBu.toLowerCase()))
  if (fCrit)    rows = rows.filter(r => r.criticality === fCrit)
  if (fExposed === 'yes') rows = rows.filter(r => r.internet_exposed)
  if (fExposed === 'no')  rows = rows.filter(r => !r.internet_exposed)
  if (fEnv)     rows = rows.filter(r => r.environment === fEnv)

  // Sort: most KEV matches first, then by criticality
  const CRIT_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
  rows.sort((a, b) =>
    b.kev_alerts.length - a.kev_alerts.length ||
    (CRIT_ORDER[a.criticality] ?? 4) - (CRIT_ORDER[b.criticality] ?? 4)
  )

  const hasFilter = fSearch||fType||fPlatform||fOs||fSite||fTeam||fBu||fCrit||fExposed||fEnv
  const clearAll  = () => {
    setFSearch(''); setFType(''); setFPlatform(''); setFOs(''); setFSite('')
    setFTeam(''); setFBu(''); setFCrit(''); setFExposed(''); setFEnv('')
  }

  const selCls  = "px-2 py-1.5 rounded text-xs bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono"
  const inpCls  = "px-2 py-1.5 rounded text-xs bg-[var(--surface-2)] border border-[var(--border)] text-white"

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="vra-card space-y-3">
        <div className="flex items-center justify-between">
          <span className="mono-label">Filters</span>
          {hasFilter && (
            <button onClick={clearAll} className="text-xs text-[var(--amber)] hover:underline">Clear all</button>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <input className={inpCls + ' w-44'} placeholder="Hostname or IP…"
            value={fSearch} onChange={e => setFSearch(e.target.value)} />
          <select className={selCls} value={fType} onChange={e => setFType(e.target.value)}>
            <option value="">All types</option>
            {ASSET_TYPE_OPTIONS.map(t => <option key={t} value={t}>{t.replace('_',' ')}</option>)}
          </select>
          <input className={inpCls + ' w-28'} placeholder="Platform…"
            value={fPlatform} onChange={e => setFPlatform(e.target.value)} />
          <input className={inpCls + ' w-32'} placeholder="OS version…"
            value={fOs} onChange={e => setFOs(e.target.value)} />
          <input className={inpCls + ' w-28'} placeholder="Site…"
            value={fSite} onChange={e => setFSite(e.target.value)} />
          <input className={inpCls + ' w-28'} placeholder="Team…"
            value={fTeam} onChange={e => setFTeam(e.target.value)} />
          <input className={inpCls + ' w-24'} placeholder="BU…"
            value={fBu} onChange={e => setFBu(e.target.value)} />
          <select className={selCls} value={fCrit} onChange={e => setFCrit(e.target.value)}>
            <option value="">All criticalities</option>
            {CRITICALITY.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className={selCls} value={fExposed} onChange={e => setFExposed(e.target.value)}>
            <option value="">All exposed</option>
            <option value="yes">Exposed</option>
            <option value="no">Not exposed</option>
          </select>
          <select className={selCls} value={fEnv} onChange={e => setFEnv(e.target.value)}>
            <option value="">All envs</option>
            {ENVIRONMENTS.map(e => <option key={e} value={e}>{e}</option>)}
          </select>
        </div>
      </div>

      {/* Summary */}
      <div className="flex items-center gap-3">
        <span className="text-xs" style={{ color: 'var(--muted)' }}>
          {loading ? 'Loading…' : `${rows.length} asset${rows.length !== 1 ? 's' : ''} with KEV matches`}
        </span>
        {loading && (
          <div className="w-4 h-4 rounded-full border-2 animate-spin"
            style={{ borderColor: 'var(--border)', borderTopColor: 'var(--amber)' }} />
        )}
      </div>

      {/* Table */}
      {!loading && (
        <div className="rounded border border-[var(--border)] overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-[var(--surface-2)] mono-label text-[var(--muted)]">
                {[['hostname','Hostname'],['ip_address','IP'],['asset_type','Type'],['platform','Platform'],
                  ['os_version','OS Version'],['site','Site'],['owning_team','Team'],
                  ['business_unit','BU'],['criticality','Criticality'],['environment','Env']].map(([c,l]) => (
                  <SortTh key={c} col={c} sortCol={kevSort.col} sortDir={kevSort.dir} onSort={toggleKevSort}
                    className="px-4 py-3">{l}</SortTh>
                ))}
                <th className="px-4 py-3 text-left">Exposed</th>
                <th className="px-4 py-3 text-left">KEV Matches</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={12} className="px-4 py-10 text-center text-xs" style={{ color: 'var(--muted)' }}>
                    {hasFilter ? 'No assets match the active filters.' : 'No KEV matches found.'}
                  </td>
                </tr>
              ) : rows.map(r => (
                <tr key={r.asset_id} className="border-t border-[var(--border)] hover:bg-[var(--surface)]">
                  <td className="px-4 py-2 font-mono text-xs text-white">{r.hostname}</td>
                  <td className="px-4 py-2 font-mono text-xs" style={{ color: 'var(--muted)' }}>{r.ip_address}</td>
                  <td className="px-4 py-2 text-xs" style={{ color: 'var(--muted)' }}>{r.asset_type !== '—' ? r.asset_type.replace('_',' ') : '—'}</td>
                  <td className="px-4 py-2 text-xs" style={{ color: 'var(--muted)' }}>{r.platform}</td>
                  <td className="px-4 py-2 text-xs" style={{ color: 'var(--muted)' }}>{r.os_version}</td>
                  <td className="px-4 py-2 text-xs" style={{ color: 'var(--muted)' }}>{r.site}</td>
                  <td className="px-4 py-2 text-xs" style={{ color: 'var(--muted)' }}>{r.owning_team}</td>
                  <td className="px-4 py-2 text-xs">{r.business_unit}</td>
                  <td className="px-4 py-2"><CritBadge value={r.criticality !== '—' ? r.criticality : 'low'} /></td>
                  <td className="px-4 py-2 text-xs">
                    {r.internet_exposed
                      ? <span style={{ color: 'var(--red)' }}>● yes</span>
                      : <span style={{ color: 'var(--muted)' }}>no</span>}
                  </td>
                  <td className="px-4 py-2 text-xs" style={{ color: 'var(--muted)' }}>{r.environment}</td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {r.kev_alerts.map((alert, i) => (
                        <span key={i}
                          className="px-1.5 py-0.5 rounded font-mono text-[10px]"
                          style={{ background: 'rgba(224,82,82,0.15)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.35)' }}
                          title={`${alert.matched_product ?? ''} · ${alert.severity ?? ''}`}>
                          {alert.cve_id}
                        </span>
                      ))}
                    </div>
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

// ── Main component ────────────────────────────────────────────────────────────

export default function Assets() {
  const { role } = useAuth()
  const canWrite  = ['analyst','remediation_owner','admin'].includes(role)
  const canDelete = role === 'admin'

  const [assets, setAssets]   = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [search, setSearch]   = useState('')
  const [fleetEnv, setFleetEnv]  = useState('')
  const [fleetSite, setFleetSite] = useState('')
  const [fleetTeam, setFleetTeam] = useState('')
  const [editing, setEditing] = useState(null)
  const [form, setForm]       = useState(EMPTY_FORM)
  const [showImport, setShowImport]   = useState(false)
  const [importText, setImportText]   = useState('')
  const [importResult, setImportResult] = useState(null)
  const [expanded, setExpanded] = useState(null)  // asset_id with open software panel
  const [classifying, setClassifying] = useState(false)
  const [activeTab, setActiveTab]     = useState('inventory')  // 'inventory' | 'kev'
  const [kevFocusAsset, setKevFocusAsset] = useState(null)

  // Column sort for both tables
  const [kevSort,  setKevSort]  = useState({ col: 'hostname',    dir: 'asc' })
  const { sorted: sortedAssets, col: asc, dir: asd, toggle: toggleAssetSort } =
    useSortable(assets, 'hostname')
  const toggleKevSort = (col) =>
    setKevSort(s => ({ col, dir: s.col === col ? (s.dir === 'asc' ? 'desc' : 'asc') : 'asc' }))

  const load = useCallback(() => {
    setLoading(true)
    const params = { search: search || undefined, limit: 1000 }
    if (fleetEnv)  params.environment  = fleetEnv
    if (fleetSite) params.site         = fleetSite
    if (fleetTeam) params.owning_team  = fleetTeam
    Promise.all([
      fetchAssets(params),
      fetchFleetSummary(),
    ])
      .then(([ar, sr]) => {
        setAssets(ar.data?.data ?? [])
        setSummary(sr.data?.data ?? null)
      })
      .catch(e => setError(e?.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }, [search, fleetEnv, fleetSite, fleetTeam])

  // On first mount: auto-backfill asset_type/platform for unclassified assets
  useEffect(() => {
    if (canWrite) {
      classifyAssets().then(() => load()).catch(() => load())
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load() }, [load])

  const startEdit = (a) => {
    setEditing(a.asset_id)
    setForm({
      hostname: a.hostname||'', ip_address: a.ip_address||'',
      business_unit: a.business_unit||'IT', business_owner: a.business_owner||'',
      criticality: a.criticality||'medium', internet_exposed: !!a.internet_exposed,
      environment: a.environment||'production',
      asset_type: a.asset_type||'', platform: a.platform||'',
      os_version: a.os_version||'', site: a.site||'', owning_team: a.owning_team||'',
    })
  }
  const resetForm = () => { setEditing(null); setForm(EMPTY_FORM) }

  const onSubmit = async (e) => {
    e.preventDefault(); setError(null)
    try {
      const payload = { ...form }
      if (!payload.asset_type)  delete payload.asset_type
      if (!payload.platform)    delete payload.platform
      if (!payload.os_version)  delete payload.os_version
      if (!payload.site)        delete payload.site
      if (!payload.owning_team) delete payload.owning_team
      if (editing) { await updateAsset(editing, payload) } else { await createAsset(payload) }
      resetForm(); load()
    } catch (e) { setError(e?.response?.data?.detail || e.message) }
  }

  const onDelete = async (id) => {
    if (!confirm('Delete asset? This cannot be undone.')) return
    setError(null)
    try { await deleteAsset(id); load() }
    catch (e) { setError(e?.response?.data?.detail || e.message) }
  }

  const parseCSVPaste = (text) => {
    const lines = text.trim().split(/\r?\n/).filter(Boolean)
    if (lines.length < 2) return []
    const header = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g,''))
    return lines.slice(1).map(line => {
      const cells = line.split(',').map(c => c.trim().replace(/^"|"$/g,''))
      const obj = {}; header.forEach((h,i) => { obj[h] = cells[i] ?? '' })
      return {
        hostname:         obj.hostname,
        ip_address:       obj.ip_address || obj.ip || '',
        business_unit:    obj.business_unit || 'IT',
        business_owner:   obj.business_owner || '',
        criticality:      (obj.criticality || 'medium').toLowerCase(),
        internet_exposed: ['true','1','yes'].includes(String(obj.internet_exposed).toLowerCase()),
        environment:      (obj.environment || 'production').toLowerCase(),
        asset_type:       obj.asset_type || null,
        platform:         obj.platform || null,
        os_version:       obj.os_version || null,
        site:             obj.site || null,
        owning_team:      obj.owning_team || null,
      }
    }).filter(a => a.hostname && a.ip_address)
  }

  const onBulkImport = async () => {
    setError(null); setImportResult(null)
    const rows = parseCSVPaste(importText)
    if (!rows.length) { setError('No valid rows parsed.'); return }
    try {
      const r = await bulkImportAssets({ assets: rows, upsert: true })
      setImportResult(r.data?.data ?? r.data)
      setImportText(''); load()
    } catch (e) { setError(e?.response?.data?.detail || e.message) }
  }

  const inputCls = "px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
  const selCls   = inputCls + " font-mono"

  return (
    <div className="p-8 max-w-[1600px] mx-auto space-y-6">
      <div>
        <div className="mono-label text-[var(--amber)] mb-1">FLEET MANAGEMENT</div>
        <h1 className="font-syne text-3xl font-bold text-white">Asset Inventory</h1>
        <p className="text-sm text-[var(--muted)] mt-1 max-w-2xl">
          Ground-truth inventory with software inventory and threat-exposure matching.
        </p>
      </div>

      {/* ── Tab switcher ── */}
      <div className="flex gap-1 p-1 rounded-lg w-fit" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
        {[
          { id: 'inventory', label: 'Asset Inventory' },
          { id: 'kev',       label: '🔴 KEV Matches'  },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className="px-4 py-1.5 rounded text-sm font-medium transition-all"
            style={{
              background:  activeTab === tab.id ? 'var(--surface-2)' : 'transparent',
              color:       activeTab === tab.id ? (tab.id === 'kev' ? 'var(--red)' : 'var(--amber)') : 'var(--muted)',
              border:      activeTab === tab.id ? '1px solid var(--border)' : '1px solid transparent',
              fontFamily:  '"IBM Plex Mono", monospace',
              fontSize:    11,
              letterSpacing: '0.05em',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'kev' ? (
        <KevMatchesTab assets={assets} focusAssetId={kevFocusAsset} />
      ) : (<>

      <FleetSummary
        summary={summary}
        canWrite={canWrite}
        classifying={classifying}
        onClassify={async () => {
          setClassifying(true)
          try { await classifyAssets(); load() } catch { /* ignore */ }
          finally { setClassifying(false) }
        }}
      />

      {error && (
        <div className="px-4 py-3 rounded text-sm"
          style={{ background:'rgba(224,82,82,0.1)', border:'1px solid rgba(224,82,82,0.3)', color:'var(--red)' }}>
          {error}
        </div>
      )}

      {/* ── Fleet filters ── */}
      <div className="vra-card flex flex-wrap gap-3 items-center">
        <span className="mono-label">Fleet filter:</span>
        <select className={selCls} value={fleetEnv}  onChange={e=>{setFleetEnv(e.target.value)}}>
          <option value="">All environments</option>
          {ENVIRONMENTS.map(e=><option key={e} value={e}>{e}</option>)}
        </select>
        <input className={inputCls} placeholder="Site (e.g. DC-Paris)" value={fleetSite}
          onChange={e=>setFleetSite(e.target.value)} />
        <input className={inputCls} placeholder="Owning team" value={fleetTeam}
          onChange={e=>setFleetTeam(e.target.value)} />
        {(fleetEnv||fleetSite||fleetTeam) && (
          <button className="btn-ghost text-xs" onClick={()=>{setFleetEnv('');setFleetSite('');setFleetTeam('')}}>
            Clear filters
          </button>
        )}
      </div>

      {/* ── Add / Edit form ── */}
      {canWrite && (
        <form onSubmit={onSubmit}
          className="vra-card grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3">
          <div className="col-span-full mono-label">
            {editing ? `Editing ${editing.slice(0,8)}…` : 'Add new asset'}
          </div>
          <input required placeholder="hostname *" value={form.hostname}
            onChange={e=>setForm({...form,hostname:e.target.value})} className={inputCls+" font-mono"} />
          <input required placeholder="ip_address *" value={form.ip_address}
            onChange={e=>setForm({...form,ip_address:e.target.value})} className={inputCls+" font-mono"} />
          <input placeholder="business_unit" value={form.business_unit}
            onChange={e=>setForm({...form,business_unit:e.target.value})} className={inputCls} />
          <input placeholder="business_owner" value={form.business_owner}
            onChange={e=>setForm({...form,business_owner:e.target.value})} className={inputCls} />
          <select value={form.criticality} onChange={e=>setForm({...form,criticality:e.target.value})} className={selCls}>
            {CRITICALITY.map(c=><option key={c} value={c}>criticality: {c}</option>)}
          </select>
          <select value={form.environment} onChange={e=>setForm({...form,environment:e.target.value})} className={selCls}>
            {ENVIRONMENTS.map(c=><option key={c} value={c}>env: {c}</option>)}
          </select>
          {/* Cascade dropdowns: Asset Type → Platform → OS Version */}
          <select value={form.asset_type}
            onChange={e=>setForm({...form, asset_type:e.target.value, platform:'', os_version:''})}
            className={selCls}>
            <option value="">Asset type…</option>
            {ASSET_TYPE_OPTIONS.map(t=><option key={t} value={t}>{t.replace('_',' ')}</option>)}
          </select>
          <select value={form.platform}
            onChange={e=>setForm({...form, platform:e.target.value, os_version:''})}
            className={selCls}
            disabled={!form.asset_type}>
            <option value="">Platform…</option>
            {(PLATFORM_BY_TYPE[form.asset_type] || []).map(p=><option key={p} value={p}>{p}</option>)}
          </select>
          <select value={form.os_version}
            onChange={e=>setForm({...form, os_version:e.target.value})}
            className={selCls}
            disabled={!form.platform}>
            <option value="">OS version…</option>
            {(OS_BY_PLATFORM[form.platform] || []).map(v=><option key={v} value={v}>{v}</option>)}
          </select>
          <input placeholder="Site (e.g. DC-Paris)" value={form.site}
            onChange={e=>setForm({...form,site:e.target.value})} className={inputCls} />
          <input placeholder="Owning team" value={form.owning_team}
            onChange={e=>setForm({...form,owning_team:e.target.value})} className={inputCls} />
          <label className={`flex items-center gap-2 ${inputCls}`}>
            <input type="checkbox" checked={form.internet_exposed}
              onChange={e=>setForm({...form,internet_exposed:e.target.checked})} className="accent-[var(--amber)]"/>
            Internet exposed
          </label>
          <div className="flex gap-2 col-span-2">
            <button type="submit" className="btn-amber flex-1">
              {editing ? 'Save' : 'Add asset'}
            </button>
            {editing && <button type="button" onClick={resetForm} className="btn-ghost">Cancel</button>}
          </div>
        </form>
      )}

      {/* ── Bulk CSV import ── */}
      <div>
        <button onClick={()=>setShowImport(!showImport)} className="mono-label text-[var(--amber)] hover:underline">
          {showImport?'▾':'▸'} Bulk import from CSV
        </button>
        {showImport && (
          <div className="mt-3 vra-card">
            <p className="text-xs text-[var(--muted)] mb-3">
              Required: <code className="text-[var(--amber)]">hostname, ip_address</code>.
              Optional: <code>business_unit, business_owner, criticality, internet_exposed, environment,
              os_version, site, owning_team</code>. Existing assets (by hostname) are updated.
            </p>
            <textarea value={importText} onChange={e=>setImportText(e.target.value)}
              placeholder={'hostname,ip_address,os_version,site,owning_team,criticality\nweb-prod-01,10.0.1.5,Ubuntu 22.04,DC-Paris,WebOps,critical'}
              className="w-full h-32 px-3 py-2 rounded text-xs bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono" />
            <div className="flex gap-2 mt-2 items-center">
              <button onClick={onBulkImport} className="btn-amber text-sm">Import</button>
              {importResult && (
                <span className="text-xs text-[var(--green)]">
                  ✓ inserted {importResult.inserted}, updated {importResult.updated}
                  {importResult.sw_upserted>0 && `, sw ${importResult.sw_upserted}`}
                  {importResult.errors?.length>0 && (
                    <span className="text-[var(--red)] ml-2">({importResult.errors.length} errors)</span>
                  )}
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Search ── */}
      <div className="flex items-center gap-3">
        <input placeholder="Search hostname or IP…" value={search}
          onChange={e=>setSearch(e.target.value)}
          className="flex-1 max-w-md px-3 py-2 rounded text-sm bg-[var(--surface)] border border-[var(--border)] text-white" />
        <span className="text-xs text-[var(--muted)]">{assets.length} assets</span>
      </div>

      {/* ── Table ── */}
      <div className="rounded border border-[var(--border)] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-[var(--surface-2)] mono-label text-[var(--muted)]">
              <th className="px-4 py-3 text-left w-4" />
              {[['hostname','Hostname'],['ip_address','IP'],['asset_type','Type'],['platform','Platform'],
                ['os_version','OS Version'],['site','Site'],['owning_team','Team'],
                ['business_unit','BU'],['criticality','Criticality']].map(([c,l]) => (
                <SortTh key={c} col={c} sortCol={asc} sortDir={asd} onSort={toggleAssetSort}
                  className="px-4 py-3">{l}</SortTh>
              ))}
              <th className="px-4 py-3 text-left">Exposed</th>
              <th className="px-4 py-3 text-left">Env</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={13} className="px-4 py-8 text-center text-[var(--muted)]">Loading…</td></tr>
            ) : sortedAssets.length === 0 ? (
              <tr><td colSpan={13} className="px-4 py-8 text-center text-[var(--muted)]">
                No assets match. Add one or use Bulk import.
              </td></tr>
            ) : sortedAssets.map(a => (
              <>
                <tr key={a.asset_id}
                  className="border-t border-[var(--border)] hover:bg-[var(--surface)] cursor-pointer">
                  <td className="px-3 py-2 text-center text-[var(--muted)]"
                    onClick={() => setExpanded(expanded===a.asset_id ? null : a.asset_id)}>
                    {expanded===a.asset_id ? '▾' : '▸'}
                  </td>
                  <td className="px-4 py-2 text-white font-mono">{a.hostname}</td>
                  <td className="px-4 py-2 text-[var(--muted)] font-mono">{a.ip_address}</td>
                  <td className="px-4 py-2 text-xs text-[var(--muted)]">{a.asset_type ? a.asset_type.replace('_',' ') : '—'}</td>
                  <td className="px-4 py-2 text-xs text-[var(--muted)]">{a.platform || '—'}</td>
                  <td className="px-4 py-2 text-xs text-[var(--muted)]">{a.os_version || '—'}</td>
                  <td className="px-4 py-2 text-xs text-[var(--muted)]">{a.site || '—'}</td>
                  <td className="px-4 py-2 text-xs text-[var(--muted)]">{a.owning_team || '—'}</td>
                  <td className="px-4 py-2">{a.business_unit}</td>
                  <td className="px-4 py-2"><CritBadge value={a.criticality} /></td>
                  <td className="px-4 py-2 text-xs">
                    {a.internet_exposed
                      ? <span className="text-[var(--red)]">● yes</span>
                      : <span className="text-[var(--muted)]">no</span>}
                  </td>
                  <td className="px-4 py-2 text-xs text-[var(--muted)]">{a.environment}</td>
                  <td className="px-4 py-2 text-right whitespace-nowrap">
                    {canWrite && (
                      <button onClick={e=>{e.stopPropagation();startEdit(a)}}
                        className="px-2 py-1 text-xs text-[var(--amber)] hover:underline">edit</button>
                    )}
                    {canDelete && (
                      <button onClick={e=>{e.stopPropagation();onDelete(a.asset_id)}}
                        className="px-2 py-1 text-xs text-[var(--red)] hover:underline">delete</button>
                    )}
                  </td>
                </tr>
                {expanded === a.asset_id && (
                  <tr key={`sw-${a.asset_id}`}>
                    <td colSpan={13} className="p-0">
                      <SoftwarePanel
                        assetId={a.asset_id}
                        canWrite={canWrite}
                        onKevClick={(id) => { setKevFocusAsset(id); setActiveTab('kev') }}
                      />
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
      </>)}
    </div>
  )
}
