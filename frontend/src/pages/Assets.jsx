import { useEffect, useState } from 'react'
import {
  fetchAssets, createAsset, updateAsset, deleteAsset, bulkImportAssets,
} from '../api/client'

const CRITICALITY = ['low', 'medium', 'high', 'critical']
const ENVIRONMENTS = ['production', 'staging', 'dev', 'test']

const EMPTY_FORM = {
  hostname: '',
  ip_address: '',
  business_unit: 'IT',
  business_owner: '',
  criticality: 'medium',
  internet_exposed: false,
  environment: 'production',
}

function CritBadge({ value }) {
  const map = {
    low:      'text-[var(--green)] bg-[rgba(78,175,124,0.1)] border-[rgba(78,175,124,0.3)]',
    medium:   'text-[var(--blue)] bg-[rgba(78,143,175,0.1)] border-[rgba(78,143,175,0.3)]',
    high:     'text-[var(--amber)] bg-[rgba(255,196,13,0.1)] border-[rgba(255,196,13,0.3)]',
    critical: 'text-[var(--red)] bg-[rgba(224,82,82,0.1)] border-[rgba(224,82,82,0.3)]',
  }
  const cls = map[value] || map.medium
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono uppercase tracking-wider border ${cls}`}>
      {value}
    </span>
  )
}

export default function Assets() {
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState(EMPTY_FORM)
  const [showImport, setShowImport] = useState(false)
  const [importText, setImportText] = useState('')
  const [importResult, setImportResult] = useState(null)

  const load = () => {
    setLoading(true)
    fetchAssets({ search: search || undefined, limit: 1000 })
      .then((r) => setAssets(r.data?.data ?? []))
      .catch((e) => setError(e?.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])
  useEffect(() => {
    const t = setTimeout(load, 250)
    return () => clearTimeout(t)
  }, [search])

  const startEdit = (asset) => {
    setEditing(asset.asset_id)
    setForm({
      hostname:         asset.hostname || '',
      ip_address:       asset.ip_address || '',
      business_unit:    asset.business_unit || 'IT',
      business_owner:   asset.business_owner || '',
      criticality:      asset.criticality || 'medium',
      internet_exposed: !!asset.internet_exposed,
      environment:      asset.environment || 'production',
    })
  }

  const resetForm = () => { setEditing(null); setForm(EMPTY_FORM) }

  const onSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    try {
      if (editing) {
        await updateAsset(editing, form)
      } else {
        await createAsset(form)
      }
      resetForm()
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  const onDelete = async (id) => {
    if (!confirm(`Delete asset ${id}? This cannot be undone.`)) return
    setError(null)
    try {
      await deleteAsset(id)
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  const parseCSVPaste = (text) => {
    const lines = text.trim().split(/\r?\n/).filter(Boolean)
    if (lines.length < 2) return []
    const header = lines[0].split(',').map((h) => h.trim().replace(/^"|"$/g, ''))
    return lines.slice(1).map((line) => {
      const cells = line.split(',').map((c) => c.trim().replace(/^"|"$/g, ''))
      const obj = {}
      header.forEach((h, i) => { obj[h] = cells[i] ?? '' })
      return {
        hostname:         obj.hostname,
        ip_address:       obj.ip_address || obj.ip || '',
        business_unit:    obj.business_unit || 'IT',
        business_owner:   obj.business_owner || '',
        criticality:      (obj.criticality || 'medium').toLowerCase(),
        internet_exposed: ['true', '1', 'yes'].includes(String(obj.internet_exposed).toLowerCase()),
        environment:      (obj.environment || 'production').toLowerCase(),
      }
    }).filter((a) => a.hostname && a.ip_address)
  }

  const onBulkImport = async () => {
    setError(null); setImportResult(null)
    const rows = parseCSVPaste(importText)
    if (rows.length === 0) {
      setError('No valid rows parsed. Need a header row with at least hostname,ip_address.')
      return
    }
    try {
      const r = await bulkImportAssets({ assets: rows, upsert: true })
      setImportResult(r.data?.data ?? r.data)
      setImportText('')
      load()
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  return (
    <div className="p-10 max-w-[1400px] mx-auto">
      <div className="mb-8">
        <div className="mono-label text-[var(--amber)] mb-2">ASSET INVENTORY</div>
        <h1 className="font-syne text-3xl font-bold text-white">Real Assets</h1>
        <p className="text-sm text-[var(--muted)] mt-2 max-w-2xl">
          Ground-truth inventory used by risk scoring. Criticality and internet exposure
          directly affect job risk levels and SLA deadlines.
        </p>
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded bg-[rgba(224,82,82,0.1)] border border-[rgba(224,82,82,0.3)] text-sm text-[var(--red)]">
          {error}
        </div>
      )}

      {/* ── Form ── */}
      <form onSubmit={onSubmit} className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-8 p-5 rounded bg-[var(--surface)] border border-[var(--border)]">
        <div className="md:col-span-4 mono-label">
          {editing ? `Editing asset ${editing.slice(0, 8)}…` : 'Add new asset'}
        </div>
        <input
          required placeholder="hostname (e.g. web-prod-01)"
          value={form.hostname}
          onChange={(e) => setForm({ ...form, hostname: e.target.value })}
          className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono"
        />
        <input
          required placeholder="ip_address (e.g. 10.0.1.5)"
          value={form.ip_address}
          onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
          className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono"
        />
        <input
          placeholder="business_unit (e.g. IT)"
          value={form.business_unit}
          onChange={(e) => setForm({ ...form, business_unit: e.target.value })}
          className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
        />
        <input
          placeholder="business_owner (email)"
          value={form.business_owner}
          onChange={(e) => setForm({ ...form, business_owner: e.target.value })}
          className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
        />
        <select
          value={form.criticality}
          onChange={(e) => setForm({ ...form, criticality: e.target.value })}
          className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
        >
          {CRITICALITY.map((c) => (<option key={c} value={c}>criticality: {c}</option>))}
        </select>
        <select
          value={form.environment}
          onChange={(e) => setForm({ ...form, environment: e.target.value })}
          className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
        >
          {ENVIRONMENTS.map((c) => (<option key={c} value={c}>env: {c}</option>))}
        </select>
        <label className="flex items-center gap-2 px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white">
          <input
            type="checkbox"
            checked={form.internet_exposed}
            onChange={(e) => setForm({ ...form, internet_exposed: e.target.checked })}
          />
          Internet exposed
        </label>
        <div className="flex gap-2">
          <button
            type="submit"
            className="flex-1 px-4 py-2 rounded text-sm font-semibold bg-[var(--amber)] text-black hover:bg-[var(--amber-dim)]"
          >
            {editing ? 'Save' : 'Add asset'}
          </button>
          {editing && (
            <button type="button" onClick={resetForm}
              className="px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
            >Cancel</button>
          )}
        </div>
      </form>

      {/* ── Bulk CSV import ── */}
      <div className="mb-8">
        <button
          onClick={() => setShowImport(!showImport)}
          className="mono-label text-[var(--amber)] hover:underline"
        >
          {showImport ? '▾' : '▸'} Bulk import from CSV
        </button>
        {showImport && (
          <div className="mt-3 p-5 rounded bg-[var(--surface)] border border-[var(--border)]">
            <p className="text-xs text-[var(--muted)] mb-3">
              Paste CSV with header. Required columns: <code>hostname,ip_address</code>.
              Optional: <code>business_unit, business_owner, criticality, internet_exposed, environment</code>.
              Existing assets (matched by hostname) are updated.
            </p>
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder={'hostname,ip_address,criticality,internet_exposed\nweb-prod-01,10.0.1.5,critical,true\napp-srv-01,10.0.1.6,high,false'}
              className="w-full h-40 px-3 py-2 rounded text-xs bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono"
            />
            <div className="flex gap-2 mt-2">
              <button onClick={onBulkImport}
                className="px-4 py-2 rounded text-sm font-semibold bg-[var(--amber)] text-black hover:bg-[var(--amber-dim)]">
                Import
              </button>
              {importResult && (
                <div className="text-xs text-[var(--green)] py-2">
                  ✓ inserted {importResult.inserted}, updated {importResult.updated}, skipped {importResult.skipped}
                  {importResult.errors?.length > 0 && (
                    <span className="text-[var(--red)] ml-2">({importResult.errors.length} errors)</span>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Search + table ── */}
      <div className="mb-4 flex items-center gap-3">
        <input
          placeholder="Search hostname or IP…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 max-w-md px-3 py-2 rounded text-sm bg-[var(--surface)] border border-[var(--border)] text-white"
        />
        <div className="text-xs text-[var(--muted)]">{assets.length} assets</div>
      </div>

      <div className="rounded border border-[var(--border)] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-[var(--surface-2)] text-[var(--muted)] mono-label">
              <th className="px-4 py-3 text-left">Hostname</th>
              <th className="px-4 py-3 text-left">IP</th>
              <th className="px-4 py-3 text-left">BU</th>
              <th className="px-4 py-3 text-left">Criticality</th>
              <th className="px-4 py-3 text-left">Exposed</th>
              <th className="px-4 py-3 text-left">Env</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-[var(--muted)]">Loading…</td></tr>
            ) : assets.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-[var(--muted)]">
                No assets yet. Add one with the form above, or paste CSV via Bulk import.
              </td></tr>
            ) : assets.map((a) => (
              <tr key={a.asset_id} className="border-t border-[var(--border)] hover:bg-[var(--surface)]">
                <td className="px-4 py-2 text-white font-mono">{a.hostname}</td>
                <td className="px-4 py-2 text-[var(--muted)] font-mono">{a.ip_address}</td>
                <td className="px-4 py-2 text-white">{a.business_unit}</td>
                <td className="px-4 py-2"><CritBadge value={a.criticality} /></td>
                <td className="px-4 py-2 text-xs">{a.internet_exposed ? <span className="text-[var(--red)]">● yes</span> : <span className="text-[var(--muted)]">no</span>}</td>
                <td className="px-4 py-2 text-[var(--muted)] text-xs">{a.environment}</td>
                <td className="px-4 py-2 text-right whitespace-nowrap">
                  <button onClick={() => startEdit(a)} className="px-2 py-1 text-xs text-[var(--amber)] hover:underline">edit</button>
                  <button onClick={() => onDelete(a.asset_id)} className="px-2 py-1 text-xs text-[var(--red)] hover:underline">delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
