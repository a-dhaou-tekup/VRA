import { Fragment, useCallback, useEffect, useState } from 'react'
import {
  fetchEnrichmentStatus, refreshKEV, refreshEPSS, refreshNVD, fetchCveDetail,
  fetchEnrichmentCatalog, fetchEnrichmentVendors,
} from '../api/client'

const PAGE_SIZE = 50

const SORT_OPTIONS = [
  { value: 'kev_added_date', label: 'KEV Added Date' },
  { value: 'epss_score',     label: 'EPSS Score' },
  { value: 'epss_percentile',label: 'EPSS Percentile' },
  { value: 'cve_id',         label: 'CVE ID' },
  { value: 'kev_vendor',     label: 'Vendor' },
]

function epssBar(score) {
  if (score == null) return null
  const pct = Math.round(score * 100)
  const color = pct >= 50 ? '#E05252' : pct >= 20 ? '#FFC40D' : '#4EAF7C'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
        <div style={{ width: `${pct}%`, background: color }} className="h-full rounded-full" />
      </div>
      <span style={{ color }} className="font-mono text-[11px]">{(score).toFixed(3)}</span>
    </div>
  )
}

function StatusCard({ title, source, description, data, action, isRefreshing, accent }) {
  const stale = data?.last_fetched && data?.ttl_days
    ? (Date.now() - new Date(data.last_fetched).getTime()) / 86_400_000 > data.ttl_days
    : (data?.cached || 0) === 0

  return (
    <div className="p-5 rounded bg-[var(--surface)] border border-[var(--border)]">
      <div className="flex items-start justify-between mb-2">
        <div>
          <div className="mono-label" style={{ color: accent }}>{title}</div>
          <div className="text-xs text-[var(--muted)] mt-0.5">{source}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          {stale ? (
            <span className="text-xs px-2 py-0.5 rounded border bg-[rgba(255,196,13,0.1)] border-[rgba(255,196,13,0.3)] text-[var(--amber)] font-mono uppercase">stale</span>
          ) : (
            <span className="text-xs px-2 py-0.5 rounded border bg-[rgba(78,175,124,0.1)] border-[rgba(78,175,124,0.3)] text-[var(--green)] font-mono uppercase">fresh</span>
          )}
        </div>
      </div>
      <div className="text-3xl font-syne font-bold text-white mb-1">
        {(data?.cached ?? 0).toLocaleString()}
      </div>
      <div className="text-xs text-[var(--muted)] mb-3">
        {description} · TTL {data?.ttl_days}d
      </div>
      <div className="text-xs text-[var(--muted)] mb-4 font-mono">
        last fetched: {data?.age ?? 'never'}
      </div>
      <button
        onClick={action}
        disabled={isRefreshing}
        className="w-full px-3 py-2 rounded text-xs font-semibold bg-[var(--surface-2)] border border-[var(--border)] text-[var(--amber)] hover:bg-[var(--amber)] hover:text-black disabled:opacity-50 transition"
      >
        {isRefreshing ? 'Refreshing…' : 'Refresh now'}
      </button>
    </div>
  )
}

export default function Enrichment() {
  const [status, setStatus]           = useState(null)
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState(null)
  const [refreshing, setRefreshing]   = useState({ kev: false, epss: false, nvd: false })
  const [toast, setToast]             = useState(null)
  const [lookupCve, setLookupCve]     = useState('')
  const [lookupResult, setLookupResult] = useState(null)
  const [lookupError, setLookupError]   = useState(null)

  // ── Catalog state ─────────────────────────────────────────────────────────
  const [vendors, setVendors]         = useState([])
  const [catalogRows, setCatalogRows] = useState([])
  const [catalogTotal, setCatalogTotal] = useState(0)
  const [catalogLoading, setCatalogLoading] = useState(false)
  const [catalogPage, setCatalogPage] = useState(0)
  const [catalogSearch, setCatalogSearch] = useState('')
  const [catalogVendor, setCatalogVendor] = useState('')
  const [catalogKevOnly, setCatalogKevOnly] = useState(true)
  const [catalogSort, setCatalogSort] = useState('kev_added_date')
  const [catalogOrder, setCatalogOrder] = useState('desc')
  const [expandedRow, setExpandedRow] = useState(null)

  const load = () => {
    fetchEnrichmentStatus()
      .then((r) => setStatus(r.data?.data ?? r.data))
      .catch((e) => setError(e?.response?.data?.detail || e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  // load vendors once
  useEffect(() => {
    fetchEnrichmentVendors()
      .then((r) => setVendors(r.data?.data ?? []))
      .catch(() => {})
  }, [])

  const loadCatalog = useCallback(() => {
    setCatalogLoading(true)
    fetchEnrichmentCatalog({
      search:   catalogSearch || undefined,
      vendor:   catalogVendor || undefined,
      kev_only: catalogKevOnly,
      sort_by:  catalogSort,
      order:    catalogOrder,
      limit:    PAGE_SIZE,
      offset:   catalogPage * PAGE_SIZE,
    })
      .then((r) => {
        setCatalogRows(r.data?.data ?? [])
        setCatalogTotal(r.data?.total ?? 0)
      })
      .catch(() => {})
      .finally(() => setCatalogLoading(false))
  }, [catalogSearch, catalogVendor, catalogKevOnly, catalogSort, catalogOrder, catalogPage])

  useEffect(() => { loadCatalog() }, [loadCatalog])

  // reset page when filters change
  useEffect(() => { setCatalogPage(0) }, [catalogSearch, catalogVendor, catalogKevOnly, catalogSort, catalogOrder])

  const handleRefresh = async (kind, fn) => {
    setRefreshing((r) => ({ ...r, [kind]: true }))
    setToast(null)
    try {
      const r = await fn()
      const msg = r.data?.data?.cve_count
        ? `${kind.toUpperCase()} refresh queued for ${r.data.data.cve_count} CVE(s).`
        : `${kind.toUpperCase()} refresh queued.`
      setToast({ type: 'ok', msg })
      setTimeout(() => setToast(null), 5000)
    } catch (e) {
      setToast({ type: 'err', msg: e?.response?.data?.detail || e.message })
    } finally {
      setTimeout(() => setRefreshing((r) => ({ ...r, [kind]: false })), 1200)
    }
  }

  const handleLookup = async (e) => {
    e.preventDefault()
    setLookupError(null)
    setLookupResult(null)
    if (!/^CVE-\d{4}-\d{4,}$/i.test(lookupCve.trim())) {
      setLookupError('Format: CVE-YYYY-NNNN')
      return
    }
    try {
      const r = await fetchCveDetail(lookupCve.trim().toUpperCase())
      setLookupResult(r.data?.data ?? r.data)
    } catch (e) {
      setLookupError(e?.response?.data?.detail || e.message)
    }
  }

  const handleRowClick = (row) => {
    if (expandedRow === row.cve_id) {
      setExpandedRow(null)
    } else {
      setExpandedRow(row.cve_id)
      setLookupCve(row.cve_id)
      // pre-populate lookup result from catalog row data
      setLookupResult({
        cve_id:          row.cve_id,
        kev_flag:        row.kev_flag,
        kev_added_date:  row.kev_added_date,
        kev_vendor:      row.kev_vendor,
        kev_product:     row.kev_product,
        kev_short_description: row.kev_short_description,
        kev_required_action:   row.kev_required_action,
        epss_score:      row.epss_score,
        epss_percentile: row.epss_percentile,
        nvd_cwe:         row.nvd_cwe,
        nvd_description: row.nvd_description,
      })
      setLookupError(null)
    }
  }

  const totalPages = Math.ceil(catalogTotal / PAGE_SIZE)

  return (
    <div className="p-10 max-w-[1400px] mx-auto">
      <div className="mb-8 flex items-start justify-between">
        <div>
          <div className="mono-label text-[var(--amber)] mb-2">THREAT INTELLIGENCE</div>
          <h1 className="font-syne text-3xl font-bold text-white">Enrichment Sources</h1>
          <p className="text-sm text-[var(--muted)] mt-2 max-w-3xl">
            Live caches for CISA Known Exploited Vulnerabilities, FIRST EPSS,
            and NVD descriptions. Refresh feeds the risk-scoring engine and the
            RAG corpus.
          </p>
        </div>
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded bg-[rgba(224,82,82,0.1)] border border-[rgba(224,82,82,0.3)] text-sm text-[var(--red)]">
          {error}
        </div>
      )}

      {toast && (
        <div className={`mb-4 px-4 py-3 rounded text-sm border ${
          toast.type === 'ok'
            ? 'bg-[rgba(78,175,124,0.1)] border-[rgba(78,175,124,0.3)] text-[var(--green)]'
            : 'bg-[rgba(224,82,82,0.1)] border-[rgba(224,82,82,0.3)] text-[var(--red)]'
        }`}>
          {toast.msg}
        </div>
      )}

      {/* ── Source cards ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {loading ? (
          <div className="col-span-3 p-8 rounded bg-[var(--surface)] border border-[var(--border)] text-center text-[var(--muted)]">
            Loading status…
          </div>
        ) : (
          <>
            <StatusCard
              title="CISA KEV"
              source="cisa.gov · known_exploited_vulnerabilities.json"
              description="Known exploited vulnerabilities catalog"
              data={status?.kev}
              action={() => handleRefresh('kev', refreshKEV)}
              isRefreshing={refreshing.kev}
              accent="#E05252"
            />
            <StatusCard
              title="FIRST EPSS"
              source="first.org/data/1.0/epss"
              description="30-day exploitation probability"
              data={status?.epss}
              action={() => handleRefresh('epss', () => refreshEPSS({}))}
              isRefreshing={refreshing.epss}
              accent="#FFC40D"
            />
            <StatusCard
              title="NVD"
              source="services.nvd.nist.gov/rest/json/cves/2.0"
              description="Canonical CVSS, CWE, descriptions"
              data={status?.nvd}
              action={() => handleRefresh('nvd', () => refreshNVD({ limit: 50 }))}
              isRefreshing={refreshing.nvd}
              accent="#4E8FAF"
            />
          </>
        )}
      </div>

      {/* ── Storage stats ── */}
      {status && (
        <div className="mb-8 grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-3 rounded bg-[var(--surface)] border border-[var(--border)]">
            <div className="mono-label">RAG corpus files</div>
            <div className="text-xl font-bold text-white font-syne">
              {(status.rag_corpus_files ?? 0).toLocaleString()}
            </div>
          </div>
          <div className="p-3 rounded bg-[var(--surface)] border border-[var(--border)]">
            <div className="mono-label">Cache size</div>
            <div className="text-xl font-bold text-white font-syne">
              {((status.db_size_bytes ?? 0) / 1024 / 1024).toFixed(1)} MB
            </div>
          </div>
          <div className="p-3 rounded bg-[var(--surface)] border border-[var(--border)] col-span-2">
            <div className="mono-label">Cache path</div>
            <div className="text-xs text-[var(--muted)] font-mono truncate">
              {status.db_path}
            </div>
          </div>
        </div>
      )}

      {/* ── KEV Catalog Browse ── */}
      <div className="mb-8 rounded bg-[var(--surface)] border border-[var(--border)]">
        {/* header + controls */}
        <div className="px-5 pt-5 pb-3 border-b border-[var(--border)]">
          <div className="mono-label text-[var(--red)] mb-1">KEV CATALOG</div>
          <p className="text-xs text-[var(--muted)] mb-4">
            Browse CISA Known Exploited Vulnerabilities cached locally.
            Click a row to inspect EPSS / NVD details below.
          </p>

          <div className="flex flex-wrap gap-2 items-center">
            {/* search */}
            <input
              value={catalogSearch}
              onChange={(e) => setCatalogSearch(e.target.value)}
              placeholder="Search CVE ID, vendor, product, description…"
              className="flex-1 min-w-[220px] max-w-sm px-3 py-1.5 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono"
            />

            {/* vendor filter */}
            <select
              value={catalogVendor}
              onChange={(e) => setCatalogVendor(e.target.value)}
              className="px-3 py-1.5 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
            >
              <option value="">All vendors</option>
              {vendors.map((v) => (
                <option key={v.vendor} value={v.vendor}>
                  {v.vendor} ({v.count})
                </option>
              ))}
            </select>

            {/* sort */}
            <select
              value={catalogSort}
              onChange={(e) => setCatalogSort(e.target.value)}
              className="px-3 py-1.5 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>

            {/* order */}
            <button
              onClick={() => setCatalogOrder((o) => o === 'desc' ? 'asc' : 'desc')}
              className="px-3 py-1.5 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white hover:border-[var(--amber)] transition"
              title="Toggle sort order"
            >
              {catalogOrder === 'desc' ? '↓ Newest' : '↑ Oldest'}
            </button>

            {/* kev-only toggle */}
            <label className="flex items-center gap-2 cursor-pointer select-none text-sm text-[var(--muted)]">
              <div
                onClick={() => setCatalogKevOnly((v) => !v)}
                className={`w-9 h-5 rounded-full border transition ${
                  catalogKevOnly
                    ? 'bg-[rgba(224,82,82,0.25)] border-[rgba(224,82,82,0.5)]'
                    : 'bg-[var(--surface-2)] border-[var(--border)]'
                } relative`}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${
                  catalogKevOnly ? 'left-4 bg-[var(--red)]' : 'left-0.5 bg-[var(--muted)]'
                }`} />
              </div>
              KEV only
            </label>

            <span className="ml-auto text-xs text-[var(--muted)] font-mono whitespace-nowrap">
              {catalogTotal.toLocaleString()} entries
            </span>
          </div>
        </div>

        {/* table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[var(--muted)] text-xs">
                <th className="px-4 py-2 text-left font-mono uppercase">CVE ID</th>
                <th className="px-4 py-2 text-left font-mono uppercase">Vendor</th>
                <th className="px-4 py-2 text-left font-mono uppercase">Product</th>
                <th className="px-4 py-2 text-left font-mono uppercase">KEV Date</th>
                <th className="px-4 py-2 text-left font-mono uppercase">EPSS</th>
                <th className="px-4 py-2 text-left font-mono uppercase">CWE</th>
                <th className="px-4 py-2 text-left font-mono uppercase">Description</th>
              </tr>
            </thead>
            <tbody>
              {catalogLoading && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-[var(--muted)] text-xs">
                    Loading…
                  </td>
                </tr>
              )}
              {!catalogLoading && catalogRows.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-[var(--muted)] text-xs">
                    No entries match the current filter.
                  </td>
                </tr>
              )}
              {!catalogLoading && catalogRows.map((row) => {
                const isExpanded = expandedRow === row.cve_id
                return (
                  <Fragment key={row.cve_id}>
                    <tr
                      onClick={() => handleRowClick(row)}
                      className={`border-b border-[var(--border)] cursor-pointer transition-colors ${
                        isExpanded
                          ? 'bg-[rgba(224,82,82,0.06)]'
                          : 'hover:bg-[var(--surface-2)]'
                      }`}
                    >
                      <td className="px-4 py-2 font-mono text-xs whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {row.kev_flag ? (
                            <span className="w-1.5 h-1.5 rounded-full bg-[var(--red)] flex-shrink-0" title="In CISA KEV" />
                          ) : (
                            <span className="w-1.5 h-1.5 rounded-full bg-[var(--border)] flex-shrink-0" />
                          )}
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="text-[var(--blue)] hover:underline"
                          >
                            {row.cve_id}
                          </a>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-xs text-white whitespace-nowrap max-w-[130px] truncate">
                        {row.kev_vendor || <span className="text-[var(--muted)]">—</span>}
                      </td>
                      <td className="px-4 py-2 text-xs text-[var(--muted)] whitespace-nowrap max-w-[130px] truncate">
                        {row.kev_product || '—'}
                      </td>
                      <td className="px-4 py-2 text-xs text-[var(--muted)] font-mono whitespace-nowrap">
                        {row.kev_added_date || '—'}
                      </td>
                      <td className="px-4 py-2 whitespace-nowrap">
                        {epssBar(row.epss_score) ?? <span className="text-[var(--muted)] text-xs">—</span>}
                      </td>
                      <td className="px-4 py-2 text-xs font-mono text-[var(--muted)] whitespace-nowrap">
                        {row.nvd_cwe || '—'}
                      </td>
                      <td className="px-4 py-2 text-xs text-[var(--muted)] max-w-xs truncate">
                        {row.kev_short_description || row.nvd_description || '—'}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-[rgba(224,82,82,0.04)]">
                        <td colSpan={7} className="px-6 py-4 border-b border-[var(--border)]">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                            <div className="space-y-1.5">
                              <div className="flex gap-3">
                                <span className="text-[var(--muted)] w-28 flex-shrink-0">CVE ID</span>
                                <span className="text-white font-bold">{row.cve_id}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-[var(--muted)] w-28 flex-shrink-0">CISA KEV</span>
                                <span>
                                  {row.kev_flag
                                    ? <span className="text-[var(--red)]">● In KEV catalog</span>
                                    : <span className="text-[var(--muted)]">Not in KEV</span>}
                                </span>
                              </div>
                              {row.kev_added_date && (
                                <div className="flex gap-3">
                                  <span className="text-[var(--muted)] w-28 flex-shrink-0">Date Added</span>
                                  <span className="text-white">{row.kev_added_date}</span>
                                </div>
                              )}
                              <div className="flex gap-3">
                                <span className="text-[var(--muted)] w-28 flex-shrink-0">Vendor</span>
                                <span className="text-white">{row.kev_vendor || '—'}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-[var(--muted)] w-28 flex-shrink-0">Product</span>
                                <span className="text-white">{row.kev_product || '—'}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-[var(--muted)] w-28 flex-shrink-0">EPSS Score</span>
                                <span>{row.epss_score != null
                                  ? <span className="text-[var(--amber)]">{row.epss_score.toFixed(4)}</span>
                                  : <span className="text-[var(--muted)]">—</span>}
                                  {row.epss_percentile != null && (
                                    <span className="text-[var(--muted)]"> · p{Math.round(row.epss_percentile * 100)}</span>
                                  )}
                                </span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-[var(--muted)] w-28 flex-shrink-0">CWE</span>
                                <span className="text-white">{row.nvd_cwe || '—'}</span>
                              </div>
                            </div>
                            <div className="space-y-2">
                              {row.kev_short_description && (
                                <div>
                                  <div className="text-[var(--muted)] mb-1">Required Action</div>
                                  <div className="text-white leading-relaxed whitespace-pre-wrap">{row.kev_required_action || row.kev_short_description}</div>
                                </div>
                              )}
                              {row.nvd_description && (
                                <div>
                                  <div className="text-[var(--muted)] mb-1">NVD Description</div>
                                  <div className="text-[var(--muted)] leading-relaxed whitespace-pre-wrap">{row.nvd_description}</div>
                                </div>
                              )}
                              <div className="flex gap-2 mt-3">
                                <a
                                  href={`https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
                                  target="_blank" rel="noopener noreferrer"
                                  className="px-3 py-1 rounded text-[11px] hover:opacity-80"
                                  style={{ background: 'rgba(78,143,175,0.15)', color: 'var(--blue)', border: '1px solid rgba(78,143,175,0.4)', textDecoration: 'none' }}
                                >
                                  NVD ↗
                                </a>
                                <a
                                  href={`https://www.cve.org/CVERecord?id=${row.cve_id}`}
                                  target="_blank" rel="noopener noreferrer"
                                  className="px-3 py-1 rounded text-[11px] hover:opacity-80"
                                  style={{ background: 'rgba(255,196,13,0.08)', color: 'var(--amber)', border: '1px solid rgba(255,196,13,0.3)', textDecoration: 'none' }}
                                >
                                  MITRE ↗
                                </a>
                                {row.kev_flag && (
                                  <a
                                    href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                                    target="_blank" rel="noopener noreferrer"
                                    className="px-3 py-1 rounded text-[11px] hover:opacity-80"
                                    style={{ background: 'rgba(224,82,82,0.12)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.4)', textDecoration: 'none' }}
                                  >
                                    CISA KEV ↗
                                  </a>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* pagination */}
        {totalPages > 1 && (
          <div className="px-5 py-3 border-t border-[var(--border)] flex items-center justify-between">
            <span className="text-xs text-[var(--muted)] font-mono">
              Page {catalogPage + 1} of {totalPages} &nbsp;·&nbsp; {catalogTotal.toLocaleString()} total
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setCatalogPage((p) => Math.max(0, p - 1))}
                disabled={catalogPage === 0}
                className="px-3 py-1 rounded text-xs bg-[var(--surface-2)] border border-[var(--border)] text-white disabled:opacity-40 hover:border-[var(--amber)] transition"
              >
                ← Prev
              </button>
              {/* page number pills — show up to 7 around current */}
              {Array.from({ length: totalPages }, (_, i) => i)
                .filter((i) => i === 0 || i === totalPages - 1 || Math.abs(i - catalogPage) <= 2)
                .reduce((acc, i, idx, arr) => {
                  if (idx > 0 && i - arr[idx - 1] > 1) acc.push('…')
                  acc.push(i)
                  return acc
                }, [])
                .map((item, idx) =>
                  item === '…' ? (
                    <span key={`ellipsis-${idx}`} className="px-2 py-1 text-xs text-[var(--muted)]">…</span>
                  ) : (
                    <button
                      key={item}
                      onClick={() => setCatalogPage(item)}
                      className={`px-3 py-1 rounded text-xs border transition ${
                        item === catalogPage
                          ? 'bg-[var(--amber)] text-black border-[var(--amber)]'
                          : 'bg-[var(--surface-2)] border-[var(--border)] text-white hover:border-[var(--amber)]'
                      }`}
                    >
                      {item + 1}
                    </button>
                  )
                )
              }
              <button
                onClick={() => setCatalogPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={catalogPage >= totalPages - 1}
                className="px-3 py-1 rounded text-xs bg-[var(--surface-2)] border border-[var(--border)] text-white disabled:opacity-40 hover:border-[var(--amber)] transition"
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Single-CVE lookup ── */}
      <div className="p-5 rounded bg-[var(--surface)] border border-[var(--border)]">
        <div className="mono-label text-[var(--amber)] mb-3">CVE LOOKUP</div>
        <p className="text-xs text-[var(--muted)] mb-3">
          Inspect cached KEV / EPSS / NVD data for a single CVE. Click any catalog row above to pre-fill.
        </p>
        <form onSubmit={handleLookup} className="flex gap-2 mb-3">
          <input
            value={lookupCve}
            onChange={(e) => setLookupCve(e.target.value)}
            placeholder="CVE-2024-3400"
            className="flex-1 max-w-sm px-3 py-2 rounded text-sm bg-[var(--surface-2)] border border-[var(--border)] text-white font-mono"
          />
          <button
            type="submit"
            className="px-4 py-2 rounded text-sm font-semibold bg-[var(--amber)] text-black hover:bg-[var(--amber-dim)]"
          >
            Look up
          </button>
        </form>
        {lookupError && (
          <div className="text-xs text-[var(--red)] mb-2">{lookupError}</div>
        )}
        {lookupResult && (
          <div className="mt-3 p-3 rounded bg-[var(--surface-2)] border border-[var(--border)] text-xs font-mono space-y-1">
            <div className="flex items-center gap-3 mb-2">
              <span className="text-[var(--muted)]">cve_id:</span>
              <span className="text-white font-bold">{lookupResult.cve_id}</span>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${lookupResult.cve_id}`}
                target="_blank" rel="noopener noreferrer"
                className="px-2 py-0.5 rounded text-[10px] hover:opacity-80"
                style={{ background: 'rgba(78,143,175,0.15)', color: 'var(--blue)', border: '1px solid rgba(78,143,175,0.4)', textDecoration: 'none' }}
              >
                NVD ↗
              </a>
              <a
                href={`https://www.cve.org/CVERecord?id=${lookupResult.cve_id}`}
                target="_blank" rel="noopener noreferrer"
                className="px-2 py-0.5 rounded text-[10px] hover:opacity-80"
                style={{ background: 'rgba(255,196,13,0.08)', color: 'var(--amber)', border: '1px solid rgba(255,196,13,0.3)', textDecoration: 'none' }}
              >
                MITRE ↗
              </a>
              {lookupResult.kev_flag ? (
                <a
                  href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                  target="_blank" rel="noopener noreferrer"
                  className="px-2 py-0.5 rounded text-[10px] hover:opacity-80"
                  style={{ background: 'rgba(224,82,82,0.12)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.4)', textDecoration: 'none' }}
                >
                  CISA KEV ↗
                </a>
              ) : null}
            </div>
            <div>
              <span className="text-[var(--muted)]">kev:</span>{' '}
              {lookupResult.kev_flag
                ? <span className="text-[var(--red)]">● in KEV</span>
                : <span className="text-[var(--muted)]">not in KEV</span>}
              {lookupResult.kev_age && <span className="text-[var(--muted)]"> · cached {lookupResult.kev_age}</span>}
            </div>
            <div>
              <span className="text-[var(--muted)]">epss:</span>{' '}
              <span className="text-white">{lookupResult.epss_score ?? '—'}</span>
              {lookupResult.epss_percentile != null && (
                <span className="text-[var(--muted)]"> (p{Math.round(lookupResult.epss_percentile * 100)})</span>
              )}
              {lookupResult.epss_age && <span className="text-[var(--muted)]"> · cached {lookupResult.epss_age}</span>}
            </div>
            <div><span className="text-[var(--muted)]">cwe:</span> <span className="text-white">{lookupResult.nvd_cwe || '—'}</span></div>
            {lookupResult.kev_vendor && (
              <div><span className="text-[var(--muted)]">vendor/product:</span> <span className="text-white">{lookupResult.kev_vendor} / {lookupResult.kev_product}</span></div>
            )}
            {lookupResult.kev_short_description && (
              <div><span className="text-[var(--muted)]">required action:</span> <span className="text-white">{lookupResult.kev_required_action || lookupResult.kev_short_description}</span></div>
            )}
            {lookupResult.nvd_description && (
              <div className="mt-2 pt-2 border-t border-[var(--border)] text-[var(--muted)] whitespace-pre-wrap">
                {lookupResult.nvd_description}
              </div>
            )}
          </div>
        )}
      </div>

      <p className="mt-8 text-xs text-[var(--muted)] max-w-3xl leading-relaxed">
        <strong className="text-white">Auto-enrichment:</strong> when a scan or manual finding is
        submitted, the pipeline fetches EPSS scores from FIRST for any CVE not already cached.
        KEV and NVD are refreshed on demand from this page.
      </p>
    </div>
  )
}
