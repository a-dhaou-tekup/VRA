import { useEffect, useState } from 'react'
import {
  fetchEnrichmentStatus, refreshKEV, refreshEPSS, refreshNVD, fetchCveDetail,
} from '../api/client'

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
  const [status, setStatus]       = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [refreshing, setRefreshing] = useState({ kev: false, epss: false, nvd: false })
  const [toast, setToast]         = useState(null)
  const [lookupCve, setLookupCve] = useState('')
  const [lookupResult, setLookupResult] = useState(null)
  const [lookupError, setLookupError]   = useState(null)

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

      {/* ── Single-CVE lookup ── */}
      <div className="p-5 rounded bg-[var(--surface)] border border-[var(--border)]">
        <div className="mono-label text-[var(--amber)] mb-3">CVE LOOKUP</div>
        <p className="text-xs text-[var(--muted)] mb-3">
          Inspect cached KEV / EPSS / NVD data for a single CVE.
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
            <div><span className="text-[var(--muted)]">cve_id:</span> <span className="text-white">{lookupResult.cve_id}</span></div>
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
