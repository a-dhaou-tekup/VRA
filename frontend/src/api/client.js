import axios from 'axios'

export const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT Bearer token from the auth session stored in localStorage
api.interceptors.request.use((config) => {
  try {
    const raw = localStorage.getItem('vra_auth')
    if (raw) {
      const { token } = JSON.parse(raw)
      if (token) config.headers['Authorization'] = `Bearer ${token}`
    }
  } catch {
    // ignore parse errors
  }
  return config
})

// ─── Auth ──────────────────────────────────────────────────────────────────
// loginUser uses form-encoded body (OAuth2PasswordRequestForm)
export const loginUser = (username, password) =>
  api.post(
    '/api/auth/login',
    new URLSearchParams({ username, password }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  )

export const fetchMe = () => api.get('/api/auth/me')

// ─── Users (admin only) ────────────────────────────────────────────────────
export const fetchUsers  = ()           => api.get('/api/users')
export const createUser  = (body)       => api.post('/api/users', body)
export const updateUser  = (id, body)   => api.patch(`/api/users/${id}`, body)
export const deleteUser  = (id)         => api.delete(`/api/users/${id}`)

// ─── Jobs ──────────────────────────────────────────────────────────────────
export const fetchJobs = (params) => api.get('/api/jobs', { params })
export const fetchJob = (id) => api.get(`/api/jobs/${id}`)
export const updateJobStatus = (id, body) => api.patch(`/api/jobs/${id}/status`, body)
export const triageJob = (id, body) => api.patch(`/api/jobs/${id}/triage`, body)
export const updateJobSla = (id, body) => api.patch(`/api/jobs/${id}/sla`, body)
export const fetchJobEvents = (id) => api.get(`/api/jobs/${id}/events`)

// ─── Metrics ───────────────────────────────────────────────────────────────
export const fetchMetricsOverview = () => api.get('/api/metrics/overview')
export const fetchMetricsSLA = () => api.get('/api/metrics/sla')
export const fetchMetricsTimeline = () => api.get('/api/metrics/timeline')

// ─── RAG ───────────────────────────────────────────────────────────────────
export const fetchRagRecommendation = (jobId) =>
  api.get(`/api/rag/jobs/${jobId}/recommend`)
export const submitRagFeedback = (jobId, feedback) =>
  api.post(`/api/rag/jobs/${jobId}/feedback`, feedback)
export const fetchRagStats = () => api.get('/api/rag/stats')

// ─── Rescan ────────────────────────────────────────────────────────────────
export const fetchRescanStatus = () => api.get('/api/rescan/status')
export const runRescan = (body) => api.post('/api/rescan/run', body)

// ─── Uploads ───────────────────────────────────────────────────────────────
export const fetchUploads = () => api.get('/api/uploads')
export const fetchUpload = (id) => api.get(`/api/uploads/${id}`)
export const uploadScanFile = (formData) =>
  api.post('/api/uploads', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })

// ─── Tickets ───────────────────────────────────────────────────────────────
export const fetchTickets = () => api.get('/api/tickets')
export const createTicket = (jobId, body) =>
  api.post(`/api/tickets/jobs/${jobId}`, body)

// ─── Assets ────────────────────────────────────────────────────────────────
export const fetchAssets = (params) => api.get('/api/assets', { params })
export const fetchAsset = (id) => api.get(`/api/assets/${id}`)
export const createAsset = (body) => api.post('/api/assets', body)
export const updateAsset = (id, body) => api.patch(`/api/assets/${id}`, body)
export const deleteAsset = (id) => api.delete(`/api/assets/${id}`)
export const bulkImportAssets = (body) => api.post('/api/assets/bulk', body)
export const classifyAssets   = ()     => api.post('/api/assets/classify')

// ─── Manual findings ───────────────────────────────────────────────────────
export const submitManualFindings = (body) =>
  api.post('/api/findings/manual', body)
export const fetchManualExample = () => api.get('/api/findings/manual/example')

// ─── Enrichment ────────────────────────────────────────────────────────────
export const fetchEnrichmentStatus = () => api.get('/api/enrichment/status')
export const refreshKEV = () => api.post('/api/enrichment/kev/refresh')
export const refreshEPSS = (body) => api.post('/api/enrichment/epss/refresh', body || {})
export const refreshNVD = (body) => api.post('/api/enrichment/nvd/refresh', body || { limit: 50 })
export const fetchCveDetail = (cveId) => api.get(`/api/enrichment/cve/${cveId}`)
export const fetchEnrichmentCatalog = (params) => api.get('/api/enrichment/catalog', { params })
export const fetchEnrichmentVendors = () => api.get('/api/enrichment/vendors')

// ─── Fleet + Software inventory (P4a) ─────────────────────────────────────
export const fetchFleetSummary   = ()              => api.get('/api/fleet/summary')
export const fetchAssetSoftware  = (assetId)       => api.get(`/api/assets/${assetId}/software`)
export const addAssetSoftware    = (assetId, body) => api.post(`/api/assets/${assetId}/software`, body)
export const replaceAssetSoftware = (assetId, items) => api.put(`/api/assets/${assetId}/software`, items)
export const deleteAssetSoftware = (assetId, swId) => api.delete(`/api/assets/${assetId}/software/${swId}`)

// ─── Threat alerts (P4b) ───────────────────────────────────────────────────
export const fetchThreatAlerts   = (params)      => api.get('/api/threat-alerts', { params })
export const fetchThreatSummary  = ()            => api.get('/api/threat-alerts/summary')
export const fetchAssetThreats   = (assetId)     => api.get(`/api/assets/${assetId}/threats`)
export const runThreatMatch      = (body)        => api.post('/api/threat-alerts/match', body)
export const promoteAlerts       = (body)        => api.post('/api/threat-alerts/promote', body)
export const updateThreatAlert   = (id, body)    => api.patch(`/api/threat-alerts/${id}`, body)
export const domainBreachCheck   = (domain)      => api.get('/api/threat-alerts/breach-check', { params: { domain } })

// ─── Software inventory (global) ──────────────────────────────────────────
export const fetchAllSoftware = (params) => api.get('/api/software', { params })
export async function uploadSoftwareCsv(file) {
  const form = new FormData()
  form.append('file', file)
  return api.post('/api/software/csv', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
}

// ─── Compliance ────────────────────────────────────────────────────────────
export const fetchComplianceSummary  = ()       => api.get('/api/compliance/summary')
export const fetchComplianceControls = (params) => api.get('/api/compliance/controls', { params })
export const fetchComplianceControl  = (id)     => api.get(`/api/compliance/controls/${id}`)
export const tagJobControls          = (jobId, body) => api.post(`/api/compliance/jobs/${jobId}/controls`, body)
export const reloadComplianceCatalog = ()       => api.post('/api/compliance/catalog/reload')

// ─── Lifecycle (P2) ────────────────────────────────────────────────────────
export const transitionJob = (jobId, body) =>
  api.post(`/api/jobs/${jobId}/transition`, body)

// Risk acceptances
export const createRiskAcceptance = (jobId, body) =>
  api.post(`/api/jobs/${jobId}/risk-acceptance`, body)
export const updateRiskAcceptance = (raId, body) =>
  api.patch(`/api/risk-acceptances/${raId}`, body)
export const fetchRiskAcceptances = (jobId) =>
  api.get(`/api/jobs/${jobId}/risk-acceptances`)
export const fetchRiskRegister = () => api.get('/api/risk-register')

// Workarounds
export const createWorkaround = (jobId, body) =>
  api.post(`/api/jobs/${jobId}/workaround`, body)
export const fetchWorkarounds = (jobId) =>
  api.get(`/api/jobs/${jobId}/workarounds`)

// ─── Agent chat ─────────────────────────────────────────────────────────────
export const agentChat      = (body) => api.post('/api/agent/chat', body)
export const agentFeedback  = (body) => api.post('/api/agent/feedback', body)
export const fetchAgentTools = ()   => api.get('/api/agent/tools')

// ─── Findings + Auto-triage ───────────────────────────────────────────────────
export const fetchFindings         = (params)     => api.get('/api/findings/', { params })
export const triggerAutoTriage     = (findingId, force = false) =>
  api.post(`/api/findings/${findingId}/auto-triage`, null, { params: { force } })
export const fetchAutoTriage       = (findingId)  => api.get(`/api/findings/${findingId}/auto-triage`)
export const backfillFindings      = ()           => api.post('/api/findings/backfill-from-jobs')
export const reprocessUpload       = (uploadId)   => api.post(`/api/uploads/${uploadId}/reprocess`)

// ─── Graph (blast radius + similarity) ────────────────────────────────────────
export const fetchBlastRadius    = (findingId, depth = 2, maxNodes = 80) =>
  api.get(`/api/findings/${findingId}/blast-radius`, { params: { depth, max_nodes: maxNodes } })
export const fetchSimilarFindings = (findingId, k = 10) =>
  api.get(`/api/findings/${findingId}/similar`, { params: { k } })
export const refreshGraph = () =>
  api.post('/api/graph/refresh')

// ─── Executive Reports (Prompt #9) ───────────────────────────────────────────
export const createExecReport = (body = {}) => api.post('/api/reports/executive', body)
export const listExecReports  = (params)    => api.get('/api/reports/executive', { params })
export const getExecReport    = (id)        => api.get(`/api/reports/executive/${id}`)

/**
 * Download a PDF via axios (carries the Bearer token) then trigger a
 * browser save-as dialog using a blob URL.  This avoids the 401 that
 * occurs when the browser opens the URL directly without auth headers.
 */
export async function downloadExecReport(id) {
  const resp = await api.get(`/api/reports/executive/${id}/pdf`, {
    responseType: 'blob',
  })
  const blob = new Blob([resp.data], { type: 'application/pdf' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `vra-exec-report-${id.slice(0, 8)}.pdf`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ─── Chat-with-Finding ───────────────────────────────────────────────────────
export const fetchFindingConversations = (jobId) =>
  api.get(`/api/findings/${jobId}/conversations`)

export const fetchConversation = (conversationId) =>
  api.get(`/api/conversations/${conversationId}`)

/**
 * Open a streaming SSE connection to POST /api/findings/{jobId}/chat.
 * Returns an EventSource-like object backed by fetch (supports POST + auth).
 *
 * @param {string}   jobId
 * @param {string}   message
 * @param {string}   [conversationId]
 * @param {function} onToken    (text: string) => void
 * @param {function} onDone     ({conversation_id, turn_id}) => void
 * @param {function} onError    (detail: string) => void
 * @returns {{ abort: () => void }}
 */
export function streamFindingChat({ jobId, message, conversationId, onToken, onDone, onError }) {
  const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
  const url = `${BASE_URL}/api/findings/${jobId}/chat`

  let auth = ''
  try {
    const raw = localStorage.getItem('vra_auth')
    if (raw) auth = JSON.parse(raw).token || ''
  } catch { /* ignore */ }

  const controller = new AbortController()

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(auth ? { Authorization: `Bearer ${auth}` } : {}),
    },
    body: JSON.stringify({ message, conversation_id: conversationId || undefined }),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        onError?.(err.detail || 'Request failed')
        return
      }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        // SSE lines are separated by \n\n; each line is "data: <json>"
        const parts = buffer.split('\n\n')
        buffer = parts.pop() ?? ''

        for (const part of parts) {
          const line = part.replace(/^data:\s*/, '').trim()
          if (!line) continue
          try {
            const event = JSON.parse(line)
            if (event.type === 'token')  onToken?.(event.content)
            if (event.type === 'done')   onDone?.(event)
            if (event.type === 'error')  onError?.(event.detail)
          } catch { /* ignore malformed */ }
        }
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') onError?.(err.message)
    })

  return { abort: () => controller.abort() }
}
