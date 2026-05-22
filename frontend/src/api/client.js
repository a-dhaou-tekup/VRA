import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

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
