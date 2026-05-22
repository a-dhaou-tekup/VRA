import { useEffect, useRef, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { uploadScanFile, fetchUploads, fetchUpload } from '../api/client'

const SCANNER_TYPES = [
  { value: 'auto', label: 'Auto-detect' },
  { value: 'nessus', label: 'Nessus XML' },
  { value: 'openvas', label: 'OpenVAS XML' },
  { value: 'csv', label: 'CSV Generic' },
]

const STATUS_STEPS = [
  { key: 'uploading', label: 'Uploading…' },
  { key: 'parsing', label: 'Parsing findings…' },
  { key: 'scoring', label: 'Running risk scoring…' },
  { key: 'building', label: 'Building jobs…' },
  { key: 'done', label: 'Done!' },
]

const PIPELINE_STATUS_MAP = {
  uploaded: 'uploading',
  parsing: 'parsing',
  scoring: 'scoring',
  building: 'building',
  done: 'done',
  failed: 'failed',
}

function formatBytes(bytes) {
  if (!bytes) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function StatusBadgeSmall({ status }) {
  const map = {
    done: { cls: 'text-[var(--green)] bg-[rgba(78,175,124,0.1)] border-[rgba(78,175,124,0.3)]', label: 'Done' },
    failed: { cls: 'text-[var(--red)] bg-[rgba(224,82,82,0.1)] border-[rgba(224,82,82,0.3)]', label: 'Failed' },
    processing: { cls: 'text-[var(--amber)] bg-[rgba(255,196,13,0.1)] border-[rgba(255,196,13,0.3)]', label: 'Processing' },
    uploaded: { cls: 'text-[var(--blue)] bg-[rgba(78,143,175,0.1)] border-[rgba(78,143,175,0.3)]', label: 'Uploaded' },
  }
  const info = map[status] || { cls: 'text-[var(--muted)] bg-[rgba(136,136,136,0.1)] border-[rgba(136,136,136,0.2)]', label: status }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold uppercase tracking-wider border ${info.cls}`}>
      {info.label}
    </span>
  )
}

function StatBox({ label, value, color }) {
  return (
    <div className="text-center">
      <div className="text-2xl font-bold font-syne" style={{ color: color || 'var(--text)' }}>
        {value ?? '—'}
      </div>
      <div className="mono-label mt-1">{label}</div>
    </div>
  )
}

export default function Upload() {
  const navigate = useNavigate()
  const fileInputRef = useRef(null)
  const [isDragging, setIsDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const [scannerType, setScannerType] = useState('auto')
  const [uploadedBy, setUploadedBy] = useState('')
  const [uploading, setUploading] = useState(false)
  const [pipelineStatus, setPipelineStatus] = useState(null) // null | 'uploading' | pipeline status string
  const [uploadResult, setUploadResult] = useState(null)
  const [uploadError, setUploadError] = useState(null)
  const [currentUploadId, setCurrentUploadId] = useState(null)
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const pollingRef = useRef(null)

  const loadHistory = useCallback(() => {
    fetchUploads()
      .then((r) => setHistory(r.data?.data ?? []))
      .catch(() => setHistory([]))
      .finally(() => setHistoryLoading(false))
  }, [])

  useEffect(() => {
    loadHistory()
    return () => clearInterval(pollingRef.current)
  }, [loadHistory])

  const startPolling = useCallback((uploadId) => {
    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetchUpload(uploadId)
        const data = res.data?.data ?? res.data   // unwrap {"data": {...}} envelope
        const mapped = PIPELINE_STATUS_MAP[data.status] || data.status
        setPipelineStatus(mapped)
        if (data.status === 'done') {
          clearInterval(pollingRef.current)
          setUploadResult(data)
          setUploading(false)
          loadHistory()
        } else if (data.status === 'failed') {
          clearInterval(pollingRef.current)
          setUploadError(data.error_message || 'Pipeline failed')
          setUploading(false)
          loadHistory()
        }
      } catch {
        // keep polling on transient errors
      }
    }, 2000)
  }, [loadHistory])

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) setSelectedFile(file)
  }

  const handleFileChange = (e) => {
    const file = e.target.files?.[0]
    if (file) setSelectedFile(file)
  }

  const handleSubmit = async () => {
    if (!selectedFile) return
    setUploading(true)
    setUploadError(null)
    setUploadResult(null)
    setPipelineStatus('uploading')

    const formData = new FormData()
    formData.append('file', selectedFile)
    if (scannerType !== 'auto') formData.append('scanner_type', scannerType)
    if (uploadedBy) formData.append('uploaded_by', uploadedBy)

    try {
      const res = await uploadScanFile(formData)
      const uploadId = res.data?.id ?? res.data?.upload_id
      setCurrentUploadId(uploadId)
      setPipelineStatus('parsing')
      if (uploadId) {
        startPolling(uploadId)
      } else {
        // No id to poll — treat as immediate result
        setUploadResult(res.data)
        setUploading(false)
        setPipelineStatus('done')
        loadHistory()
      }
    } catch (err) {
      setUploadError(err.response?.data?.detail || err.message || 'Upload failed')
      setUploading(false)
      setPipelineStatus(null)
    }
  }

  const currentStepIndex = STATUS_STEPS.findIndex((s) => s.key === pipelineStatus)

  const inputStyle = {
    background: 'var(--surface-2)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    borderRadius: 6,
    padding: '8px 12px',
    fontSize: 13,
    fontFamily: 'Inter, sans-serif',
    outline: 'none',
    width: '100%',
  }

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="page-title">Upload Scan Results</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
          Upload scanner output to run the full VRA pipeline — accepts <span style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)' }}>.nessus</span>, <span style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)' }}>.xml</span>, <span style={{ fontFamily: '"IBM Plex Mono", monospace', color: 'var(--amber)' }}>.csv</span>
        </p>
      </div>

      {/* Upload form */}
      {!uploadResult && (
        <div className="vra-card space-y-5">
          {/* Drop zone */}
          <div
            className="rounded-lg cursor-pointer flex flex-col items-center justify-center gap-3 transition-colors"
            style={{
              height: 200,
              border: `2px dashed ${isDragging ? '#FFC40D' : selectedFile ? 'var(--green)' : 'var(--border)'}`,
              background: isDragging ? 'rgba(255,196,13,0.05)' : selectedFile ? 'rgba(78,175,124,0.04)' : 'transparent',
            }}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
          >
            <input
              ref={fileInputRef}
              type="file"
              hidden
              accept=".nessus,.xml,.csv"
              onChange={handleFileChange}
            />
            {selectedFile ? (
              <div className="text-center">
                <div className="text-3xl mb-2">📄</div>
                <div className="font-medium text-sm" style={{ color: 'var(--text)' }}>{selectedFile.name}</div>
                <div className="mono-label mt-1">{formatBytes(selectedFile.size)}</div>
                <button
                  className="mt-3 text-xs hover:opacity-80"
                  style={{ color: 'var(--muted)' }}
                  onClick={(e) => { e.stopPropagation(); setSelectedFile(null); if (fileInputRef.current) fileInputRef.current.value = '' }}
                >
                  Remove file ✕
                </button>
              </div>
            ) : (
              <div className="text-center">
                <div className="text-4xl mb-2">☁️</div>
                <div className="text-sm font-medium" style={{ color: 'var(--text)' }}>
                  Drop scanner file here or <span style={{ color: 'var(--amber)' }}>click to browse</span>
                </div>
                <div className="mono-label mt-1">.nessus · .xml · .csv</div>
              </div>
            )}
          </div>

          {/* Options row */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <div className="mono-label mb-2">Scanner Type</div>
              <select style={{ ...inputStyle, cursor: 'pointer' }} value={scannerType} onChange={(e) => setScannerType(e.target.value)}>
                {SCANNER_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div>
              <div className="mono-label mb-2">Uploaded By (optional)</div>
              <input
                style={inputStyle}
                type="text"
                placeholder="Your name or team…"
                value={uploadedBy}
                onChange={(e) => setUploadedBy(e.target.value)}
              />
            </div>
          </div>

          {/* Pipeline progress */}
          {(uploading || pipelineStatus) && pipelineStatus !== 'done' && pipelineStatus !== 'failed' && (
            <div className="space-y-2">
              <div className="mono-label mb-3">Pipeline Progress</div>
              <div className="flex items-center gap-2">
                {STATUS_STEPS.filter((s) => s.key !== 'failed').map((step, i) => {
                  const stepIdx = STATUS_STEPS.findIndex((s) => s.key === step.key)
                  const active = stepIdx === currentStepIndex
                  const done = stepIdx < currentStepIndex || pipelineStatus === 'done'
                  return (
                    <div key={step.key} className="flex items-center gap-2">
                      <div className="flex items-center gap-1.5">
                        <div
                          className={`w-2 h-2 rounded-full flex-shrink-0 ${active ? 'animate-pulse' : ''}`}
                          style={{ background: done ? 'var(--green)' : active ? 'var(--amber)' : 'var(--border)' }}
                        />
                        <span className="text-xs" style={{ color: done ? 'var(--green)' : active ? 'var(--amber)' : 'var(--muted)', fontFamily: '"IBM Plex Mono", monospace' }}>
                          {step.label}
                        </span>
                      </div>
                      {i < STATUS_STEPS.length - 2 && (
                        <span style={{ color: 'var(--border)' }}>→</span>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Error */}
          {uploadError && (
            <div
              className="px-4 py-3 rounded text-sm"
              style={{ background: 'rgba(224,82,82,0.1)', border: '1px solid rgba(224,82,82,0.3)', color: 'var(--red)' }}
            >
              ✕ {uploadError}
            </div>
          )}

          {/* Submit */}
          <button
            className="btn-amber w-full py-3 text-base font-semibold"
            disabled={!selectedFile || uploading}
            onClick={handleSubmit}
          >
            {uploading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 rounded-full border-2 border-t-transparent animate-spin" style={{ borderColor: 'rgba(0,0,0,0.3)', borderTopColor: 'transparent' }} />
                Processing…
              </span>
            ) : '⬆ Upload & Run Pipeline'}
          </button>
        </div>
      )}

      {/* Results panel */}
      {uploadResult && uploadResult.status === 'done' && (
        <div
          className="vra-card space-y-5"
          style={{ borderColor: 'rgba(78,175,124,0.5)', borderLeftWidth: 3 }}
        >
          <div className="flex items-center gap-3">
            <span className="text-2xl">✅</span>
            <h2 className="font-syne font-bold text-xl text-white">Pipeline Complete</h2>
          </div>

          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatBox label="New Jobs" value={uploadResult.stats?.new_jobs} color="var(--green)" />
            <StatBox label="Updated Jobs" value={uploadResult.stats?.updated_jobs} color="var(--amber)" />
            <StatBox label="New Findings" value={uploadResult.stats?.new_findings} color="var(--green)" />
            <StatBox label="Re-detected" value={uploadResult.stats?.redetected_findings} color="var(--amber)" />
          </div>

          <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
            <div className="text-center">
              <div className="text-xl font-bold font-syne" style={{ color: 'var(--muted)', textDecoration: 'line-through' }}>
                {uploadResult.stats?.cves_gone ?? '—'}
              </div>
              <div className="mono-label mt-1">CVEs Gone</div>
            </div>
            <StatBox label="Total CVEs" value={uploadResult.stats?.total_cves} />
            <StatBox label="Total Assets" value={uploadResult.stats?.total_assets} />
          </div>

          <button className="btn-amber" onClick={() => navigate('/jobs')}>
            View Jobs →
          </button>
        </div>
      )}

      {/* Failed state */}
      {uploadResult && uploadResult.status === 'failed' && (
        <div
          className="vra-card"
          style={{ borderColor: 'rgba(224,82,82,0.5)', borderLeftWidth: 3 }}
        >
          <div className="flex items-center gap-2 mb-3">
            <span className="text-2xl">❌</span>
            <h2 className="font-syne font-bold text-xl" style={{ color: 'var(--red)' }}>Pipeline Failed</h2>
          </div>
          <p className="text-sm font-mono" style={{ color: 'var(--red)' }}>
            {uploadResult.error_message || 'An unknown error occurred during processing.'}
          </p>
          <button className="btn-ghost mt-4 text-sm" onClick={() => { setUploadResult(null); setPipelineStatus(null) }}>
            Try Again
          </button>
        </div>
      )}

      {/* Upload history */}
      <div className="vra-card">
        <div className="flex items-center justify-between mb-4">
          <div className="mono-label">Upload History</div>
          <button className="btn-ghost text-xs" onClick={loadHistory}>Refresh</button>
        </div>
        {historyLoading ? (
          <div className="text-center py-6 text-sm" style={{ color: 'var(--muted)' }}>Loading…</div>
        ) : history.length === 0 ? (
          <div className="text-center py-8 text-sm" style={{ color: 'var(--muted)' }}>
            <div className="text-3xl mb-2">📂</div>
            No uploads yet
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Filename', 'Scanner', 'Uploaded At', 'Status', 'Stats'].map((h) => (
                    <th key={h} className="text-left py-2 px-3 mono-label">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr
                    key={item.id ?? item.upload_id}
                    style={{ borderBottom: '1px solid var(--border)' }}
                    className="hover:bg-[var(--surface-2)] transition-colors"
                  >
                    <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--text)' }}>
                      {item.filename || item.file_name || '—'}
                    </td>
                    <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {item.scanner_type || 'auto'}
                    </td>
                    <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {item.uploaded_at || item.created_at
                        ? new Date(item.uploaded_at || item.created_at).toLocaleString()
                        : '—'}
                    </td>
                    <td className="py-2 px-3">
                      <StatusBadgeSmall status={item.status} />
                    </td>
                    <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                      {item.stats ? (
                        <span>
                          {item.stats.new_jobs ?? 0} new ·{' '}
                          <span style={{ color: 'var(--amber)' }}>{item.stats.redetected_findings ?? 0} re-det</span>
                        </span>
                      ) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
