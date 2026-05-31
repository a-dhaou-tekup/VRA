import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchTickets, fetchJobs, createTicket } from '../api/client'
import { jobLabel } from '../utils/jobLabel'

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 rounded-full border-2 animate-spin" style={{ borderColor: 'var(--border)', borderTopColor: 'var(--amber)' }} />
    </div>
  )
}

function CreateTicketModal({ jobId, onClose, onCreated }) {
  const [provider, setProvider] = useState('console')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      await createTicket(jobId, { provider })
      onCreated()
      onClose()
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to create ticket')
    } finally {
      setLoading(false)
    }
  }

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
    cursor: 'pointer',
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.7)' }}
      onClick={onClose}
    >
      <div
        className="vra-card w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-syne font-bold text-lg text-white">Create Ticket</h2>
          <button className="text-xl hover:opacity-70" style={{ color: 'var(--muted)' }} onClick={onClose}>✕</button>
        </div>
        <div className="mono-label mb-2">Job ID</div>
        <div className="mb-4 font-mono text-sm" style={{ color: 'var(--amber)' }}>{jobId}</div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <div className="mono-label mb-2">Provider</div>
            <select style={inputStyle} value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="console">Console</option>
              <option value="jira">Jira</option>
            </select>
          </div>
          {error && (
            <div className="text-sm px-3 py-2 rounded" style={{ background: 'rgba(224,82,82,0.1)', color: 'var(--red)', border: '1px solid rgba(224,82,82,0.3)' }}>
              {error}
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" className="btn-ghost text-sm" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-amber" disabled={loading}>
              {loading ? 'Creating…' : 'Create Ticket'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Tickets() {
  const navigate = useNavigate()
  const [tickets, setTickets] = useState([])
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [modalJobId, setModalJobId] = useState(null)

  const load = () => {
    Promise.all([fetchTickets(), fetchJobs({ limit: 200 })])
      .then(([ticketsRes, jobsRes]) => {
        setTickets(ticketsRes.data?.data ?? [])
        setJobs(jobsRes.data?.data ?? [])
      })
      .catch((e) => setError(e.message || 'Failed to load tickets'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const ticketedJobIds = new Set(tickets.map((t) => t.job_id))
  const jobsWithoutTicket = jobs.filter((j) => !ticketedJobIds.has(j.job_id))

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="page-title">Tickets</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
          Track and create tickets for remediation jobs
        </p>
      </div>

      {loading ? (
        <Spinner />
      ) : error ? (
        <div className="vra-card" style={{ borderColor: 'var(--red)' }}>
          <p className="font-mono text-sm" style={{ color: 'var(--red)' }}>{error}</p>
        </div>
      ) : (
        <>
          {/* Existing tickets */}
          <div className="vra-card">
            <div className="mono-label mb-4">Existing Tickets ({tickets.length})</div>
            {tickets.length === 0 ? (
              <div className="text-center py-8 text-sm" style={{ color: 'var(--muted)' }}>
                No tickets created yet
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Job ID', 'Provider', 'Ticket ID', 'Created At'].map((h) => (
                        <th key={h} className="text-left py-2 px-3 mono-label">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {tickets.map((ticket) => (
                      <tr key={ticket.id ?? ticket.ticket_id} style={{ borderBottom: '1px solid var(--border)' }} className="hover:bg-[var(--surface-2)] transition-colors">
                        <td className="py-2 px-3 font-mono text-xs min-w-[200px]" style={{ color: 'var(--amber)' }}>
                          <span
                            className="cursor-pointer hover:underline block"
                            onClick={() => navigate(`/jobs/${ticket.job_id}`)}
                            title={ticket.job_id}
                          >
                            {jobs.find(j => j.job_id === ticket.job_id)
                              ? jobLabel(jobs.find(j => j.job_id === ticket.job_id))
                              : ticket.job_id.slice(0, 8) + '…'}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <span className="mono-label" style={{ textTransform: 'capitalize', letterSpacing: '0.05em' }}>
                            {ticket.provider}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-mono text-xs">
                          {/* console:// URLs aren't real — route internally to the job */}
                          {ticket.provider === 'console' || !ticket.ticket_url || ticket.ticket_url.startsWith('console://') ? (
                            <button
                              className="underline hover:opacity-80 text-left"
                              style={{ color: 'var(--amber)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit', fontSize: 'inherit' }}
                              onClick={() => navigate(`/jobs/${ticket.job_id}`)}
                              title="View job detail"
                            >
                              {ticket.ticket_id}
                            </button>
                          ) : (
                            <a
                              href={ticket.ticket_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="underline hover:opacity-80"
                              style={{ color: 'var(--blue)' }}
                            >
                              {ticket.ticket_id}
                            </a>
                          )}
                        </td>
                        <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                          {ticket.created_at ? new Date(ticket.created_at).toLocaleString() : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Jobs without tickets */}
          {jobsWithoutTicket.length > 0 && (
            <div className="vra-card">
              <div className="mono-label mb-4">Remediation Jobs Without Tickets ({jobsWithoutTicket.length})</div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Job ID', 'Product', 'Risk', 'Status', ''].map((h) => (
                        <th key={h} className="text-left py-2 px-3 mono-label">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {jobsWithoutTicket.map((job) => (
                      <tr key={job.job_id} style={{ borderBottom: '1px solid var(--border)' }} className="hover:bg-[var(--surface-2)] transition-colors">
                        <td className="py-2 px-3 font-mono text-xs min-w-[200px]" style={{ color: 'var(--amber)' }}>
                          <span
                            className="cursor-pointer hover:underline block"
                            onClick={() => navigate(`/jobs/${job.job_id}`)}
                            title={job.job_id}
                          >
                            {jobLabel(job)}
                          </span>
                        </td>
                        <td className="py-2 px-3" style={{ color: 'var(--text)' }}>{job.product_name || job.main_product || '—'}</td>
                        <td className="py-2 px-3">
                          <span className={`badge-${(job.risk_level || 'info').toLowerCase()}`}>{job.risk_level}</span>
                        </td>
                        <td className="py-2 px-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>{job.status}</td>
                        <td className="py-2 px-3 text-right">
                          <button
                            className="btn-amber text-xs px-3 py-1"
                            onClick={() => setModalJobId(job.job_id)}
                          >
                            + Create Ticket
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {modalJobId && (
        <CreateTicketModal
          jobId={modalJobId}
          onClose={() => setModalJobId(null)}
          onCreated={() => { setLoading(true); load() }}
        />
      )}
    </div>
  )
}
