const STATUS_STYLES = {
  TO_DO: 'bg-[rgba(136,136,136,0.12)] text-[#888] border border-[rgba(136,136,136,0.25)]',
  IN_PROGRESS: 'bg-[rgba(78,143,175,0.15)] text-[#4e8faf] border border-[rgba(78,143,175,0.3)]',
  DONE: 'bg-[rgba(78,175,124,0.15)] text-[#4eaf7c] border border-[rgba(78,175,124,0.3)]',
  CLOSED: 'bg-[rgba(136,136,136,0.08)] text-[#666] border border-[rgba(136,136,136,0.15)] line-through',
  RESURFACED: 'bg-[rgba(224,82,82,0.15)] text-[#e05252] border border-[rgba(224,82,82,0.3)]',
  CONFIRMED: 'bg-[rgba(224,82,82,0.12)] text-[#e05252] border border-[rgba(224,82,82,0.25)]',
  FALSE_POSITIVE: 'bg-[rgba(155,109,255,0.15)] text-[#9b6dff] border border-[rgba(155,109,255,0.3)]',
  RISK_ACCEPTED: 'bg-[rgba(255,196,13,0.12)] text-[#ffc40d] border border-[rgba(255,196,13,0.25)]',
  DEFERRED: 'bg-[rgba(136,136,136,0.1)] text-[#777] border border-[rgba(136,136,136,0.2)]',
}

const STATUS_LABELS = {
  TO_DO: 'To Do',
  IN_PROGRESS: 'In Progress',
  DONE: 'Done',
  CLOSED: 'Closed',
  RESURFACED: 'Resurfaced',
  CONFIRMED: 'Confirmed',
  FALSE_POSITIVE: 'False Positive',
  RISK_ACCEPTED: 'Risk Accepted',
  DEFERRED: 'Deferred',
}

export default function StatusBadge({ status }) {
  if (!status) return <span className="badge-info">—</span>

  const key = status.toString().toUpperCase()
  const cls = STATUS_STYLES[key] || 'bg-[rgba(136,136,136,0.12)] text-[#888] border border-[rgba(136,136,136,0.2)]'
  const label = STATUS_LABELS[key] || status

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold uppercase tracking-wider ${cls}`}
    >
      {label}
    </span>
  )
}
