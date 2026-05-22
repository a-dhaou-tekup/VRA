export default function RiskBadge({ level }) {
  if (!level) return <span className="badge-info">—</span>

  const normalized = level.toString().toUpperCase()

  switch (normalized) {
    case 'CRITICAL':
      return <span className="badge-critical">Critical</span>
    case 'HIGH':
      return <span className="badge-high">High</span>
    case 'MEDIUM':
      return <span className="badge-medium">Medium</span>
    case 'LOW':
      return <span className="badge-low">Low</span>
    default:
      return <span className="badge-info">{level}</span>
  }
}
