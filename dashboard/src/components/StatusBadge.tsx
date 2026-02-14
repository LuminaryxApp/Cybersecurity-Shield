interface StatusBadgeProps {
  status: string
}

const statusConfig: Record<string, { bg: string; text: string; dot: string }> = {
  online: { bg: 'bg-green-500/10', text: 'text-green-400', dot: 'bg-green-400' },
  offline: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-400' },
  open: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-400' },
  acknowledged: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', dot: 'bg-yellow-400' },
  resolved: { bg: 'bg-green-500/10', text: 'text-green-400', dot: 'bg-green-400' },
  dismissed: { bg: 'bg-gray-500/10', text: 'text-gray-400', dot: 'bg-gray-400' },
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig.offline

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium capitalize ${config.bg} ${config.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {status}
    </span>
  )
}
