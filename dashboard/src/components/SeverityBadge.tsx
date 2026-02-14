interface SeverityBadgeProps {
  severity: string
  size?: 'sm' | 'md'
}

const severityConfig: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-400' },
  info: { bg: 'bg-gray-500/10', text: 'text-gray-400' },
}

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const config = severityConfig[severity] || severityConfig.info
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'

  return (
    <span className={`inline-flex items-center rounded-full font-medium capitalize ${config.bg} ${config.text} ${sizeClasses}`}>
      {severity}
    </span>
  )
}
