interface ThreatGaugeProps {
  score: number
  trend: number
}

export default function ThreatGauge({ score, trend }: ThreatGaugeProps) {
  const getColor = (s: number) => {
    if (s >= 80) return { text: 'text-green-400', bg: 'bg-green-500', label: 'Good' }
    if (s >= 60) return { text: 'text-yellow-400', bg: 'bg-yellow-500', label: 'Fair' }
    if (s >= 40) return { text: 'text-orange-400', bg: 'bg-orange-500', label: 'Warning' }
    if (s >= 20) return { text: 'text-red-400', bg: 'bg-red-500', label: 'Poor' }
    return { text: 'text-red-500', bg: 'bg-red-600', label: 'Critical' }
  }

  const color = getColor(score)
  const circumference = 2 * Math.PI * 60
  const dashoffset = circumference - (score / 100) * circumference

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
      <h3 className="text-sm font-medium text-gray-400 mb-4">Threat Score</h3>
      <div className="flex items-center justify-center">
        <div className="relative">
          <svg width="160" height="160" className="-rotate-90">
            <circle cx="80" cy="80" r="60" fill="none" stroke="#1f2937" strokeWidth="12" />
            <circle
              cx="80" cy="80" r="60" fill="none"
              stroke="currentColor"
              strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={dashoffset}
              strokeLinecap="round"
              className={color.text}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-3xl font-bold ${color.text}`}>{Math.round(score)}</span>
            <span className="text-xs text-gray-500">{color.label}</span>
          </div>
        </div>
      </div>
      <div className="mt-4 text-center">
        <span className={`text-sm ${trend > 0 ? 'text-green-400' : trend < 0 ? 'text-red-400' : 'text-gray-500'}`}>
          {trend > 0 ? '+' : ''}{trend.toFixed(1)} from last period
        </span>
      </div>
    </div>
  )
}
