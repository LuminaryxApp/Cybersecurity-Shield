import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import ThreatGauge from '../components/ThreatGauge'
import SeverityBadge from '../components/SeverityBadge'
import { useThreatScore, useAlerts, useEvents, useAgents } from '../hooks/useApi'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280']

export default function Dashboard() {
  const { data: threatScore } = useThreatScore('default')
  const { data: alerts } = useAlerts()
  const { data: events } = useEvents()
  const { data: agents } = useAgents()

  const score = threatScore?.score ?? 100
  const trend = threatScore?.trend ?? 0
  const factors = threatScore?.factors ?? {}

  const recentAlerts = (alerts ?? []).slice(0, 5)
  const recentEvents = (events ?? []).slice(0, 10)

  const activeAgents = (agents ?? []).filter(a => a.status === 'online').length
  const totalAgents = (agents ?? []).length

  const openAlerts = (alerts ?? []).filter(a => a.status === 'open').length
  const criticalAlerts = (alerts ?? []).filter(a => a.severity === 'critical').length

  const severityDistribution = Object.entries(
    (events ?? []).reduce<Record<string, number>>((acc, e) => {
      acc[e.severity] = (acc[e.severity] || 0) + 1
      return acc
    }, {})
  ).map(([name, value]) => ({ name, value }))

  const factorData = Object.entries(factors).map(([name, value]) => ({ name, value }))

  const timeSeriesData = (events ?? []).slice(0, 50).reverse().map((e, i) => ({
    time: new Date(e.time).toLocaleTimeString(),
    events: i + 1,
    risk: e.risk_score,
  }))

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Agents Online" value={`${activeAgents}/${totalAgents}`} color="cyan" />
        <StatCard title="Open Alerts" value={openAlerts.toString()} color={openAlerts > 0 ? 'red' : 'green'} />
        <StatCard title="Critical" value={criticalAlerts.toString()} color={criticalAlerts > 0 ? 'red' : 'gray'} />
        <StatCard title="Events (24h)" value={(events ?? []).length.toString()} color="blue" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ThreatGauge score={score} trend={trend} />

        <div className="lg:col-span-2 bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Event Timeline</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <defs>
                  <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="time" stroke="#4b5563" fontSize={11} />
                <YAxis stroke="#4b5563" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#9ca3af' }}
                />
                <Area type="monotone" dataKey="events" stroke="#06b6d4" fill="url(#eventGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Severity Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityDistribution.length > 0 ? severityDistribution : [{ name: 'none', value: 1 }]}
                  cx="50%" cy="50%" innerRadius={40} outerRadius={70}
                  dataKey="value" paddingAngle={2}
                >
                  {severityDistribution.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap gap-3 mt-2 justify-center">
            {severityDistribution.map((item, i) => (
              <div key={item.name} className="flex items-center gap-1.5 text-xs text-gray-400">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                <span className="capitalize">{item.name}: {item.value}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h3 className="text-sm font-medium text-gray-400 mb-4">Risk Factors</h3>
          <div className="space-y-3">
            {factorData.length === 0 ? (
              <p className="text-sm text-gray-600">No risk factors detected</p>
            ) : (
              factorData.sort((a, b) => b.value - a.value).slice(0, 6).map((factor) => (
                <div key={factor.name}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-300 capitalize">{factor.name.replace(/_/g, ' ')}</span>
                    <span className="text-gray-500">{factor.value.toFixed(1)}</span>
                  </div>
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-cyan-500 rounded-full transition-all"
                      style={{ width: `${Math.min((factor.value / 20) * 100, 100)}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Recent Alerts</h3>
        {recentAlerts.length === 0 ? (
          <p className="text-sm text-gray-600">No recent alerts</p>
        ) : (
          <div className="space-y-2">
            {recentAlerts.map((alert) => (
              <div key={alert.id} className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={alert.severity} />
                  <span className="text-sm text-gray-200">{alert.title}</span>
                </div>
                <span className="text-xs text-gray-500">
                  {new Date(alert.created_at).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Recent Events</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-left">
                <th className="pb-3 font-medium">Time</th>
                <th className="pb-3 font-medium">Source</th>
                <th className="pb-3 font-medium">Category</th>
                <th className="pb-3 font-medium">Severity</th>
                <th className="pb-3 font-medium">Summary</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.length === 0 ? (
                <tr><td colSpan={5} className="py-4 text-gray-600 text-center">No events recorded</td></tr>
              ) : (
                recentEvents.map((event, i) => (
                  <tr key={i} className="border-t border-gray-800">
                    <td className="py-2 text-gray-400">{new Date(event.time).toLocaleTimeString()}</td>
                    <td className="py-2 text-gray-300">{event.source}</td>
                    <td className="py-2 text-gray-300 capitalize">{event.category.replace(/_/g, ' ')}</td>
                    <td className="py-2"><SeverityBadge severity={event.severity} /></td>
                    <td className="py-2 text-gray-400 max-w-xs truncate">{event.summary}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, color }: { title: string; value: string; color: string }) {
  const colorMap: Record<string, string> = {
    cyan: 'text-cyan-400',
    red: 'text-red-400',
    green: 'text-green-400',
    blue: 'text-blue-400',
    gray: 'text-gray-400',
  }

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
      <p className="text-xs text-gray-500 uppercase tracking-wider">{title}</p>
      <p className={`text-2xl font-bold mt-1 ${colorMap[color] || 'text-white'}`}>{value}</p>
    </div>
  )
}
