import { useAgents } from '../hooks/useApi'
import StatusBadge from '../components/StatusBadge'

export default function Agents() {
  const { data: agents, isLoading } = useAgents()

  const getTimeSince = (dateStr: string) => {
    if (!dateStr) return 'Never'
    const diff = Date.now() - new Date(dateStr).getTime()
    const seconds = Math.floor(diff / 1000)
    if (seconds < 60) return `${seconds}s ago`
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    return `${Math.floor(hours / 24)}d ago`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">
          {(agents ?? []).length} agents registered
        </p>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
        </div>
      ) : (agents ?? []).length === 0 ? (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-12 text-center">
          <svg className="w-12 h-12 text-gray-700 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
              d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
          </svg>
          <p className="text-gray-500">No agents registered yet</p>
          <p className="text-sm text-gray-600 mt-1">Deploy a Shield agent to start monitoring</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {(agents ?? []).map((agent) => (
            <div key={agent.id} className="bg-gray-900 rounded-xl border border-gray-800 p-5 hover:border-gray-700 transition-colors">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-sm font-medium text-white">{agent.name || agent.hostname || 'Unnamed Agent'}</h3>
                  <p className="text-xs text-gray-500 mt-0.5">{agent.id}</p>
                </div>
                <StatusBadge status={agent.status} />
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Hostname</span>
                  <span className="text-gray-300">{agent.hostname || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">IP Address</span>
                  <span className="text-gray-300 font-mono text-xs">{agent.ip_address || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">OS</span>
                  <span className="text-gray-300">{agent.os || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Version</span>
                  <span className="text-gray-300">{agent.version || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Last Heartbeat</span>
                  <span className="text-gray-300">{getTimeSince(agent.last_heartbeat)}</span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-800 flex gap-2">
                <button className="flex-1 px-3 py-1.5 text-xs font-medium bg-cyan-500/10 text-cyan-400 rounded-lg hover:bg-cyan-500/20 transition-colors">
                  Configure
                </button>
                <button className="px-3 py-1.5 text-xs font-medium bg-gray-500/10 text-gray-400 rounded-lg hover:bg-gray-500/20 transition-colors">
                  Logs
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
