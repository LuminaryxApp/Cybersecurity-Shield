import { useState } from 'react'
import { useAlerts, useUpdateAlertStatus } from '../hooks/useApi'
import SeverityBadge from '../components/SeverityBadge'
import StatusBadge from '../components/StatusBadge'

export default function Alerts() {
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const { data: alerts, isLoading } = useAlerts({
    severity: severityFilter || undefined,
    status: statusFilter || undefined,
  })
  const updateStatus = useUpdateAlertStatus()

  const handleStatusChange = (id: string, status: string) => {
    updateStatus.mutate({ id, status })
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-4">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
        </div>
      ) : (alerts ?? []).length === 0 ? (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-12 text-center">
          <p className="text-gray-500">No alerts found</p>
        </div>
      ) : (
        <div className="space-y-3">
          {(alerts ?? []).map((alert) => (
            <div key={alert.id} className="bg-gray-900 rounded-xl border border-gray-800 p-5">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <SeverityBadge severity={alert.severity} size="md" />
                    <StatusBadge status={alert.status} />
                    <span className="text-xs text-gray-500 capitalize">{alert.source}</span>
                  </div>
                  <h3 className="text-base font-medium text-white">{alert.title}</h3>
                  <p className="text-sm text-gray-400 mt-1">{alert.description}</p>
                  <div className="flex gap-4 mt-3 text-xs text-gray-500">
                    <span>Agent: {alert.agent_id || 'N/A'}</span>
                    <span>Score: {alert.risk_score?.toFixed(1) || '0'}</span>
                    <span>Events: {alert.event_count || 1}</span>
                    <span>{new Date(alert.created_at).toLocaleString()}</span>
                  </div>
                </div>

                <div className="flex gap-2 ml-4">
                  {alert.status === 'open' && (
                    <>
                      <button
                        onClick={() => handleStatusChange(alert.id, 'acknowledged')}
                        className="px-3 py-1.5 text-xs font-medium bg-yellow-500/10 text-yellow-400 rounded-lg hover:bg-yellow-500/20 transition-colors"
                      >
                        Acknowledge
                      </button>
                      <button
                        onClick={() => handleStatusChange(alert.id, 'resolved')}
                        className="px-3 py-1.5 text-xs font-medium bg-green-500/10 text-green-400 rounded-lg hover:bg-green-500/20 transition-colors"
                      >
                        Resolve
                      </button>
                    </>
                  )}
                  {alert.status === 'acknowledged' && (
                    <button
                      onClick={() => handleStatusChange(alert.id, 'resolved')}
                      className="px-3 py-1.5 text-xs font-medium bg-green-500/10 text-green-400 rounded-lg hover:bg-green-500/20 transition-colors"
                    >
                      Resolve
                    </button>
                  )}
                  {alert.status !== 'dismissed' && alert.status !== 'resolved' && (
                    <button
                      onClick={() => handleStatusChange(alert.id, 'dismissed')}
                      className="px-3 py-1.5 text-xs font-medium bg-gray-500/10 text-gray-400 rounded-lg hover:bg-gray-500/20 transition-colors"
                    >
                      Dismiss
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
