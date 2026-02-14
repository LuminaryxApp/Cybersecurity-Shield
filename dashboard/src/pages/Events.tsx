import { useState } from 'react'
import { useEvents } from '../hooks/useApi'
import SeverityBadge from '../components/SeverityBadge'

export default function Events() {
  const [sourceFilter, setSourceFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const { data: events, isLoading } = useEvents({
    source: sourceFilter || undefined,
    severity: severityFilter || undefined,
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-4">
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Sources</option>
          <option value="syslog">Syslog</option>
          <option value="nginx">Nginx</option>
          <option value="auth">Auth</option>
          <option value="network">Network</option>
          <option value="cloud">Cloud</option>
        </select>

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

        <span className="text-sm text-gray-500 self-center">
          {(events ?? []).length} events
        </span>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
        </div>
      ) : (
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-800/50">
                  <th className="text-left px-4 py-3 text-gray-400 font-medium">Time</th>
                  <th className="text-left px-4 py-3 text-gray-400 font-medium">Source</th>
                  <th className="text-left px-4 py-3 text-gray-400 font-medium">Category</th>
                  <th className="text-left px-4 py-3 text-gray-400 font-medium">Severity</th>
                  <th className="text-left px-4 py-3 text-gray-400 font-medium">Agent</th>
                  <th className="text-left px-4 py-3 text-gray-400 font-medium">Summary</th>
                </tr>
              </thead>
              <tbody>
                {(events ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-12 text-center text-gray-600">
                      No events found
                    </td>
                  </tr>
                ) : (
                  (events ?? []).map((event, i) => (
                    <>
                      <tr
                        key={i}
                        className={`border-t border-gray-800 cursor-pointer hover:bg-gray-800/30 transition-colors ${
                          expandedRow === i ? 'bg-gray-800/20' : ''
                        }`}
                        onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                      >
                        <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                          {new Date(event.time).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-gray-300">{event.source}</td>
                        <td className="px-4 py-3 text-gray-300 capitalize">{event.category.replace(/_/g, ' ')}</td>
                        <td className="px-4 py-3"><SeverityBadge severity={event.severity} /></td>
                        <td className="px-4 py-3 text-gray-400 text-xs">{event.agent_id || 'N/A'}</td>
                        <td className="px-4 py-3 text-gray-400 max-w-xs truncate">{event.summary}</td>
                      </tr>
                      {expandedRow === i && (
                        <tr key={`${i}-detail`} className="border-t border-gray-800">
                          <td colSpan={6} className="px-4 py-4 bg-gray-800/10">
                            <div className="space-y-2">
                              <h4 className="text-xs font-medium text-gray-400 uppercase">Event Payload</h4>
                              <pre className="text-xs text-gray-300 bg-gray-800 rounded-lg p-3 overflow-auto max-h-40">
                                {JSON.stringify(event.payload, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
