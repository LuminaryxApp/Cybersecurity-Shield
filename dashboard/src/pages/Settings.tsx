import { useState } from 'react'

export default function Settings() {
  const [activeTab, setActiveTab] = useState('general')

  const tabs = [
    { id: 'general', label: 'General' },
    { id: 'notifications', label: 'Notifications' },
    { id: 'integrations', label: 'Integrations' },
    { id: 'api', label: 'API Keys' },
  ]

  return (
    <div className="space-y-6">
      <div className="flex gap-1 bg-gray-900 rounded-lg p-1 border border-gray-800 w-fit">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium rounded-md transition-colors ${
              activeTab === tab.id
                ? 'bg-gray-800 text-white'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'general' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-6">
          <h3 className="text-base font-medium text-white">Organization Settings</h3>

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Organization Name</label>
              <input
                type="text"
                defaultValue="My Organization"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-1">Scoring Window</label>
              <select className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
                <option value="1h">1 Hour</option>
                <option value="6h">6 Hours</option>
                <option value="24h" selected>24 Hours</option>
                <option value="7d">7 Days</option>
                <option value="30d">30 Days</option>
              </select>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-1">Alert Threshold</label>
              <input
                type="number"
                defaultValue="5"
                min="1"
                max="10"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-gray-600 mt-1">Minimum risk score to trigger an alert (1-10)</p>
            </div>
          </div>

          <button className="px-4 py-2 bg-cyan-500 text-gray-900 font-medium rounded-lg text-sm hover:bg-cyan-400 transition-colors">
            Save Changes
          </button>
        </div>
      )}

      {activeTab === 'notifications' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-6">
          <h3 className="text-base font-medium text-white">Notification Settings</h3>

          <div className="space-y-4">
            {['critical', 'high', 'medium', 'low'].map((level) => (
              <div key={level} className="flex items-center justify-between py-2">
                <div>
                  <span className="text-sm text-gray-200 capitalize">{level} Alerts</span>
                  <p className="text-xs text-gray-500">Receive notifications for {level} severity alerts</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    defaultChecked={level === 'critical' || level === 'high'}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-700 rounded-full peer peer-checked:bg-cyan-500 peer-focus:ring-2 peer-focus:ring-cyan-500/25 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full"></div>
                </label>
              </div>
            ))}

            <div className="pt-4 border-t border-gray-800">
              <label className="block text-sm text-gray-400 mb-1">Webhook URL</label>
              <input
                type="url"
                placeholder="https://hooks.slack.com/services/..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <button className="px-4 py-2 bg-cyan-500 text-gray-900 font-medium rounded-lg text-sm hover:bg-cyan-400 transition-colors">
            Save Notifications
          </button>
        </div>
      )}

      {activeTab === 'integrations' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-6">
          <h3 className="text-base font-medium text-white">Cloud Integrations</h3>

          <div className="space-y-4">
            {[
              { name: 'AWS', desc: 'Amazon Web Services', icon: 'aws' },
              { name: 'Azure', desc: 'Microsoft Azure', icon: 'azure' },
              { name: 'GCP', desc: 'Google Cloud Platform', icon: 'gcp' },
            ].map((provider) => (
              <div key={provider.name} className="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-gray-700 rounded-lg flex items-center justify-center text-xs font-bold text-gray-300">
                    {provider.icon.toUpperCase().slice(0, 3)}
                  </div>
                  <div>
                    <span className="text-sm text-gray-200">{provider.name}</span>
                    <p className="text-xs text-gray-500">{provider.desc}</p>
                  </div>
                </div>
                <button className="px-3 py-1.5 text-xs font-medium bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 transition-colors">
                  Configure
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'api' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 space-y-6">
          <h3 className="text-base font-medium text-white">API Configuration</h3>

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">LLM Provider</label>
              <select className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500">
                <option value="anthropic">Anthropic (Claude)</option>
                <option value="openai">OpenAI (GPT)</option>
                <option value="local">Local (No API Key)</option>
              </select>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-1">API Key</label>
              <input
                type="password"
                placeholder="sk-..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-gray-600 mt-1">Used for AI-powered threat explanations</p>
            </div>
          </div>

          <button className="px-4 py-2 bg-cyan-500 text-gray-900 font-medium rounded-lg text-sm hover:bg-cyan-400 transition-colors">
            Save API Settings
          </button>
        </div>
      )}
    </div>
  )
}
