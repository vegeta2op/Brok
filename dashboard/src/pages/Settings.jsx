import { Settings as SettingsIcon, Key, Database, Shield } from 'lucide-react'

export default function Settings() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="mt-2 text-slate-400">
          Configure JimCrow application settings
        </p>
      </div>

      {/* Settings Sections */}
      <div className="space-y-6">
        {/* API Keys */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg">
          <div className="px-6 py-4 border-b border-slate-700">
            <h2 className="text-lg font-semibold text-white flex items-center">
              <Key className="w-5 h-5 mr-2 text-cyan-400" />
              API Configuration
            </h2>
          </div>
          <div className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                LLM Provider
              </label>
              <select className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500">
                <option>OpenAI</option>
                <option>OpenRouter</option>
                <option>Gemini</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Model
              </label>
              <input
                type="text"
                defaultValue="gpt-4o-mini"
                className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
            <p className="text-sm text-slate-400">
              Note: API keys are configured via environment variables (.env file)
            </p>
          </div>
        </div>

        {/* Supabase */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg">
          <div className="px-6 py-4 border-b border-slate-700">
            <h2 className="text-lg font-semibold text-white flex items-center">
              <Database className="w-5 h-5 mr-2 text-cyan-400" />
              Database Configuration
            </h2>
          </div>
          <div className="p-6">
            <p className="text-sm text-slate-300">
              Supabase URL and API key are configured via environment variables
            </p>
            <p className="mt-2 text-sm text-slate-400">
              Restart the application after changing database settings
            </p>
          </div>
        </div>

        {/* Security */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg">
          <div className="px-6 py-4 border-b border-slate-700">
            <h2 className="text-lg font-semibold text-white flex items-center">
              <Shield className="w-5 h-5 mr-2 text-cyan-400" />
              Security Settings
            </h2>
          </div>
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-300">
                  Request Timeout
                </p>
                <p className="text-sm text-slate-400">
                  Maximum time for HTTP requests
                </p>
              </div>
              <input
                type="number"
                defaultValue="30"
                className="w-24 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-300">
                  Rate Limit (per second)
                </p>
                <p className="text-sm text-slate-400">
                  Maximum requests per second
                </p>
              </div>
              <input
                type="number"
                defaultValue="10"
                className="w-24 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-300">
                  Max Concurrent Scans
                </p>
                <p className="text-sm text-slate-400">
                  Maximum number of parallel scans
                </p>
              </div>
              <input
                type="number"
                defaultValue="3"
                className="w-24 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
          </div>
        </div>

        {/* Info */}
        <div className="p-4 bg-blue-500/10 border border-blue-500/50 rounded-lg">
          <p className="text-sm text-blue-400">
            <strong>ℹ️ Note:</strong> Most settings require editing the .env
            file and restarting the application. The web interface provides
            read-only views of the current configuration.
          </p>
        </div>
      </div>
    </div>
  )
}

