import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import axios from 'axios'

export default function NewScan() {
  const navigate = useNavigate()
  const [targetUrl, setTargetUrl] = useState('')
  const [mode, setMode] = useState('normal')

  const createScan = useMutation({
    mutationFn: async (data) => {
      const response = await axios.post('/api/scans', data)
      return response.data
    },
    onSuccess: (data) => {
      navigate(`/scans/${data.scan_id}`)
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    createScan.mutate({
      target_url: targetUrl,
      mode: mode,
    })
  }

  return (
    <div className="max-w-2xl space-y-6">
      {/* Header */}
      <div>
        <button
          onClick={() => navigate(-1)}
          className="flex items-center text-sm text-slate-400 hover:text-white mb-4"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back
        </button>
        <h1 className="text-3xl font-bold text-white">New Scan</h1>
        <p className="mt-2 text-slate-400">
          Configure and start a new penetration test scan
        </p>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 space-y-6">
          {/* Target URL */}
          <div>
            <label
              htmlFor="target"
              className="block text-sm font-medium text-slate-300 mb-2"
            >
              Target URL
            </label>
            <input
              type="url"
              id="target"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              required
              className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
            <p className="mt-2 text-sm text-slate-400">
              Enter the URL of the target application you want to test
            </p>
          </div>

          {/* Scan Mode */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Scan Mode
            </label>
            <div className="grid grid-cols-2 gap-4">
              {[
                {
                  value: 'quick',
                  name: 'Quick Scan',
                  description: 'Fast scan with basic checks',
                },
                {
                  value: 'normal',
                  name: 'Normal Scan',
                  description: 'Balanced scan covering common vulnerabilities',
                },
                {
                  value: 'deep',
                  name: 'Deep Scan',
                  description: 'Comprehensive scan with all tests',
                },
                {
                  value: 'targeted',
                  name: 'Targeted Scan',
                  description: 'Focus on specific vulnerability types',
                },
              ].map((option) => (
                <label
                  key={option.value}
                  className={`
                    relative flex flex-col p-4 border rounded-lg cursor-pointer
                    ${
                      mode === option.value
                        ? 'border-cyan-500 bg-cyan-500/10'
                        : 'border-slate-700 bg-slate-900 hover:border-slate-600'
                    }
                  `}
                >
                  <input
                    type="radio"
                    value={option.value}
                    checked={mode === option.value}
                    onChange={(e) => setMode(e.target.value)}
                    className="sr-only"
                  />
                  <span className="text-sm font-medium text-white">
                    {option.name}
                  </span>
                  <span className="mt-1 text-xs text-slate-400">
                    {option.description}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Warning */}
          <div className="p-4 bg-yellow-500/10 border border-yellow-500/50 rounded-lg">
            <p className="text-sm text-yellow-400">
              <strong>⚠️ Warning:</strong> Only scan applications you own or
              have explicit permission to test. Unauthorized penetration
              testing is illegal.
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end space-x-4">
          <button
            type="button"
            onClick={() => navigate(-1)}
            className="px-6 py-2 text-sm font-medium text-slate-300 bg-slate-700 rounded-lg hover:bg-slate-600"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={createScan.isPending}
            className="px-6 py-2 text-sm font-medium text-white bg-cyan-500 rounded-lg hover:bg-cyan-600 disabled:opacity-50"
          >
            {createScan.isPending ? 'Starting...' : 'Start Scan'}
          </button>
        </div>

        {createScan.isError && (
          <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
            <p className="text-sm text-red-400">
              Error: {createScan.error.message}
            </p>
          </div>
        )}
      </form>
    </div>
  )
}

