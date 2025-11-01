import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, AlertTriangle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

export default function ScanDetails() {
  const { scanId } = useParams()
  const navigate = useNavigate()

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: async () => {
      const response = await axios.get(`/api/scans/${scanId}`)
      return response.data
    },
  })

  const severityColors = {
    critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500' },
    high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500' },
    medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500' },
    low: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500' },
    info: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500' },
  }

  if (isLoading) {
    return <div className="text-white">Loading...</div>
  }

  if (!scan) {
    return <div className="text-white">Scan not found</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <button
          onClick={() => navigate('/scans')}
          className="flex items-center text-sm text-slate-400 hover:text-white mb-4"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Scans
        </button>
        <h1 className="text-3xl font-bold text-white">Scan Details</h1>
        <p className="mt-2 text-slate-400">{scan.target_url}</p>
      </div>

      {/* Overview */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
        <div className="px-6 py-5 bg-slate-800 border border-slate-700 rounded-lg">
          <p className="text-sm font-medium text-slate-400">Status</p>
          <p className="mt-2 text-2xl font-semibold text-white capitalize">
            {scan.status}
          </p>
        </div>
        <div className="px-6 py-5 bg-slate-800 border border-slate-700 rounded-lg">
          <p className="text-sm font-medium text-slate-400">Mode</p>
          <p className="mt-2 text-2xl font-semibold text-white capitalize">
            {scan.mode}
          </p>
        </div>
        <div className="px-6 py-5 bg-slate-800 border border-slate-700 rounded-lg">
          <p className="text-sm font-medium text-slate-400">Vulnerabilities</p>
          <p className="mt-2 text-2xl font-semibold text-white">
            {scan.vulnerabilities?.length || 0}
          </p>
        </div>
      </div>

      {/* Vulnerabilities */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg">
        <div className="px-6 py-4 border-b border-slate-700">
          <h2 className="text-lg font-semibold text-white flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-yellow-400" />
            Vulnerabilities Found
          </h2>
        </div>
        <div className="p-6 space-y-4">
          {scan.vulnerabilities && scan.vulnerabilities.length > 0 ? (
            scan.vulnerabilities.map((vuln, index) => {
              const colors = severityColors[vuln.severity] || severityColors.info

              return (
                <div
                  key={index}
                  className={`p-6 border ${colors.border} ${colors.bg} rounded-lg`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <span
                          className={`px-2 py-1 text-xs font-medium ${colors.text} uppercase`}
                        >
                          {vuln.severity}
                        </span>
                        <span className="text-xs text-slate-400">
                          {vuln.vuln_type}
                        </span>
                      </div>
                      <h3 className="mt-2 text-lg font-semibold text-white">
                        {vuln.title}
                      </h3>
                      <p className="mt-2 text-sm text-slate-300">
                        {vuln.description}
                      </p>

                      {/* Evidence */}
                      <div className="mt-4">
                        <p className="text-sm font-medium text-slate-400">Evidence:</p>
                        <pre className="mt-2 p-3 bg-slate-900 rounded text-xs text-slate-300 overflow-x-auto">
                          {vuln.evidence}
                        </pre>
                      </div>

                      {/* Remediation */}
                      <div className="mt-4">
                        <p className="text-sm font-medium text-slate-400">Remediation:</p>
                        <p className="mt-1 text-sm text-slate-300">
                          {vuln.remediation}
                        </p>
                      </div>

                      {/* Metadata */}
                      <div className="mt-4 flex items-center space-x-4 text-xs text-slate-400">
                        {vuln.cwe_id && <span>CWE: {vuln.cwe_id}</span>}
                        {vuln.cvss_score && (
                          <span>CVSS: {vuln.cvss_score}</span>
                        )}
                        <span className="truncate">{vuln.affected_url}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })
          ) : (
            <p className="text-center text-slate-400 py-8">
              No vulnerabilities found
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

