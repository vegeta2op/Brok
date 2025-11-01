import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, ExternalLink } from 'lucide-react'
import axios from 'axios'

export default function Scans() {
  const { data: scansData, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await axios.get('/api/scans')
      return response.data.scans
    },
  })

  const severityColors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
    info: 'text-gray-400',
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Scans</h1>
          <p className="mt-2 text-slate-400">
            View and manage your penetration test scans
          </p>
        </div>
        <Link
          to="/scans/new"
          className="flex items-center px-4 py-2 text-sm font-medium text-white bg-cyan-500 rounded-lg hover:bg-cyan-600 transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          New Scan
        </Link>
      </div>

      {/* Scans Table */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-slate-700">
          <thead className="bg-slate-900">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Target
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Mode
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Vulnerabilities
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Date
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-slate-800 divide-y divide-slate-700">
            {isLoading ? (
              <tr>
                <td colSpan="6" className="px-6 py-4 text-center text-slate-400">
                  Loading...
                </td>
              </tr>
            ) : scansData && scansData.length > 0 ? (
              scansData.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-white">
                      {scan.target_url}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="px-2 py-1 text-xs font-medium text-cyan-400 bg-cyan-500/10 rounded-full">
                      {scan.mode}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="px-2 py-1 text-xs font-medium text-green-400 bg-green-500/10 rounded-full">
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {scan.vulnerabilities?.length || 0}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                    {new Date(scan.start_time).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <Link
                      to={`/scans/${scan.id}`}
                      className="text-cyan-400 hover:text-cyan-300"
                    >
                      <ExternalLink className="w-4 h-4 inline" />
                    </Link>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6" className="px-6 py-4 text-center text-slate-400">
                  No scans found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

