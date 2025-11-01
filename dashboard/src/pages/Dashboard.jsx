import { useQuery } from '@tanstack/react-query'
import { Shield, AlertTriangle, TrendingUp, Activity } from 'lucide-react'
import axios from 'axios'

export default function Dashboard() {
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const response = await axios.get('/api/stats')
      return response.data
    },
  })

  const { data: recentScans } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await axios.get('/api/scans')
      return response.data.scans.slice(0, 5)
    },
  })

  const statCards = [
    {
      name: 'Total Scans',
      value: stats?.total_scans || 0,
      icon: Activity,
      color: 'bg-blue-500',
    },
    {
      name: 'Total Vulnerabilities',
      value: stats?.total_vulnerabilities || 0,
      icon: AlertTriangle,
      color: 'bg-red-500',
    },
    {
      name: 'Critical Issues',
      value: stats?.by_severity?.critical || 0,
      icon: Shield,
      color: 'bg-purple-500',
    },
    {
      name: 'Scan Success Rate',
      value: '95%',
      icon: TrendingUp,
      color: 'bg-green-500',
    },
  ]

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="mt-2 text-slate-400">
          Overview of your penetration testing activities
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => {
          const Icon = stat.icon
          return (
            <div
              key={stat.name}
              className="px-6 py-5 bg-slate-800 border border-slate-700 rounded-lg"
            >
              <div className="flex items-center">
                <div className={`p-3 rounded-lg ${stat.color}`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-slate-400">
                    {stat.name}
                  </p>
                  <p className="text-2xl font-semibold text-white">
                    {stat.value}
                  </p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Recent Scans */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg">
        <div className="px-6 py-4 border-b border-slate-700">
          <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
        </div>
        <div className="p-6">
          {recentScans && recentScans.length > 0 ? (
            <div className="space-y-4">
              {recentScans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between p-4 bg-slate-900 rounded-lg"
                >
                  <div>
                    <p className="font-medium text-white">{scan.target_url}</p>
                    <p className="text-sm text-slate-400">
                      {new Date(scan.start_time).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center space-x-4">
                    <span className="px-3 py-1 text-xs font-medium text-cyan-400 bg-cyan-500/10 rounded-full">
                      {scan.status}
                    </span>
                    <span className="text-sm text-slate-400">
                      {scan.vulnerabilities?.length || 0} vulns
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-center text-slate-400">No recent scans</p>
          )}
        </div>
      </div>

      {/* Vulnerability Distribution */}
      {stats?.by_severity && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg">
          <div className="px-6 py-4 border-b border-slate-700">
            <h2 className="text-lg font-semibold text-white">
              Vulnerability Distribution
            </h2>
          </div>
          <div className="p-6">
            <div className="space-y-3">
              {Object.entries(stats.by_severity).map(([severity, count]) => {
                const colors = {
                  critical: 'bg-red-500',
                  high: 'bg-orange-500',
                  medium: 'bg-yellow-500',
                  low: 'bg-blue-500',
                  info: 'bg-gray-500',
                }

                const percentage =
                  (count / stats.total_vulnerabilities) * 100 || 0

                return (
                  <div key={severity}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-slate-300 capitalize">
                        {severity}
                      </span>
                      <span className="text-sm text-slate-400">
                        {count} ({percentage.toFixed(1)}%)
                      </span>
                    </div>
                    <div className="w-full bg-slate-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${colors[severity]}`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

