import { Outlet, Link, useLocation } from 'react-router-dom'
import { Target, History, Plus, Database, Settings, Shield } from 'lucide-react'

export default function Layout() {
  const location = useLocation()

  const navigation = [
    { name: 'Dashboard', href: '/', icon: Shield },
    { name: 'Scans', href: '/scans', icon: History },
    { name: 'New Scan', href: '/scans/new', icon: Plus },
    { name: 'Targets', href: '/targets', icon: Target },
    { name: 'Knowledge Base', href: '/knowledge-base', icon: Database },
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-slate-800 border-r border-slate-700">
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center h-16 px-6 border-b border-slate-700">
            <Shield className="w-8 h-8 text-cyan-400" />
            <span className="ml-3 text-xl font-bold text-white">JimCrow</span>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
            {navigation.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.href

              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`
                    flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors
                    ${isActive
                      ? 'bg-cyan-500/10 text-cyan-400'
                      : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                    }
                  `}
                >
                  <Icon className="w-5 h-5 mr-3" />
                  {item.name}
                </Link>
              )
            })}
          </nav>

          {/* Footer */}
          <div className="px-6 py-4 border-t border-slate-700">
            <p className="text-xs text-slate-400">
              Version 0.1.0
            </p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="pl-64">
        <main className="p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

