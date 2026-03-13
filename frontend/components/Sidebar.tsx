import { Home, Flame, Zap, Package, BarChart3, Settings, Shield, AlertCircle, CheckSquare } from 'lucide-react'

interface SidebarProps {
  activeView: string
  setActiveView: (view: string) => void
}

export default function Sidebar({ activeView, setActiveView }: SidebarProps) {
  const menuItems = [
    { id: 'overview', label: 'Overview', icon: Home },
    { id: 'risks', label: 'Top Risks', icon: Flame },
    { id: 'alerts', label: 'Alerts', icon: AlertCircle },
    { id: 'actions', label: 'Actions', icon: CheckSquare },
    { id: 'simulator', label: 'Attack Simulator', icon: Zap },
    { id: 'assets', label: 'Assets', icon: Package },
    { id: 'reports', label: 'Reports', icon: BarChart3 },
    { id: 'executive', label: 'Executive View', icon: Shield },
    { id: 'settings', label: 'Settings', icon: Settings },
  ]

  return (
    <aside className="fixed left-0 top-16 w-64 h-[calc(100vh-4rem)] bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 overflow-y-auto transition-colors">
      <nav className="p-4 space-y-1">
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = activeView === item.id
          
          return (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id)}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-md transition-colors text-left ${
                isActive
                  ? 'bg-primary text-white'
                  : 'text-gray-700 dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="text-sm font-medium">{item.label}</span>
            </button>
          )
        })}
      </nav>
    </aside>
  )
}
