import { Play, Shield, ChevronRight } from 'lucide-react'

interface RecommendedActionsProps {
  onViewAll?: () => void
}

export default function RecommendedActions({ onViewAll }: RecommendedActionsProps) {
  const actions = [
    { label: 'Run Incident Response Playbook', icon: Play, priority: 'critical' },
    { label: 'Isolate Affected Hosts (3)', icon: Shield, priority: 'critical' },
  ]

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'border-critical text-critical hover:bg-red-50 dark:hover:bg-gray-700'
      case 'high':
        return 'border-warning text-warning hover:bg-amber-50 dark:hover:bg-gray-700'
      case 'medium':
        return 'border-blue-500 text-blue-600 hover:bg-blue-50 dark:hover:bg-gray-700'
      default:
        return 'border-gray-400 text-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-3">Recommended Actions</h3>
      <div className="space-y-1.5">
        {actions.map((action, index) => {
          const Icon = action.icon
          return (
            <button
              key={index}
              className={`w-full flex items-center space-x-2 p-2 border-l-4 rounded-r transition-colors ${getPriorityColor(
                action.priority
              )}`}
            >
              <Icon className="w-3 h-3" />
              <span className="text-xs font-medium text-left flex-1 dark:text-white">{action.label}</span>
            </button>
          )
        })}
      </div>
      <button
        onClick={onViewAll}
        className="w-full mt-3 flex items-center justify-center space-x-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded transition-colors text-sm font-medium"
      >
        <span>View All Actions</span>
        <ChevronRight className="w-4 h-4" />
      </button>
    </div>
  )
}
