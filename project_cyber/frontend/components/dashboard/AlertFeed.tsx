import { AlertCircle, AlertTriangle, ChevronRight } from 'lucide-react'

interface AlertFeedProps {
  onViewAll?: () => void
}

export default function AlertFeed({ onViewAll }: AlertFeedProps) {
  const alerts = [
    { type: 'critical', message: 'Ransomware detected on FIN-SRV-01', time: '2m ago', icon: AlertCircle },
    { type: 'high', message: 'Brute force attempt on VPN gateway', time: '5m ago', icon: AlertTriangle },
  ]

  const getAlertStyle = (type: string) => {
    switch (type) {
      case 'critical':
        return 'border-l-critical bg-red-50'
      case 'high':
        return 'border-l-warning bg-amber-50'
      case 'medium':
        return 'border-l-blue-500 bg-blue-50'
      default:
        return 'border-l-gray-400 bg-gray-50'
    }
  }

  const getIconColor = (type: string) => {
    switch (type) {
      case 'critical':
        return 'text-critical'
      case 'high':
        return 'text-warning'
      case 'medium':
        return 'text-blue-500'
      default:
        return 'text-gray-500'
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-3">Real-Time Alert Feed</h3>
      <div className="space-y-2">
        {alerts.map((alert, index) => {
          const Icon = alert.icon
          return (
            <div
              key={index}
              className={`border-l-4 ${getAlertStyle(alert.type)} dark:bg-gray-700 p-2 rounded-r hover:shadow-sm transition-shadow cursor-pointer`}
            >
              <div className="flex items-start space-x-2">
                <Icon className={`w-3 h-3 mt-0.5 ${getIconColor(alert.type)}`} />
                <div className="flex-1">
                  <p className="text-xs text-gray-800 dark:text-white font-medium">{alert.message}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-300 mt-0.5">{alert.time}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>
      <button
        onClick={onViewAll}
        className="w-full mt-3 flex items-center justify-center space-x-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded transition-colors text-sm font-medium"
      >
        <span>View All Alerts</span>
        <ChevronRight className="w-4 h-4" />
      </button>
    </div>
  )
}
