import { Activity, TrendingUp, TrendingDown } from 'lucide-react'

export default function RealTimeRisk() {
  const riskMetrics = [
    { label: 'Critical Threats', value: 12, trend: 'up', change: '+3', color: 'text-critical' },
    { label: 'Active Vulnerabilities', value: 47, trend: 'down', change: '-5', color: 'text-warning' },
    { label: 'Security Score', value: 78, trend: 'up', change: '+2', color: 'text-success' },
  ]

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <div className="flex items-center space-x-2 mb-3">
        <Activity className="w-4 h-4 text-primary" />
        <h3 className="text-base font-semibold text-gray-900 dark:text-white">Real-Time Risk</h3>
      </div>
      <div className="space-y-3">
        {riskMetrics.map((metric, index) => (
          <div key={index} className="flex items-center justify-between">
            <div className="flex-1">
              <p className="text-xs text-gray-600 dark:text-white font-medium">{metric.label}</p>
              <p className={`text-2xl font-bold ${metric.color} mt-1`}>{metric.value}</p>
            </div>
            <div className="flex items-center space-x-1">
              {metric.trend === 'up' ? (
                <TrendingUp className="w-4 h-4 text-critical" />
              ) : (
                <TrendingDown className="w-4 h-4 text-success" />
              )}
              <span className={`text-sm font-semibold ${metric.trend === 'up' ? 'text-critical' : 'text-success'}`}>
                {metric.change}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
