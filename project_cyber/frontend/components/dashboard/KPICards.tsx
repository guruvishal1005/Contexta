import { Shield, AlertTriangle, Server, Clock, Activity } from 'lucide-react'

export default function KPICards() {
  const kpis = [
    {
      label: 'Overall Risk Score',
      value: '87',
      trend: '+5%',
      trendUp: true,
      icon: Shield,
      color: 'text-critical',
      bgColor: 'bg-red-50',
    },
    {
      label: 'Active Incidents',
      value: '23',
      trend: '+3',
      trendUp: true,
      icon: AlertTriangle,
      color: 'text-warning',
      bgColor: 'bg-amber-50',
    },
    {
      label: 'Critical Assets',
      value: '142',
      trend: '0%',
      trendUp: false,
      icon: Server,
      color: 'text-primary',
      bgColor: 'bg-blue-50',
    },
    {
      label: 'Avg Response Time',
      value: '12m',
      trend: '-8%',
      trendUp: false,
      icon: Clock,
      color: 'text-success',
      bgColor: 'bg-green-50',
    },
    {
      label: 'Threat Level',
      value: 'HIGH',
      trend: 'Elevated',
      trendUp: true,
      icon: Activity,
      color: 'text-critical',
      bgColor: 'bg-red-50',
    },
  ]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
      {kpis.map((kpi, index) => {
        const Icon = kpi.icon
        return (
          <div
            key={index}
            className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-3 hover:shadow-md transition-all"
          >
            <div className="flex items-start justify-between mb-2">
              <div className={`${kpi.bgColor} dark:bg-gray-700 p-1.5 rounded-md`}>
                <Icon className={`w-4 h-4 ${kpi.color}`} />
              </div>
              <span
                className={`text-xs font-semibold ${
                  kpi.trendUp ? 'text-critical' : 'text-success'
                }`}
              >
                {kpi.trend}
              </span>
            </div>
            <div className="text-xl font-bold text-gray-900 dark:text-white mb-0.5">
              {kpi.value}
            </div>
            <div className="text-xs text-gray-600 dark:text-white font-medium">{kpi.label}</div>
          </div>
        )
      })}
    </div>
  )
}
