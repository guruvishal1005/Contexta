export default function DepartmentHeatmap() {
  const departments = [
    { name: 'Finance', risk: 92, incidents: 8, color: 'bg-red-500', textColor: 'text-black' },
    { name: 'IT Operations', risk: 87, incidents: 12, color: 'bg-orange-500', textColor: 'text-black' },
    { name: 'HR', risk: 76, incidents: 5, color: 'bg-yellow-400', textColor: 'text-black' },
  ]

  return (
    <div className="glass border border-white/10 dark:border-gray-700 rounded-xl p-4 hover:border-orange-500/30 transition-all group relative overflow-hidden bg-white dark:bg-gray-800">
      <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-red-500/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>
      <h3 className="text-base font-semibold text-black dark:text-white mb-3 relative z-10">Department Risk Heatmap</h3>
      <div className="space-y-2.5 relative z-10">
        {departments.map((dept, index) => (
          <div key={index} className="flex items-center space-x-2">
            <div className="w-24 text-xs font-medium text-black dark:text-white truncate">
              {dept.name}
            </div>
            <div className="flex-1 bg-gray-700/30 dark:bg-gray-700 rounded-full h-7 relative overflow-hidden border border-gray-600/30 dark:border-gray-600">
              <div
                className={`${dept.color} h-full rounded-full flex items-center justify-end pr-2 transition-all relative overflow-hidden`}
                style={{ width: `${dept.risk}%` }}
              >
                <span className={`${dept.textColor} text-xs font-bold relative z-10`}>{dept.risk}</span>
              </div>
            </div>
            <div className="w-16 text-xs text-black dark:text-white text-right">
              {dept.incidents} inc
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
