'use client'

import TopRisksTable from './dashboard/TopRisksTable'
import RiskTrendChart from './dashboard/RiskTrendChart'
import DepartmentHeatmap from './dashboard/DepartmentHeatmap'
import AlertFeed from './dashboard/AlertFeed'
import ThreatInsights from './dashboard/ThreatInsights'
import RecommendedActions from './dashboard/RecommendedActions'
import RealTimeRisk from './dashboard/RealTimeRisk'

interface DashboardProps {
  onNavigateToRisks?: () => void
  onNavigateToAlerts?: () => void
  onNavigateToActions?: () => void
}

export default function Dashboard({ onNavigateToRisks, onNavigateToAlerts, onNavigateToActions }: DashboardProps) {
  return (
    <div className="h-[calc(100vh-5rem)] overflow-hidden p-4">
      {/* Main Grid - All sections in one view */}
      <div className="grid grid-cols-12 gap-3 h-full">
        {/* Left Column */}
        <div className="col-span-4 flex flex-col gap-3 h-full">
          <div className="flex-1 min-h-0 overflow-auto">
            <TopRisksTable onShowMore={onNavigateToRisks} />
          </div>
          <div className="flex-shrink-0">
            <AlertFeed onViewAll={onNavigateToAlerts} />
          </div>
          <div className="flex-shrink-0">
            <RealTimeRisk />
          </div>
        </div>

        {/* Middle Column */}
        <div className="col-span-4 flex flex-col gap-3 h-full">
          <div className="flex-1 min-h-0">
            <RiskTrendChart />
          </div>
          <div className="flex-1 min-h-0">
            <DepartmentHeatmap />
          </div>
        </div>

        {/* Right Column */}
        <div className="col-span-4 flex flex-col gap-3 h-full">
          <div className="flex-shrink-0">
            <RecommendedActions onViewAll={onNavigateToActions} />
          </div>
          <div className="flex-1 min-h-0 overflow-hidden">
            <ThreatInsights />
          </div>
        </div>
      </div>
    </div>
  )
}
