import {
  TrendingUp,
  DollarSign,
  Shield,
  FileText,
  CheckCircle,
  AlertTriangle,
  Zap,
  BarChart3,
} from "lucide-react";
import { useState } from "react";

export default function ExecutiveView() {
  const [selectedQuarter, setSelectedQuarter] = useState("Q4");

  const businessMetrics = [
    {
      label: "Business Risk Score",
      value: "7.8/10",
      trend: "+0.5",
      icon: AlertTriangle,
      color: "text-critical",
    },
    {
      label: "Financial Exposure",
      value: "$8.2M",
      trend: "+12%",
      icon: Zap,
      color: "text-warning",
    },
    {
      label: "Compliance Status",
      value: "94%",
      trend: "+2%",
      icon: CheckCircle,
      color: "text-success",
    },
    {
      label: "Risk Trend",
      value: "Rising",
      trend: "↑",
      icon: BarChart3,
      color: "text-critical",
    },
  ];

  const complianceFrameworks = [
    { name: "SOC 2 Type II", status: 98, color: "bg-success" },
    { name: "ISO 27001", status: 96, color: "bg-success" },
    { name: "GDPR", status: 92, color: "bg-success" },
    { name: "HIPAA", status: 88, color: "bg-warning" },
    { name: "PCI DSS", status: 85, color: "bg-warning" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Executive Risk Dashboard
        </h1>
        <button className="flex items-center space-x-2 px-4 py-2 bg-primary text-white rounded-md hover:bg-primary-dark transition-colors">
          <FileText className="w-4 h-4" />
          <span className="text-sm font-medium">Generate Board Report</span>
        </button>
      </div>

      {/* Business Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {businessMetrics.map((metric, index) => {
          const Icon = metric.icon;
          return (
            <div
              key={index}
              className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-5"
            >
              <div className="flex items-center justify-between mb-3">
                <Icon className={`w-6 h-6 ${metric.color}`} />
                <span className="text-xs font-semibold text-gray-500">
                  {metric.trend}
                </span>
              </div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white mb-1">
                {metric.value}
              </div>
              <div className="text-xs text-gray-600 dark:text-white font-medium">
                {metric.label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Financial Impact */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Financial Impact Summary
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center pb-3 border-b border-gray-200 dark:border-gray-700">
              <span className="text-sm text-gray-700 dark:text-white">
                Potential Data Breach Cost
              </span>
              <span className="text-lg font-bold text-critical">$4.5M</span>
            </div>
            <div className="flex justify-between items-center pb-3 border-b border-gray-200 dark:border-gray-700">
              <span className="text-sm text-gray-700 dark:text-white">Ransomware Impact</span>
              <span className="text-lg font-bold text-critical">$2.8M</span>
            </div>
            <div className="flex justify-between items-center pb-3 border-b border-gray-200 dark:border-gray-700">
              <span className="text-sm text-gray-700 dark:text-white">
                Regulatory Fines Risk
              </span>
              <span className="text-lg font-bold text-warning">$900K</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-700 dark:text-white font-semibold">
                Total Exposure
              </span>
              <span className="text-xl font-bold text-gray-900 dark:text-white">$8.2M</span>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Compliance Status
          </h3>
          <div className="space-y-3">
            {complianceFrameworks.map((framework, index) => (
              <div key={index}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    {framework.name}
                  </span>
                  <span className="text-gray-900 dark:text-white font-semibold">
                    {framework.status}%
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={`${framework.color} h-2 rounded-full transition-all`}
                    style={{ width: `${framework.status}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Risk Trends */}
      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Quarterly Risk Trends
        </h3>
        <div className="grid grid-cols-4 gap-4">
          {[
            { quarter: "Q1", score: 6.8 },
            { quarter: "Q2", score: 7.2 },
            { quarter: "Q3", score: 7.5 },
            { quarter: "Q4", score: 7.8 },
          ].map((item) => (
            <button
              key={item.quarter}
              onClick={() => setSelectedQuarter(item.quarter)}
              className={`text-center p-4 rounded-md transition-all cursor-pointer ${
                selectedQuarter === item.quarter
                  ? "bg-blue-50 border-2 border-primary"
                  : "bg-gray-50 border-2 border-transparent hover:border-gray-300"
              }`}
            >
              <div
                className={`text-2xl font-bold ${selectedQuarter === item.quarter ? "text-primary" : "text-gray-900 dark:text-white"}`}
              >
                {item.quarter} 2024
              </div>
              <div className="text-sm text-gray-600 dark:text-white mt-1">
                Risk Score: {item.score}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
