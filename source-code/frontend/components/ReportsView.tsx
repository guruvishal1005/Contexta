"use client";

import {
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  AreaChart,
  Area,
} from "recharts";
import { Download, FileText, TrendingUp } from "lucide-react";

export default function ReportsView() {
  // Monthly Security Incidents Report
  const monthlyIncidents = [
    { month: "Jan", incidents: 32, resolved: 28, pending: 4 },
    { month: "Feb", incidents: 45, resolved: 38, pending: 7 },
    { month: "Mar", incidents: 38, resolved: 34, pending: 4 },
    { month: "Apr", incidents: 52, resolved: 45, pending: 7 },
    { month: "May", incidents: 48, resolved: 42, pending: 6 },
    { month: "Jun", incidents: 61, resolved: 54, pending: 7 },
  ];

  // Vulnerability Distribution by Type
  const vulnerabilityTypes = [
    { name: "SQL Injection", value: 28, percentage: 18 },
    { name: "Cross-Site Scripting", value: 24, percentage: 15 },
    { name: "Authentication Issues", value: 32, percentage: 20 },
    { name: "Weak Encryption", value: 21, percentage: 14 },
    { name: "API Security", value: 26, percentage: 16 },
    { name: "Other", value: 30, percentage: 19 },
  ];

  // Compliance Status
  const complianceData = [
    { framework: "ISO 27001", compliant: 87, percentage: 87 },
    { framework: "GDPR", compliant: 92, percentage: 92 },
    { framework: "HIPAA", compliant: 79, percentage: 79 },
    { framework: "PCI-DSS", compliant: 84, percentage: 84 },
    { framework: "SOC 2", compliant: 91, percentage: 91 },
  ];

  // Security Spending
  const spendingData = [
    { category: "Incident Response", amount: 245 },
    { category: "Vulnerability Management", amount: 189 },
    { category: "Access Control", amount: 156 },
    { category: "Network Security", amount: 234 },
    { category: "Data Protection", amount: 178 },
    { category: "Training & Awareness", amount: 92 },
  ];

  // Threat Activity Trend
  const threatTrend = [
    { week: "W1", phishing: 42, malware: 18, ddos: 3, zero_day: 1 },
    { week: "W2", phishing: 56, malware: 24, ddos: 5, zero_day: 1 },
    { week: "W3", phishing: 38, malware: 19, ddos: 2, zero_day: 0 },
    { week: "W4", phishing: 63, malware: 31, ddos: 7, zero_day: 2 },
    { week: "W5", phishing: 48, malware: 22, ddos: 4, zero_day: 1 },
    { week: "W6", phishing: 71, malware: 28, ddos: 6, zero_day: 1 },
  ];

  // Risk Score Timeline
  const riskTimeline = [
    { date: "Jan 1", score: 68 },
    { date: "Jan 8", score: 71 },
    { date: "Jan 15", score: 73 },
    { date: "Jan 22", score: 69 },
    { date: "Jan 29", score: 72 },
    { date: "Feb 5", score: 75 },
    { date: "Feb 12", score: 71 },
  ];

  const COLORS = ["#DC2626", "#F59E0B", "#3B82F6", "#10B981", "#8B5CF6"];

  const reportCards = [
    { title: "Total Incidents", value: "276", change: "+12%", trend: "up" },
    {
      title: "Vulnerabilities Found",
      value: "156",
      change: "-8%",
      trend: "down",
    },
    {
      title: "Avg Resolution Time",
      value: "2.4 days",
      change: "-5%",
      trend: "down",
    },
    { title: "Compliance Score", value: "86.8%", change: "+3%", trend: "up" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Security Reports & Analytics
          </h1>
          <p className="text-sm text-gray-600 dark:text-white mt-1">
            Comprehensive security metrics and threat intelligence (Jan - Jun
            2024)
          </p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-md hover:bg-primary-dark transition-colors">
          <Download size={18} />
          Export All Reports
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        {reportCards.map((card, idx) => (
          <div
            key={idx}
            className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4"
          >
            <h3 className="text-sm font-medium text-gray-600 dark:text-white mb-2">
              {card.title}
            </h3>
            <div className="flex items-end justify-between">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {card.value}
              </div>
              <div
                className={`text-sm font-semibold flex items-center gap-1 ${card.trend === "up" ? "text-green-600" : "text-red-600"}`}
              >
                {card.change}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-2 gap-6">
        {/* Monthly Incidents */}
        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
            Monthly Security Incidents
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={monthlyIncidents}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
              <XAxis dataKey="month" stroke="#6B7280" />
              <YAxis stroke="#6B7280" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#fff",
                  border: "1px solid #E5E7EB",
                  borderRadius: "4px",
                }}
              />
              <Legend />
              <Bar dataKey="incidents" fill="#3B82F6" radius={[8, 8, 0, 0]} />
              <Bar dataKey="resolved" fill="#10B981" radius={[8, 8, 0, 0]} />
              <Bar dataKey="pending" fill="#F59E0B" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Vulnerability Distribution */}
        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
            Vulnerability Distribution by Type
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={vulnerabilityTypes}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {vulnerabilityTypes.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={COLORS[index % COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threat Activity Trends */}
      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
          Threat Activity Trends (Last 6 Weeks)
        </h2>
        <ResponsiveContainer width="100%" height={350}>
          <AreaChart data={threatTrend}>
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
            <XAxis dataKey="week" stroke="#6B7280" />
            <YAxis stroke="#6B7280" />
            <Tooltip
              contentStyle={{
                backgroundColor: "#fff",
                border: "1px solid #E5E7EB",
                borderRadius: "4px",
              }}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="phishing"
              stackId="1"
              stroke="#DC2626"
              fill="#DC2626"
              fillOpacity={0.6}
            />
            <Area
              type="monotone"
              dataKey="malware"
              stackId="1"
              stroke="#F59E0B"
              fill="#F59E0B"
              fillOpacity={0.6}
            />
            <Area
              type="monotone"
              dataKey="ddos"
              stackId="1"
              stroke="#3B82F6"
              fill="#3B82F6"
              fillOpacity={0.6}
            />
            <Area
              type="monotone"
              dataKey="zero_day"
              stackId="1"
              stroke="#8B5CF6"
              fill="#8B5CF6"
              fillOpacity={0.6}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Risk Score Timeline */}
      <div className="grid grid-cols-3 gap-6">
        {/* Risk Score */}
        <div className="col-span-2 bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
            Organizational Risk Score Trend
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={riskTimeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
              <XAxis dataKey="date" stroke="#6B7280" />
              <YAxis stroke="#6B7280" domain={[0, 100]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#fff",
                  border: "1px solid #E5E7EB",
                  borderRadius: "4px",
                }}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="#3B82F6"
                strokeWidth={3}
                dot={{ fill: "#3B82F6", r: 5 }}
                activeDot={{ r: 7 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Report Documents */}
        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
            Report Documents
          </h2>
          <div className="space-y-3">
            {[
              {
                name: "Quarterly Security Audit",
                date: "Jan 31, 2024",
                size: "4.2 MB",
              },
              {
                name: "Incident Response Report",
                date: "Jan 29, 2024",
                size: "2.8 MB",
              },
              {
                name: "Vulnerability Assessment",
                date: "Jan 27, 2024",
                size: "3.5 MB",
              },
              {
                name: "Compliance Status Update",
                date: "Jan 25, 2024",
                size: "1.9 MB",
              },
              {
                name: "Threat Intelligence Brief",
                date: "Jan 24, 2024",
                size: "2.1 MB",
              },
            ].map((doc, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 p-3 border border-gray-200 dark:border-gray-700 rounded hover:bg-gray-50 cursor-pointer transition-colors"
              >
                <FileText
                  size={18}
                  className="text-blue-500 flex-shrink-0 mt-1"
                />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {doc.name}
                  </p>
                  <p className="text-xs text-gray-500">
                    {doc.date} • {doc.size}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Compliance Framework Status */}
      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
          Compliance Framework Status
        </h2>
        <div className="space-y-4">
          {complianceData.map((framework, idx) => (
            <div
              key={idx}
              className="border-b border-gray-100 pb-3 last:border-b-0"
            >
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-medium text-gray-900 dark:text-white">
                  {framework.framework}
                </h3>
                <span className="text-sm font-semibold text-gray-700 dark:text-white">
                  {framework.percentage}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-green-400 to-green-600 h-2 rounded-full transition-all"
                  style={{ width: `${framework.percentage}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Security Spending */}
      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-4">
          Annual Security Spending Breakdown ($K)
        </h2>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart
            data={spendingData}
            layout="vertical"
            margin={{ top: 5, right: 30, left: 200, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
            <XAxis type="number" stroke="#6B7280" />
            <YAxis
              dataKey="category"
              type="category"
              stroke="#6B7280"
              width={190}
              tick={{ fontSize: 12 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#fff",
                border: "1px solid #E5E7EB",
                borderRadius: "4px",
              }}
            />
            <Bar dataKey="amount" fill="#10B981" radius={[0, 8, 8, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Summary Statistics */}
      <div className="grid grid-cols-3 gap-6">
        <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-md border border-blue-200 p-6">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
            Mean Time to Detect (MTTD)
          </h3>
          <p className="text-3xl font-bold text-blue-600">4.2 hrs</p>
          <p className="text-xs text-gray-600 dark:text-white mt-2">Industry avg: 7.4 hrs</p>
        </div>
        <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-md border border-green-200 p-6">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
            Mean Time to Response (MTTR)
          </h3>
          <p className="text-3xl font-bold text-green-600">1.8 hrs</p>
          <p className="text-xs text-gray-600 dark:text-white mt-2">Industry avg: 2.1 hrs</p>
        </div>
        <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-md border border-purple-200 p-6">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
            Threat Intel Sources
          </h3>
          <p className="text-3xl font-bold text-purple-600">23</p>
          <p className="text-xs text-gray-600 dark:text-white mt-2">Active monitoring feeds</p>
        </div>
      </div>
    </div>
  );
}
