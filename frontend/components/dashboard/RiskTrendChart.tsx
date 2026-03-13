'use client'

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'

export default function RiskTrendChart() {
  const data = [
    { date: 'Jan 24', critical: 12, high: 34, medium: 56, low: 23 },
    { date: 'Jan 27', critical: 15, high: 38, medium: 52, low: 21 },
    { date: 'Jan 30', critical: 18, high: 42, medium: 48, low: 19 },
    { date: 'Feb 02', critical: 22, high: 45, medium: 51, low: 22 },
    { date: 'Feb 05', critical: 19, high: 41, medium: 54, low: 24 },
    { date: 'Feb 08', critical: 23, high: 47, medium: 49, low: 20 },
    { date: 'Feb 11', critical: 26, high: 52, medium: 46, low: 18 },
  ]

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-3">Risk Trend (Last 30 Days)</h3>
      <ResponsiveContainer width="100%" height={180}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
          <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="#6B7280" />
          <YAxis tick={{ fontSize: 10 }} stroke="#6B7280" />
          <Tooltip
            contentStyle={{
              backgroundColor: '#fff',
              border: '1px solid #E5E7EB',
              borderRadius: '4px',
              fontSize: '10px',
            }}
          />
          <Legend wrapperStyle={{ fontSize: '10px' }} />
          <Line type="monotone" dataKey="critical" stroke="#DC2626" strokeWidth={1.5} dot={{ r: 2 }} />
          <Line type="monotone" dataKey="high" stroke="#F59E0B" strokeWidth={1.5} dot={{ r: 2 }} />
          <Line type="monotone" dataKey="medium" stroke="#3B82F6" strokeWidth={1.5} dot={{ r: 2 }} />
          <Line type="monotone" dataKey="low" stroke="#94A3B8" strokeWidth={1.5} dot={{ r: 2 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
