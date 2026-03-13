"use client";

import { useState, useEffect } from "react";
import {
  AlertCircle,
  AlertTriangle,
  Info,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { incidentsApi, type Incident } from "@/lib/api";

// Mock data for fallback
const mockAlerts = [
  {
    id: 1,
    type: "critical",
    message: "Ransomware detected on FIN-SRV-01",
    time: "2m ago",
    source: "EDR",
    affected: "Finance Server",
    icon: AlertCircle,
  },
  {
    id: 2,
    type: "high",
    message: "Brute force attempt on VPN gateway",
    time: "5m ago",
    source: "Firewall",
    affected: "VPN Gateway",
    icon: AlertTriangle,
  },
  {
    id: 3,
    type: "high",
    message: "Suspicious data transfer to external IP",
    time: "8m ago",
    source: "DLP",
    affected: "Workstation-42",
    icon: AlertTriangle,
  },
  {
    id: 4,
    type: "medium",
    message: "Failed login attempts (x47) - user: admin",
    time: "12m ago",
    source: "AD",
    affected: "Domain Controller",
    icon: Info,
  },
  {
    id: 5,
    type: "critical",
    message: "Zero-day exploit attempt detected",
    time: "15m ago",
    source: "IDS",
    affected: "Web Server",
    icon: AlertCircle,
  },
  {
    id: 6,
    type: "medium",
    message: "Unusual network traffic pattern",
    time: "18m ago",
    source: "NetFlow",
    affected: "Network",
    icon: Info,
  },
  {
    id: 7,
    type: "high",
    message: "Malware signature match in email",
    time: "22m ago",
    source: "Email Gateway",
    affected: "Mail Server",
    icon: AlertTriangle,
  },
  {
    id: 8,
    type: "medium",
    message: "Certificate expiring in 7 days",
    time: "25m ago",
    source: "SSL Monitor",
    affected: "api.company.com",
    icon: Info,
  },
  {
    id: 9,
    type: "critical",
    message: "Privilege escalation detected",
    time: "30m ago",
    source: "SIEM",
    affected: "DB Server",
    icon: AlertCircle,
  },
  {
    id: 10,
    type: "high",
    message: "Unauthorized access attempt",
    time: "35m ago",
    source: "IAM",
    affected: "Admin Portal",
    icon: AlertTriangle,
  },
];

interface DisplayAlert {
  id: number;
  type: string;
  message: string;
  time: string;
  source: string;
  affected: string;
  icon: typeof AlertCircle | typeof AlertTriangle | typeof Info;
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

function getIconForSeverity(severity: string) {
  switch (severity) {
    case "critical":
      return AlertCircle;
    case "high":
      return AlertTriangle;
    default:
      return Info;
  }
}

function mapIncidentToAlert(incident: Incident, index: number): DisplayAlert {
  return {
    id: index + 1,
    type: incident.severity,
    message: incident.title,
    time: incident.created_at ? formatTimeAgo(incident.created_at) : "N/A",
    source: incident.incident_type || "SIEM",
    affected:
      incident.affected_assets && incident.affected_assets.length > 0
        ? incident.affected_assets[0]
        : "Multiple Assets",
    icon: getIconForSeverity(incident.severity),
  };
}

export default function AlertsView() {
  const [alerts, setAlerts] = useState<DisplayAlert[]>(mockAlerts);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAlerts = async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);

      const incidents = await incidentsApi.list({ page_size: 20 });
      if (incidents && incidents.length > 0) {
        setAlerts(incidents.map(mapIncidentToAlert));
      }
    } catch (err) {
      console.warn("Using mock data - API unavailable:", err);
      setAlerts(mockAlerts);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const getSeverityColor = (type: string) => {
    switch (type) {
      case "critical":
        return "bg-critical text-white";
      case "high":
        return "bg-warning text-white";
      case "medium":
        return "bg-blue-500 text-white";
      case "low":
        return "bg-gray-400 text-white";
      default:
        return "bg-gray-300 text-gray-800";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Real-Time Alert Feed
          </h1>
          {loading && (
            <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => fetchAlerts(true)}
            disabled={refreshing}
            className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center space-x-2"
          >
            <RefreshCw
              className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
            />
            <span>Refresh</span>
          </button>
          <button className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            Filter by Severity
          </button>
          <button className="px-4 py-2 bg-primary text-white rounded-md text-sm font-medium hover:bg-primary-dark transition-colors">
            Acknowledge All
          </button>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b-2 border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  ID
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Severity
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Alert Message
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Source
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Affected Asset
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Time
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => {
                const Icon = alert.icon;
                return (
                  <tr
                    key={alert.id}
                    className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                  >
                    <td className="py-4 px-3 font-medium text-gray-900 dark:text-white">
                      #{alert.id}
                    </td>
                    <td className="py-4 px-3">
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold uppercase ${getSeverityColor(
                          alert.type,
                        )}`}
                      >
                        {alert.type}
                      </span>
                    </td>
                    <td className="py-4 px-3">
                      <div className="flex items-center space-x-2">
                        <Icon className="w-4 h-4 text-gray-600 dark:text-gray-400" />
                        <span className="text-gray-800 dark:text-white font-medium">
                          {alert.message}
                        </span>
                      </div>
                    </td>
                    <td className="py-4 px-3 text-gray-600 dark:text-white">
                      {alert.source}
                    </td>
                    <td className="py-4 px-3 text-gray-700 dark:text-white">
                      {alert.affected}
                    </td>
                    <td className="py-4 px-3 text-gray-600 dark:text-white">
                      {alert.time}
                    </td>
                    <td className="py-4 px-3">
                      <button className="px-3 py-1 bg-primary text-white rounded text-xs font-medium hover:bg-primary-dark transition-colors">
                        Investigate
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
