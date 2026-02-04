"use client";

import { useState, useEffect } from "react";
import {
  Play,
  CheckSquare,
  Shield,
  AlertTriangle,
  Database,
  Network,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { playbooksApi, type Playbook } from "@/lib/api";

// Mock data for fallback
const mockActions = [
  {
    id: 1,
    label: "Run Incident Response Playbook",
    icon: Play,
    priority: "critical",
    status: "pending",
    assignee: "SOC Team",
    eta: "5 min",
  },
  {
    id: 2,
    label: "Isolate Affected Hosts (3)",
    icon: Shield,
    priority: "critical",
    status: "pending",
    assignee: "Network Team",
    eta: "10 min",
  },
  {
    id: 3,
    label: "Patch CVE-2024-1234 (23 assets)",
    icon: CheckSquare,
    priority: "high",
    status: "in-progress",
    assignee: "IT Ops",
    eta: "2 hours",
  },
  {
    id: 4,
    label: "Reset Compromised Credentials",
    icon: CheckSquare,
    priority: "high",
    status: "pending",
    assignee: "IAM Team",
    eta: "15 min",
  },
  {
    id: 5,
    label: "Block Malicious IPs (12)",
    icon: Shield,
    priority: "medium",
    status: "completed",
    assignee: "Firewall Admin",
    eta: "Done",
  },
  {
    id: 6,
    label: "Update Firewall Rules",
    icon: Network,
    priority: "medium",
    status: "pending",
    assignee: "Network Team",
    eta: "30 min",
  },
  {
    id: 7,
    label: "Schedule Vulnerability Scan",
    icon: AlertTriangle,
    priority: "low",
    status: "pending",
    assignee: "Security Team",
    eta: "1 day",
  },
  {
    id: 8,
    label: "Backup Critical Databases",
    icon: Database,
    priority: "high",
    status: "in-progress",
    assignee: "DBA Team",
    eta: "1 hour",
  },
  {
    id: 9,
    label: "Review Access Logs",
    icon: CheckSquare,
    priority: "medium",
    status: "pending",
    assignee: "Audit Team",
    eta: "45 min",
  },
  {
    id: 10,
    label: "Update Security Policies",
    icon: CheckSquare,
    priority: "low",
    status: "pending",
    assignee: "Compliance",
    eta: "3 days",
  },
];

interface DisplayAction {
  id: number;
  label: string;
  icon: typeof Play;
  priority: string;
  status: string;
  assignee: string;
  eta: string;
}

function mapPlaybookToAction(playbook: Playbook, index: number): DisplayAction {
  const priorityMap: Record<string, string> = {
    "incident-response": "critical",
    "data-breach": "critical",
    malware: "high",
    containment: "high",
  };

  const priority = playbook.category
    ? priorityMap[playbook.category.toLowerCase()] || "medium"
    : "medium";

  return {
    id: index + 1,
    label: playbook.name,
    icon: playbook.category?.includes("incident") ? Play : CheckSquare,
    priority,
    status: playbook.is_active ? "pending" : "completed",
    assignee: "SOC Team",
    eta: `${playbook.steps?.length || 5} min`,
  };
}

export default function ActionsView() {
  const [actions, setActions] = useState<DisplayAction[]>(mockActions);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchPlaybooks = async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);

      const playbooks = await playbooksApi.list({ page_size: 20 });
      if (playbooks && playbooks.length > 0) {
        setActions(playbooks.map(mapPlaybookToAction));
      }
    } catch (err) {
      console.warn("Using mock data - API unavailable:", err);
      setActions(mockActions);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchPlaybooks();
  }, []);

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "critical":
        return "bg-critical text-white";
      case "high":
        return "bg-warning text-white";
      case "medium":
        return "bg-blue-500 text-white";
      case "low":
        return "bg-gray-400 text-white";
      default:
        return "bg-gray-300 text-gray-800 dark:text-white";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-100 text-green-800";
      case "in-progress":
        return "bg-blue-100 text-blue-800";
      case "pending":
        return "bg-gray-100 text-gray-800 dark:text-white";
      default:
        return "bg-gray-100 text-gray-800 dark:text-white";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Recommended Actions Dashboard
          </h1>
          {loading && (
            <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => fetchPlaybooks(true)}
            disabled={refreshing}
            className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center space-x-2"
          >
            <RefreshCw
              className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
            />
            <span>Refresh</span>
          </button>
          <button className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 rounded-md text-sm font-medium text-gray-700 dark:text-white hover:bg-gray-50 transition-colors">
            Filter by Priority
          </button>
          <button className="px-4 py-2 bg-primary text-white rounded-md text-sm font-medium hover:bg-primary-dark transition-colors">
            Execute All Critical
          </button>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b-2 border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  ID
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Action
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Priority
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Status
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Assignee
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  ETA
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {actions.map((action) => {
                const Icon = action.icon;
                return (
                  <tr
                    key={action.id}
                    className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer transition-colors"
                  >
                    <td className="py-4 px-3 font-medium text-gray-900 dark:text-white">
                      #{action.id}
                    </td>
                    <td className="py-4 px-3">
                      <div className="flex items-center space-x-2">
                        <Icon className="w-4 h-4 text-gray-600 dark:text-white" />
                        <span className="text-gray-800 dark:text-white font-medium">
                          {action.label}
                        </span>
                      </div>
                    </td>
                    <td className="py-4 px-3">
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold uppercase ${getPriorityColor(
                          action.priority,
                        )}`}
                      >
                        {action.priority}
                      </span>
                    </td>
                    <td className="py-4 px-3">
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold capitalize ${getStatusColor(
                          action.status,
                        )}`}
                      >
                        {action.status}
                      </span>
                    </td>
                    <td className="py-4 px-3 text-gray-700 dark:text-white">
                      {action.assignee}
                    </td>
                    <td className="py-4 px-3 text-gray-600 dark:text-white">
                      {action.eta}
                    </td>
                    <td className="py-4 px-3">
                      <button className="px-3 py-1 bg-primary text-white rounded text-xs font-medium hover:bg-primary-dark transition-colors">
                        Execute
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
