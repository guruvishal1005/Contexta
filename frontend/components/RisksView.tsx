"use client";

import { useState, useEffect } from "react";
import { Loader2, RefreshCw } from "lucide-react";
import { risksApi, type Risk } from "@/lib/api";
import AgentDiscussionModal from "./AgentDiscussionModal";
import PlaybookModal from "./PlaybookModal";
import { PLAYBOOKS, Playbook } from "../utils/playbooks";

// Fallback mock data
const mockRisks = [
  {
    rank: 1,
    name: "Ransomware Campaign - LockBit 3.0",
    score: 98,
    severity: "CRITICAL",
    affected: 47,
    category: "Malware",
    lastDetected: "2m ago",
  },
  {
    rank: 2,
    name: "VPN Zero-Day RCE (CVE-2024-1234)",
    score: 92,
    severity: "CRITICAL",
    affected: 23,
    category: "Vulnerability",
    lastDetected: "15m ago",
  },
  {
    rank: 3,
    name: "Phishing Campaign - Finance Dept",
    score: 85,
    severity: "HIGH",
    affected: 156,
    category: "Social Engineering",
    lastDetected: "1h ago",
  },
  {
    rank: 4,
    name: "Unpatched Apache Struts",
    score: 78,
    severity: "HIGH",
    affected: 12,
    category: "Vulnerability",
    lastDetected: "3h ago",
  },
  {
    rank: 5,
    name: "Insider Threat - Data Exfiltration",
    score: 74,
    severity: "HIGH",
    affected: 3,
    category: "Insider Threat",
    lastDetected: "5h ago",
  },
  {
    rank: 6,
    name: "DDoS Attack Pattern Detected",
    score: 68,
    severity: "MEDIUM",
    affected: 8,
    category: "Network Attack",
    lastDetected: "8h ago",
  },
  {
    rank: 7,
    name: "Weak Password Policy Violations",
    score: 62,
    severity: "MEDIUM",
    affected: 89,
    category: "Policy Violation",
    lastDetected: "12h ago",
  },
  {
    rank: 8,
    name: "Outdated SSL/TLS Certificates",
    score: 55,
    severity: "MEDIUM",
    affected: 34,
    category: "Configuration",
    lastDetected: "1d ago",
  },
  {
    rank: 9,
    name: "Misconfigured S3 Buckets",
    score: 48,
    severity: "LOW",
    affected: 6,
    category: "Cloud Security",
    lastDetected: "2d ago",
  },
  {
    rank: 10,
    name: "Shadow IT - Unapproved SaaS",
    score: 42,
    severity: "LOW",
    affected: 67,
    category: "Policy Violation",
    lastDetected: "3d ago",
  },
];

interface DisplayRisk {
  rank: number;
  name: string;
  score: number;
  severity: string;
  affected: number;
  category: string;
  lastDetected: string;
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

export default function RisksView() {
  const [risks, setRisks] = useState<DisplayRisk[]>(mockRisks);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Playbook Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentRiskName, setCurrentRiskName] = useState("");
  const [messages, setMessages] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Playbook Modal State
  const [isPlaybookModalOpen, setIsPlaybookModalOpen] = useState(false);
  const [currentPlaybook, setCurrentPlaybook] = useState<Playbook | null>(null);
  const [currentRiskIdForPlaybook, setCurrentRiskIdForPlaybook] = useState<
    number | null
  >(null);

  const fetchRisks = async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);

      const response = await risksApi.getTop10();
      if (response.risks && response.risks.length > 0) {
        const mappedRisks: DisplayRisk[] = response.risks.map(
          (risk: Risk, index: number) => ({
            rank: index + 1,
            name: risk.name,
            score: Math.round(risk.bwvs_score || risk.priority_score || 0),
            severity: risk.severity.toUpperCase(),
            affected: risk.affected_assets_count || 0,
            category:
              risk.cve_ids && risk.cve_ids.length > 0
                ? "Vulnerability"
                : "Threat",
            lastDetected: risk.updated_at
              ? formatTimeAgo(risk.updated_at)
              : "N/A",
          }),
        );
        setRisks(mappedRisks);
      }
    } catch (err) {
      console.warn("Using mock data - API unavailable:", err);
      setRisks(mockRisks);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchRisks();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-critical text-white";
      case "HIGH":
        return "bg-warning text-white";
      case "MEDIUM":
        return "bg-blue-500 text-white";
      case "LOW":
        return "bg-gray-400 text-white";
      default:
        return "bg-gray-300 text-gray-800";
    }
  };

  const handlePlaybookClick = (risk: any) => {
    const name = risk.name.toLowerCase();
    const category = risk.category.toLowerCase();

    // Logic to select the correct playbook based on risk
    let playbookKey = "";

    if (
      name.includes("ransomware") ||
      name.includes("malware") ||
      category.includes("malware")
    ) {
      playbookKey = "malware-containment";
    } else if (
      name.includes("disconnect") ||
      name.includes("ddos") ||
      category.includes("network")
    ) {
      playbookKey = "malware-containment"; // Use containment for network attacks too as a fallback
    } else {
      // Default to data breach for phishing, insider threat, policy violations etc that might lead to data leaks
      playbookKey = "data-breach-response";
    }

    // Specific overrides
    if (name.includes("unpatched") || name.includes("vulnerability")) {
      playbookKey = "malware-containment"; // Patching often involves containment first
    }

    const playbook = PLAYBOOKS[playbookKey];
    if (playbook) {
      setCurrentPlaybook(playbook);
      setCurrentRiskIdForPlaybook(risk.rank);
      setIsPlaybookModalOpen(true);
    }
  };

  // Backup risks to replenish the list
  const BACKUP_RISKS = [
    {
      name: "API Key Leak - Repository",
      score: 95,
      severity: "CRITICAL",
      affected: 1,
      category: "Data Leak",
      lastDetected: "10m ago",
    },
    {
      name: "Suspicious PowerShell Execution",
      score: 88,
      severity: "HIGH",
      affected: 5,
      category: "Malware",
      lastDetected: "20m ago",
    },
    {
      name: "RDP Brute Force Attack",
      score: 82,
      severity: "HIGH",
      affected: 2,
      category: "Network Attack",
      lastDetected: "45m ago",
    },
    {
      name: "Unusual Data Transfer - Marketing",
      score: 70,
      severity: "MEDIUM",
      affected: 1,
      category: "Insider Threat",
      lastDetected: "1h ago",
    },
    {
      name: "New Admin Account Created",
      score: 65,
      severity: "MEDIUM",
      affected: 1,
      category: "Privilege Escalation",
      lastDetected: "2h ago",
    },
    {
      name: "Port 445 Open Exposure",
      score: 58,
      severity: "MEDIUM",
      affected: 3,
      category: "Configuration",
      lastDetected: "4h ago",
    },
    {
      name: "Failed Login Anomalies",
      score: 50,
      severity: "LOW",
      affected: 15,
      category: "Identity",
      lastDetected: "6h ago",
    },
  ];

  const handleMitigateRisk = () => {
    if (currentRiskIdForPlaybook !== null) {
      setRisks((prevRisks) => {
        // 1. Remove the mitigated risk
        const filtered = prevRisks.filter(
          (r) => r.rank !== currentRiskIdForPlaybook,
        );

        // 2. Find a new risk from backup that is NOT in the current filtered list
        // Simple check by name
        const currentNames = new Set(filtered.map((r) => r.name));
        const availableBackup = BACKUP_RISKS.find(
          (backup) => !currentNames.has(backup.name),
        );

        let newRisksList = [...filtered];

        if (availableBackup) {
          // Add the new risk to the end (initially)
          newRisksList.push({ ...availableBackup, rank: 0 }); // Rank will be fixed below
        }

        // 3. Sort by score (descending) and re-rank everyone 1 to N
        newRisksList.sort((a, b) => b.score - a.score);
        return newRisksList.map((risk, index) => ({
          ...risk,
          rank: index + 1,
        }));
      });
      setIsPlaybookModalOpen(false);
      setCurrentRiskIdForPlaybook(null);
    }
  };

  const handleAgentDiscussion = async (riskName: string) => {
    setCurrentRiskName(riskName);
    setIsModalOpen(true);
    setIsLoading(true);
    setMessages([]);

    try {
      // Get auth token from localStorage
      const token =
        typeof window !== "undefined"
          ? localStorage.getItem("contexta_access_token")
          : null;

      const encodedRiskName = encodeURIComponent(riskName);
      const response = await fetch(
        `http://localhost:8000/api/agents/analyze/demo?risk_title=${encodedRiskName}&agents=analyst&agents=intel&agents=forensics&agents=business`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        },
      );

      if (response.ok) {
        const data = await response.json();
        if (data.discussion) {
          setMessages(data.discussion);
        } else {
          // API returned but no discussion - show error
          setMessages([
            {
              agent: "analyst" as const,
              message:
                "⚠️ Unable to generate AI analysis. Please check your Gemini API configuration.",
              timestamp: new Date().toLocaleTimeString("en-US", {
                hour12: false,
              }),
            },
          ]);
        }
      } else {
        // API error - show error message
        const errorData = await response.json().catch(() => ({}));
        setMessages([
          {
            agent: "analyst" as const,
            message: `⚠️ AI Service Error: ${errorData.detail || "Backend unavailable. Please ensure the server is running."}`,
            timestamp: new Date().toLocaleTimeString("en-US", {
              hour12: false,
            }),
          },
        ]);
      }
    } catch (error) {
      console.error("Failed to fetch explanation", error);
      setMessages([
        {
          agent: "analyst" as const,
          message:
            "⚠️ Network Error: Unable to connect to the backend. Please ensure the server is running on port 8000.",
          timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Top 10 Risks Dashboard
          </h1>
          {loading && (
            <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => fetchRisks(true)}
            disabled={refreshing}
            className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center space-x-2"
          >
            <RefreshCw
              className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
            />
            <span>Refresh</span>
          </button>
          <button className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            Filter
          </button>
          <button className="px-4 py-2 bg-primary text-white rounded-md text-sm font-medium hover:bg-primary-dark transition-colors">
            Export Report
          </button>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b-2 border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Rank
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Risk Name
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Category
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Score
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Severity
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Affected Assets
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Last Detected
                </th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {risks.map((risk) => (
                <tr
                  key={risk.rank}
                  className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                >
                  <td className="py-4 px-3 font-bold text-gray-900 dark:text-white">
                    {risk.rank}
                  </td>
                  <td className="py-4 px-3 text-gray-800 dark:text-white font-medium">
                    {risk.name}
                  </td>
                  <td className="py-4 px-3 text-gray-600 dark:text-white">
                    {risk.category}
                  </td>
                  <td className="py-4 px-3">
                    <span className="font-bold text-gray-900 dark:text-white text-base">
                      {risk.score}
                    </span>
                  </td>
                  <td className="py-4 px-3">
                    <span
                      className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityColor(
                        risk.severity,
                      )}`}
                    >
                      {risk.severity}
                    </span>
                  </td>
                  <td className="py-4 px-3 text-gray-700 dark:text-white">
                    {risk.affected} assets
                  </td>
                  <td className="py-4 px-3 text-gray-600 dark:text-white">
                    {risk.lastDetected}
                  </td>
                  <td className="py-4 px-3">
                    <div className="flex gap-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleAgentDiscussion(risk.name);
                        }}
                        className="px-3 py-1 bg-primary text-white rounded text-xs font-medium hover:bg-primary-dark transition-colors"
                      >
                        Agent Discussion
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handlePlaybookClick(risk);
                        }}
                        className="px-3 py-1 bg-white border border-gray-300 text-gray-700 rounded text-xs font-medium hover:bg-gray-50 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700 transition-colors"
                      >
                        Playbook
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AgentDiscussionModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        riskName={currentRiskName}
        messages={messages}
        isLoading={isLoading}
      />

      <PlaybookModal
        isOpen={isPlaybookModalOpen}
        onClose={() => setIsPlaybookModalOpen(false)}
        playbook={currentPlaybook}
        onMitigate={handleMitigateRisk}
      />
    </div>
  );
}
