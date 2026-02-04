"use client";

import { useState, useEffect } from "react";
import { Brain, TrendingUp, Loader2 } from "lucide-react";
import { cvesApi, type CVE } from "@/lib/api";

// Mock data for fallback
const mockInsights = [
  {
    title: "LockBit 3.0 Campaign",
    confidence: 87,
    description:
      "Active ransomware targeting financial sector. 12 attacks in 48h.",
    indicators: ["Lateral movement", "Data exfiltration"],
  },
  {
    title: "APT29 Phishing Wave",
    confidence: 92,
    description:
      "Sophisticated spear-phishing targeting C-level executives. 8 attempts detected.",
    indicators: ["Credential harvesting", "Social engineering"],
  },
  {
    title: "Emotet Botnet Resurgence",
    confidence: 78,
    description:
      "Malware distribution via compromised email threads. 15 infections blocked.",
    indicators: ["Email compromise", "Payload delivery"],
  },
  {
    title: "SQL Injection Attempts",
    confidence: 85,
    description:
      "Automated scanning targeting web applications. 47 attempts in 24h.",
    indicators: ["Database probing", "Input validation bypass"],
  },
  {
    title: "DDoS Attack Pattern",
    confidence: 73,
    description:
      "Distributed denial of service targeting public endpoints. Traffic spike detected.",
    indicators: ["Network flooding", "Service disruption"],
  },
];

interface Insight {
  title: string;
  confidence: number;
  description: string;
  indicators: string[];
}

function mapCVEToInsight(cve: CVE): Insight {
  const indicators: string[] = [];
  if (cve.has_exploit) indicators.push("Active Exploit");
  if (cve.is_kev) indicators.push("Known Exploited");
  if (cve.cvss_score >= 9) indicators.push("Critical Severity");
  if (indicators.length === 0) indicators.push(cve.severity.toUpperCase());

  return {
    title: cve.cve_id,
    confidence: Math.round((cve.cvss_score / 10) * 100),
    description:
      cve.description.length > 120
        ? cve.description.substring(0, 120) + "..."
        : cve.description,
    indicators,
  };
}

export default function ThreatInsights() {
  const [insights, setInsights] = useState<Insight[]>(mockInsights);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCVEs = async () => {
      try {
        setLoading(true);
        const response = await cvesApi.getTrending(5);
        if (response.trending_cves && response.trending_cves.length > 0) {
          setInsights(response.trending_cves.map(mapCVEToInsight));
        }
      } catch (err) {
        console.warn("Using mock data - API unavailable:", err);
        setInsights(mockInsights);
      } finally {
        setLoading(false);
      }
    };

    fetchCVEs();
    // Refresh every minute
    const interval = setInterval(fetchCVEs, 60000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <Brain className="w-4 h-4 text-primary" />
          <h3 className="text-base font-semibold text-gray-900 dark:text-white">
            Threat Intelligence
          </h3>
        </div>
        {loading && <Loader2 className="w-4 h-4 animate-spin text-gray-400" />}
      </div>
      <div className="space-y-2">
        {insights.map((insight, index) => (
          <div
            key={index}
            className="border border-gray-200 dark:border-gray-700 rounded-md p-3 hover:border-primary transition-colors"
          >
            <div className="flex items-start justify-between mb-1">
              <h4 className="text-xs font-semibold text-gray-900 dark:text-white">
                {insight.title}
              </h4>
              <div className="flex items-center space-x-1">
                <TrendingUp className="w-3 h-3 text-success" />
                <span className="text-xs font-semibold text-success">
                  {insight.confidence}%
                </span>
              </div>
            </div>
            <p className="text-xs text-gray-600 dark:text-white mb-2">
              {insight.description}
            </p>
            <div className="flex flex-wrap gap-1">
              {insight.indicators.map((indicator, idx) => (
                <span
                  key={idx}
                  className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-white text-xs rounded"
                >
                  {indicator}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
