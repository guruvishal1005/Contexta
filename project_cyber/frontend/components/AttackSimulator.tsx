"use client";

import { useState, useEffect } from "react";
import { Play, Pause, RotateCcw, Target, Zap, Loader2, AlertCircle } from "lucide-react";
import { twinApi, type TwinStats, type SimulationResult } from "@/lib/api";

export default function AttackSimulator() {
  const [twinStats, setTwinStats] = useState<TwinStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [simulationResult, setSimulationResult] =
    useState<SimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attackType, setAttackType] = useState<string>("ransomware");

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        const stats = await twinApi.getStats();
        setTwinStats(stats);
        setError(null);
      } catch (err) {
        console.warn("Digital twin API unavailable:", err);
        // Don't set error for stats - just continue with default values
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  const runSimulation = async () => {
    try {
      setSimulating(true);
      setError(null);
      const result = await twinApi.simulate({
        attack_type: attackType,
        entry_point: "external_firewall",
      });
      setSimulationResult(result);
    } catch (err: unknown) {
      console.error("Simulation failed:", err);
      let errorMessage = "Simulation failed. Please ensure the backend is running.";
      
      if (err instanceof Error) {
        errorMessage = err.message;
      } else if (typeof err === 'object' && err !== null) {
        const errObj = err as { message?: string; status?: number; detail?: string };
        if (errObj.message) {
          errorMessage = errObj.message;
        } else if (errObj.detail) {
          errorMessage = errObj.detail;
        }
      }
      
      setError(errorMessage);
    } finally {
      setSimulating(false);
    }
  };

  const resetSimulation = () => {
    setSimulationResult(null);
    setError(null);
  };

  const mitrePhases = [
    { id: 1, name: "Initial Access", techniques: 12, active: true },
    { id: 2, name: "Execution", techniques: 8, active: true },
    { id: 3, name: "Persistence", techniques: 15, active: false },
    { id: 4, name: "Privilege Escalation", techniques: 11, active: false },
    { id: 5, name: "Defense Evasion", techniques: 18, active: false },
    { id: 6, name: "Credential Access", techniques: 9, active: false },
    { id: 7, name: "Discovery", techniques: 14, active: false },
    { id: 8, name: "Lateral Movement", techniques: 7, active: false },
    { id: 9, name: "Collection", techniques: 10, active: false },
    { id: 10, name: "Exfiltration", techniques: 6, active: false },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Attack Path Simulator
          </h1>
          {loading && (
            <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
          )}
          {twinStats && (
            <span className="text-sm text-gray-500">
              ({twinStats.total_nodes} nodes, {twinStats.total_edges}{" "}
              connections)
            </span>
          )}
        </div>
        <div className="flex items-center space-x-3">
          {/* Attack Type Selector */}
          <select
            value={attackType}
            onChange={(e) => setAttackType(e.target.value)}
            className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="ransomware">Ransomware</option>
            <option value="apt">APT</option>
            <option value="insider">Insider Threat</option>
            <option value="ddos">DDoS</option>
          </select>
          <button
            onClick={runSimulation}
            disabled={simulating}
            className="flex items-center space-x-2 px-4 py-2 bg-success text-white rounded-md hover:bg-green-700 transition-colors disabled:opacity-50"
          >
            {simulating ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span className="text-sm font-medium">
              {simulating ? "Running..." : "Start Simulation"}
            </span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-white rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
            <Pause className="w-4 h-4" />
            <span className="text-sm font-medium">Pause</span>
          </button>
          <button
            onClick={resetSimulation}
            className="flex items-center space-x-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-white rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            <span className="text-sm font-medium">Reset</span>
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md text-red-700 dark:text-red-300">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Graph Canvas */}
        <div className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Attack Path Visualization
          </h3>
          <div className="bg-gray-50 dark:bg-gray-700 rounded-md h-96 overflow-auto border-2 border-dashed border-gray-300 dark:border-gray-600 p-4">
            {simulating ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <Loader2 className="w-12 h-12 text-primary animate-spin mx-auto mb-3" />
                  <p className="text-gray-600 dark:text-white font-medium">
                    Running Simulation...
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-300 mt-1">
                    Analyzing attack paths and blast radius
                  </p>
                </div>
              </div>
            ) : simulationResult && simulationResult.paths_found?.length > 0 ? (
              <div className="space-y-4">
                <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 mb-4">
                  <span className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                    {simulationResult.attack_type?.toUpperCase()}
                  </span>
                  <span>Entry: <strong>{simulationResult.entry_point}</strong></span>
                  {simulationResult.target && <span>→ Target: <strong>{simulationResult.target}</strong></span>}
                </div>
                
                {/* Attack Paths Visualization */}
                <div className="space-y-3">
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-200">
                    Attack Paths Found ({simulationResult.paths_found.length})
                  </h4>
                  {simulationResult.paths_found.slice(0, 5).map((pathInfo, idx) => (
                    <div key={idx} className="bg-white dark:bg-gray-800 rounded-md p-3 border border-gray-200 dark:border-gray-600">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium text-gray-500 dark:text-gray-400">
                          Path {idx + 1}
                        </span>
                        <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                          pathInfo.risk_score >= 8 ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' :
                          pathInfo.risk_score >= 5 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300' :
                          'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                        }`}>
                          Risk: {pathInfo.risk_score?.toFixed(1) || 'N/A'}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-1">
                        {pathInfo.path?.map((node, nodeIdx) => (
                          <div key={nodeIdx} className="flex items-center">
                            <span className={`px-2 py-1 text-xs rounded ${
                              nodeIdx === 0 ? 'bg-red-500 text-white' :
                              nodeIdx === pathInfo.path.length - 1 ? 'bg-purple-500 text-white' :
                              'bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200'
                            }`}>
                              {node}
                            </span>
                            {nodeIdx < pathInfo.path.length - 1 && (
                              <span className="text-gray-400 mx-1">→</span>
                            )}
                          </div>
                        ))}
                      </div>
                      {pathInfo.description && (
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">{pathInfo.description}</p>
                      )}
                    </div>
                  ))}
                </div>

                {/* Blast Radius */}
                {simulationResult.blast_radius && simulationResult.blast_radius.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-2">
                      Blast Radius ({simulationResult.blast_radius.length} assets)
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {simulationResult.blast_radius.slice(0, 15).map((asset, idx) => (
                        <span key={idx} className="px-2 py-1 text-xs bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                          {asset}
                        </span>
                      ))}
                      {simulationResult.blast_radius.length > 15 && (
                        <span className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300 rounded">
                          +{simulationResult.blast_radius.length - 15} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <Target className="w-16 h-16 text-gray-400 dark:text-gray-500 mx-auto mb-3" />
                  <p className="text-gray-600 dark:text-white font-medium">
                    Interactive Attack Graph
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-300 mt-1">
                    Click &quot;Start Simulation&quot; to visualize attack paths
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Impact Estimation */}
        <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Impact Estimation
          </h3>
          {simulationResult ? (
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Risk Assessment
                  </span>
                  <span className="text-critical font-semibold">
                    {simulationResult.risk_assessment || "HIGH"}
                  </span>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Attack Paths Found
                  </span>
                  <span className="text-gray-900 dark:text-white font-semibold">
                    {simulationResult.paths_found?.length || 0}
                  </span>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Blast Radius
                  </span>
                  <span className="text-gray-900 dark:text-white font-semibold">
                    {simulationResult.blast_radius?.length || 0} assets
                  </span>
                </div>
              </div>
              {simulationResult.recommendations &&
                simulationResult.recommendations.length > 0 && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 dark:text-white mb-2">
                      Recommendations:
                    </div>
                    <ul className="text-xs text-gray-600 dark:text-gray-300 space-y-1">
                      {simulationResult.recommendations
                        .slice(0, 3)
                        .map((rec, idx) => (
                          <li key={idx} className="flex items-start">
                            <span className="text-primary mr-1">•</span>
                            {rec}
                          </li>
                        ))}
                    </ul>
                  </div>
                )}
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Business Impact
                  </span>
                  <span className="text-critical font-semibold">HIGH</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className="bg-critical h-2 rounded-full"
                    style={{ width: "85%" }}
                  ></div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Financial Loss
                  </span>
                  <span className="text-gray-900 dark:text-white font-semibold">
                    $2.4M
                  </span>
                </div>
                <div className="text-xs text-gray-600 dark:text-white">
                  Estimated revenue impact
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Assets at Risk
                  </span>
                  <span className="text-gray-900 dark:text-white font-semibold">
                    {twinStats?.total_nodes || 47}
                  </span>
                </div>
                <div className="text-xs text-gray-600 dark:text-white">
                  Critical systems affected
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-700 dark:text-white font-medium">
                    Recovery Time
                  </span>
                  <span className="text-gray-900 dark:text-white font-semibold">
                    72 hours
                  </span>
                </div>
                <div className="text-xs text-gray-600 dark:text-white">
                  Estimated downtime
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* MITRE ATT&CK Mapping */}
      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
        <div className="flex items-center space-x-2 mb-4">
          <Zap className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            MITRE ATT&CK Tactics
          </h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {mitrePhases.map((phase) => (
            <div
              key={phase.id}
              className={`p-4 rounded-md border-2 transition-all cursor-pointer ${
                phase.active
                  ? "border-primary bg-blue-50 dark:bg-blue-900/30"
                  : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
              }`}
            >
              <div className="text-sm font-semibold text-gray-900 dark:text-white mb-1">
                {phase.name}
              </div>
              <div className="text-xs text-gray-600 dark:text-white">
                {phase.techniques} techniques
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
