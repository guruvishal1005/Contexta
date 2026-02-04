"use client";

import { useState, useEffect } from "react";
import {
  Server,
  Database,
  Shield,
  AlertCircle,
  Loader2,
  RefreshCw,
  Cloud,
  Monitor,
  Wifi,
} from "lucide-react";
import { assetsApi, type Asset as ApiAsset } from "@/lib/api";

interface Asset {
  id: string;
  name: string;
  type: string;
  status: "healthy" | "warning" | "critical";
  vulnerabilities: number;
  lastScanned: string;
  owner: string;
  location: string;
  osVersion: string;
}

const mockAssets: Asset[] = [
  {
    id: "AST-001",
    name: "Web Server 01",
    type: "Server",
    status: "healthy",
    vulnerabilities: 2,
    lastScanned: "2024-01-30",
    owner: "Infrastructure Team",
    location: "US-EAST-1",
    osVersion: "Ubuntu 22.04 LTS",
  },
  {
    id: "AST-002",
    name: "Database Server",
    type: "Database",
    status: "warning",
    vulnerabilities: 5,
    lastScanned: "2024-01-28",
    owner: "Data Team",
    location: "US-EAST-2",
    osVersion: "CentOS 8",
  },
  {
    id: "AST-003",
    name: "API Gateway",
    type: "Server",
    status: "critical",
    vulnerabilities: 12,
    lastScanned: "2024-01-25",
    owner: "DevOps Team",
    location: "US-WEST-1",
    osVersion: "Amazon Linux 2",
  },
  {
    id: "AST-004",
    name: "Cache Server",
    type: "Server",
    status: "healthy",
    vulnerabilities: 1,
    lastScanned: "2024-01-29",
    owner: "Infrastructure Team",
    location: "US-EAST-1",
    osVersion: "Redis on Ubuntu 20.04",
  },
  {
    id: "AST-005",
    name: "Backup Database",
    type: "Database",
    status: "warning",
    vulnerabilities: 3,
    lastScanned: "2024-01-27",
    owner: "Data Team",
    location: "US-WEST-2",
    osVersion: "PostgreSQL 13",
  },
  {
    id: "AST-006",
    name: "Load Balancer",
    type: "Server",
    status: "healthy",
    vulnerabilities: 0,
    lastScanned: "2024-01-30",
    owner: "Infrastructure Team",
    location: "US-CENTRAL-1",
    osVersion: "F5 BIG-IP",
  },
];

function mapAssetStatus(
  criticality: string,
  vulnCount?: number,
): "healthy" | "warning" | "critical" {
  if (criticality === "critical" || (vulnCount && vulnCount > 10))
    return "critical";
  if (criticality === "high" || (vulnCount && vulnCount > 3)) return "warning";
  return "healthy";
}

function mapApiAsset(asset: ApiAsset): Asset {
  return {
    id: asset.id,
    name: asset.name,
    type:
      asset.asset_type.charAt(0).toUpperCase() +
      asset.asset_type.slice(1).replace(/_/g, " "),
    status: mapAssetStatus(asset.criticality, asset.vulnerabilities_count),
    vulnerabilities: asset.vulnerabilities_count || 0,
    lastScanned: asset.updated_at
      ? new Date(asset.updated_at).toLocaleDateString()
      : "N/A",
    owner: asset.owner || asset.department || "Unassigned",
    location: asset.location || "N/A",
    osVersion: asset.operating_system || "N/A",
  };
}

export default function AssetsView() {
  const [assets, setAssets] = useState<Asset[]>(mockAssets);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAssets = async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);

      const response = await assetsApi.list({ page_size: 50 });
      if (response && response.length > 0) {
        setAssets(response.map(mapApiAsset));
      }
    } catch (err) {
      console.warn("Using mock data - API unavailable:", err);
      setAssets(mockAssets);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);
  const getStatusColor = (status: string) => {
    switch (status) {
      case "healthy":
        return "bg-green-50 text-green-700 border-green-200";
      case "warning":
        return "bg-yellow-50 text-yellow-700 border-yellow-200";
      case "critical":
        return "bg-red-50 text-red-700 border-red-200";
      default:
        return "bg-gray-50 text-gray-700 dark:text-white border-gray-200 dark:border-gray-700";
    }
  };

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case "healthy":
        return "bg-green-100 text-green-800";
      case "warning":
        return "bg-yellow-100 text-yellow-800";
      case "critical":
        return "bg-red-100 text-red-800";
      default:
        return "bg-gray-100 text-gray-800 dark:text-white";
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "Server":
        return <Server className="w-5 h-5" />;
      case "Database":
        return <Database className="w-5 h-5" />;
      default:
        return <Shield className="w-5 h-5" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Assets
          </h1>
          {loading && (
            <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => fetchAssets(true)}
            disabled={refreshing}
            className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center space-x-2"
          >
            <RefreshCw
              className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
            />
            <span>Refresh</span>
          </button>
          <button className="px-4 py-2 bg-primary text-white rounded-md hover:bg-primary/90 transition-colors">
            + Add Asset
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-600 dark:text-white">
            Total Assets
          </div>
          <div className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
            {assets.length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-600 dark:text-white">Healthy</div>
          <div className="text-2xl font-bold text-green-600 mt-1">
            {assets.filter((a) => a.status === "healthy").length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-600 dark:text-white">Warning</div>
          <div className="text-2xl font-bold text-yellow-600 mt-1">
            {assets.filter((a) => a.status === "warning").length}
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-600 dark:text-white">Critical</div>
          <div className="text-2xl font-bold text-red-600 mt-1">
            {assets.filter((a) => a.status === "critical").length}
          </div>
        </div>
      </div>

      {/* Assets Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200 dark:border-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Asset Name
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Vulnerabilities
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  OS Version
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Location
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Owner
                </th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-900 dark:text-white">
                  Last Scanned
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {assets.map((asset) => (
                <tr
                  key={asset.id}
                  className="hover:bg-gray-50 transition-colors"
                >
                  <td className="px-6 py-4 text-sm">
                    <div className="flex items-center space-x-2">
                      <div className="text-gray-400">
                        {getTypeIcon(asset.type)}
                      </div>
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">
                          {asset.name}
                        </div>
                        <div className="text-xs text-gray-500">{asset.id}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-white">
                    {asset.type}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusBadgeColor(asset.status)}`}
                    >
                      {asset.status.charAt(0).toUpperCase() +
                        asset.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <div className="flex items-center space-x-1">
                      {asset.vulnerabilities > 0 && (
                        <AlertCircle className="w-4 h-4 text-red-500" />
                      )}
                      <span className="text-gray-900 dark:text-white">
                        {asset.vulnerabilities}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-white">
                    {asset.osVersion}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-white">
                    {asset.location}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-white">
                    {asset.owner}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-white">
                    {asset.lastScanned}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
