"use client";

import { useState } from "react";
import TopNavBar from "@/components/TopNavBar";
import Sidebar from "@/components/Sidebar";
import Dashboard from "@/components/Dashboard";
import AttackSimulator from "@/components/AttackSimulator";
import ExecutiveView from "@/components/ExecutiveView";
import RisksView from "@/components/RisksView";
import AlertsView from "@/components/AlertsView";
import ActionsView from "@/components/ActionsView";
import AssetsView from "@/components/AssetsView";
import ReportsView from "@/components/ReportsView";
import SettingsView from "@/components/SettingsView";

export default function Home() {
  const [activeView, setActiveView] = useState("overview");

  return (
    <div className="min-h-screen bg-[#F8FAFC] dark:bg-gray-900 transition-colors">
      <TopNavBar />
      <div className="flex">
        <Sidebar activeView={activeView} setActiveView={setActiveView} />
        <main className="flex-1 ml-64 mt-16 p-4">
          {activeView === "overview" && (
            <Dashboard
              onNavigateToRisks={() => setActiveView("risks")}
              onNavigateToAlerts={() => setActiveView("alerts")}
              onNavigateToActions={() => setActiveView("actions")}
            />
          )}
          {activeView === "risks" && <RisksView />}
          {activeView === "alerts" && <AlertsView />}
          {activeView === "actions" && <ActionsView />}
          {activeView === "assets" && <AssetsView />}
          {activeView === "simulator" && <AttackSimulator />}
          {activeView === "executive" && <ExecutiveView />}
          {activeView === "reports" && <ReportsView />}
          {activeView === "settings" && <SettingsView />}
        </main>
      </div>
    </div>
  );
}
