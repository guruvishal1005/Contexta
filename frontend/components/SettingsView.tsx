"use client";

import { useState, useEffect } from "react";
import {
  Save,
  Bell,
  Lock,
  User,
  Shield,
  Palette,
} from "lucide-react";
import { useTheme } from "@/contexts/ThemeContext";

export default function SettingsView() {
  const { theme, setTheme } = useTheme();
  
  const [settings, setSettings] = useState({
    // Profile Settings
    fullName: "John Doe",
    email: "john.doe@company.com",
    department: "Security Operations",
    role: "Security Administrator",

    // Notification Settings
    emailAlerts: true,
    criticalAlerts: true,
    weeklyReports: true,
    alertThreshold: "high",
    notificationFrequency: "realtime",

    // Security Settings
    twoFactorAuth: true,
    sessionTimeout: "30",
    passwordExpiry: "90",
    loginNotifications: true,

    // Preferences
    theme: "light",
    language: "en",
    dateFormat: "MM/DD/YYYY",
    timezone: "UTC",

    // Data Settings
    dataRetention: "12",
    autoBackup: true,
    logLevel: "info",
  });

  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">(
    "idle",
  );

  // Sync theme from context on mount
  useEffect(() => {
    setSettings(prev => ({ ...prev, theme }));
  }, [theme]);

  const handleInputChange = (field: string, value: string | boolean) => {
    setSettings((prev) => ({
      ...prev,
      [field]: value,
    }));
    
    // Apply theme change immediately when theme is changed
    if (field === "theme") {
      setTheme(value as "light" | "dark" | "auto");
    }
  };

  const handleSave = () => {
    setSaveStatus("saving");
    // Apply theme change
    setTheme(settings.theme as "light" | "dark" | "auto");
    // Simulate saving
    setTimeout(() => {
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus("idle"), 2000);
    }, 500);
  };

  return (
    <div className="h-full overflow-auto bg-white dark:bg-gray-900 transition-colors">
      <div className="max-w-5xl mx-auto p-6">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-8">Settings</h1>

        {/* Save Status */}
        {saveStatus !== "idle" && (
          <div
            className={`mb-6 p-4 rounded-lg ${
              saveStatus === "saved"
                ? "bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-700 text-green-800 dark:text-green-200"
                : "bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-700 text-blue-800 dark:text-blue-200"
            }`}
          >
            {saveStatus === "saving"
              ? "Saving settings..."
              : "Settings saved successfully!"}
          </div>
        )}

        <div className="space-y-6">
          {/* Profile Settings */}
          <section className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 transition-colors">
            <div className="flex items-center gap-2 mb-4">
              <User className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Profile Settings
              </h2>
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Full Name
                  </label>
                  <input
                    type="text"
                    value={settings.fullName}
                    onChange={(e) =>
                      handleInputChange("fullName", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    value={settings.email}
                    onChange={(e) => handleInputChange("email", e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Department
                  </label>
                  <input
                    type="text"
                    value={settings.department}
                    onChange={(e) =>
                      handleInputChange("department", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Role
                  </label>
                  <input
                    type="text"
                    value={settings.role}
                    onChange={(e) => handleInputChange("role", e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
              </div>
            </div>
          </section>

          {/* Notification Settings */}
          <section className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 transition-colors">
            <div className="flex items-center gap-2 mb-4">
              <Bell className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Notification Settings
              </h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700 dark:text-white">
                  Email Alerts
                </label>
                <input
                  type="checkbox"
                  checked={settings.emailAlerts}
                  onChange={(e) =>
                    handleInputChange("emailAlerts", e.target.checked)
                  }
                  className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700 dark:text-white">
                  Critical Alerts Only
                </label>
                <input
                  type="checkbox"
                  checked={settings.criticalAlerts}
                  onChange={(e) =>
                    handleInputChange("criticalAlerts", e.target.checked)
                  }
                  className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700 dark:text-white">
                  Weekly Reports
                </label>
                <input
                  type="checkbox"
                  checked={settings.weeklyReports}
                  onChange={(e) =>
                    handleInputChange("weeklyReports", e.target.checked)
                  }
                  className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600"
                />
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Alert Threshold
                  </label>
                  <select
                    value={settings.alertThreshold}
                    onChange={(e) =>
                      handleInputChange("alertThreshold", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option>low</option>
                    <option>medium</option>
                    <option>high</option>
                    <option>critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Notification Frequency
                  </label>
                  <select
                    value={settings.notificationFrequency}
                    onChange={(e) =>
                      handleInputChange("notificationFrequency", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option value="realtime">Real-time</option>
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          {/* Security Settings */}
          <section className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 transition-colors">
            <div className="flex items-center gap-2 mb-4">
              <Lock className="w-5 h-5 text-red-600 dark:text-red-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Security Settings
              </h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700 dark:text-white">
                  Two-Factor Authentication
                </label>
                <input
                  type="checkbox"
                  checked={settings.twoFactorAuth}
                  onChange={(e) =>
                    handleInputChange("twoFactorAuth", e.target.checked)
                  }
                  className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700 dark:text-white">
                  Login Notifications
                </label>
                <input
                  type="checkbox"
                  checked={settings.loginNotifications}
                  onChange={(e) =>
                    handleInputChange("loginNotifications", e.target.checked)
                  }
                  className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600"
                />
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Session Timeout (minutes)
                  </label>
                  <input
                    type="number"
                    value={settings.sessionTimeout}
                    onChange={(e) =>
                      handleInputChange("sessionTimeout", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Password Expiry (days)
                  </label>
                  <input
                    type="number"
                    value={settings.passwordExpiry}
                    onChange={(e) =>
                      handleInputChange("passwordExpiry", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
              </div>
            </div>
          </section>

          {/* Preferences */}
          <section className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 transition-colors">
            <div className="flex items-center gap-2 mb-4">
              <Palette className="w-5 h-5 text-purple-600 dark:text-purple-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Preferences
              </h2>
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Theme
                  </label>
                  <select
                    value={settings.theme}
                    onChange={(e) => handleInputChange("theme", e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option>light</option>
                    <option>dark</option>
                    <option>auto</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Language
                  </label>
                  <select
                    value={settings.language}
                    onChange={(e) =>
                      handleInputChange("language", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option value="en">English</option>
                    <option value="es">Spanish</option>
                    <option value="fr">French</option>
                    <option value="de">German</option>
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Date Format
                  </label>
                  <select
                    value={settings.dateFormat}
                    onChange={(e) =>
                      handleInputChange("dateFormat", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option>MM/DD/YYYY</option>
                    <option>DD/MM/YYYY</option>
                    <option>YYYY-MM-DD</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Timezone
                  </label>
                  <select
                    value={settings.timezone}
                    onChange={(e) =>
                      handleInputChange("timezone", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option>UTC</option>
                    <option>EST</option>
                    <option>CST</option>
                    <option>MST</option>
                    <option>PST</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          {/* Data Settings */}
          <section className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 transition-colors">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-green-600 dark:text-green-400" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                Data Settings
              </h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-gray-700 dark:text-white">
                  Auto Backup
                </label>
                <input
                  type="checkbox"
                  checked={settings.autoBackup}
                  onChange={(e) =>
                    handleInputChange("autoBackup", e.target.checked)
                  }
                  className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600"
                />
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Data Retention (months)
                  </label>
                  <input
                    type="number"
                    value={settings.dataRetention}
                    onChange={(e) =>
                      handleInputChange("dataRetention", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-white mb-1">
                    Log Level
                  </label>
                  <select
                    value={settings.logLevel}
                    onChange={(e) =>
                      handleInputChange("logLevel", e.target.value)
                    }
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white transition-colors"
                  >
                    <option>debug</option>
                    <option>info</option>
                    <option>warn</option>
                    <option>error</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          {/* Save Button */}
          <div className="flex justify-end">
            <button
              onClick={handleSave}
              disabled={saveStatus === "saving"}
              className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-blue-400 transition-colors font-medium"
            >
              <Save className="w-4 h-4" />
              {saveStatus === "saving" ? "Saving..." : "Save Settings"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
