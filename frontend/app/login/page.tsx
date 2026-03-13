"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

const demoCredentials = {
  email: "demo-user@contexta.io",
  password: "demo12345",
};

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState(demoCredentials.email);
  const [password, setPassword] = useState(demoCredentials.password);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/auth/login`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            username: email,
            password: password,
          }),
        },
      );

      if (!response.ok) {
        throw new Error("Login failed");
      }

      const data = await response.json();

      // Store tokens
      localStorage.setItem("contexta_access_token", data.access_token);
      if (data.refresh_token) {
        localStorage.setItem("contexta_refresh_token", data.refresh_token);
      }

      // Redirect to dashboard
      router.push("/");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Login failed. Please try again.",
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setEmail(demoCredentials.email);
    setPassword(demoCredentials.password);

    // Auto-fill and submit
    setTimeout(() => {
      const form = document.getElementById("loginForm") as HTMLFormElement;
      if (form) form.dispatchEvent(new Event("submit", { bubbles: true }));
    }, 100);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-600 via-blue-500 to-purple-600">
      <div className="w-full max-w-md mx-auto p-8">
        <div className="bg-white rounded-lg shadow-2xl p-8">
          {/* Logo/Title */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">CONTEXTA</h1>
            <p className="text-gray-600">
              Autonomous Context-Aware Threat Intelligence
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          )}

          {/* Login Form */}
          <form id="loginForm" onSubmit={handleLogin} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                Email Address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition"
                placeholder="user@example.com"
                required
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition"
                placeholder="••••••••"
                required
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-2 px-4 rounded-lg transition mt-6"
            >
              {isLoading ? "Logging in..." : "Login"}
            </button>
          </form>

          {/* Demo Login */}
          <div className="mt-6 pt-6 border-t border-gray-200">
            <p className="text-sm text-gray-600 text-center mb-4">
              Try Demo Account
            </p>
            <button
              onClick={handleDemoLogin}
              className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-semibold py-2 px-4 rounded-lg transition"
            >
              Demo Login
            </button>
            <div className="mt-4 p-4 bg-blue-50 rounded-lg text-xs text-gray-700 space-y-1">
              <p>
                <strong>Demo Email:</strong> {demoCredentials.email}
              </p>
              <p>
                <strong>Demo Password:</strong> {demoCredentials.password}
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-8 text-white text-sm">
          <p>© 2026 Contexta. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
}
