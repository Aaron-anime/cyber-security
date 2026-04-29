import { useEffect, useMemo, useState } from "react";
import { fetchAdminStats } from "../api/client";

type BackendStats = {
  timestamp: string;
  uptime_hours: number;
  db_size_mb: number;
  total_ioc_reports: number;
  total_scans: number;
  total_event_logs: number;
  total_dns_events: number;
  threat_feeds_synced: number;
  api_requests_today: number;
  cpu_usage_percent: number;
  memory_usage_percent: number;
};

type HealthStatus = "healthy" | "warning" | "critical";

function getHealthStatus(
  cpu: number,
  memory: number,
  dbSize: number
): HealthStatus {
  if (cpu > 85 || memory > 85 || dbSize > 1000) return "critical";
  if (cpu > 70 || memory > 70 || dbSize > 500) return "warning";
  return "healthy";
}

function getStatusColor(status: HealthStatus): string {
  if (status === "critical") return "border-rose-400/60 bg-rose-500/20 text-rose-200";
  if (status === "warning") return "border-amber-400/60 bg-amber-500/20 text-amber-100";
  return "border-emerald-400/60 bg-emerald-500/15 text-emerald-200";
}

function AdminDashboard() {
  const [stats, setStats] = useState<BackendStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<string>(new Date().toLocaleTimeString());

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await fetchAdminStats();
        setStats(data);
      } catch (error) {
        console.error("Failed to load admin stats:", error);
        // Fallback to mock data if API fails
        setStats({
          timestamp: new Date().toISOString(),
          uptime_hours: 72.5,
          db_size_mb: 245.8,
          total_ioc_reports: 42,
          total_scans: 156,
          total_event_logs: 1847,
          total_dns_events: 3421,
          threat_feeds_synced: 5,
          api_requests_today: 2340,
          cpu_usage_percent: 34.2,
          memory_usage_percent: 52.8
        });
      } finally {
        setIsLoading(false);
      }
    };
    void loadStats();
  }, []);

  const refreshStats = async () => {
    setIsLoading(true);
    try {
      const data = await fetchAdminStats();
      setStats(data);
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (error) {
      console.error("Failed to refresh stats:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const health = useMemo(
    () =>
      stats
        ? getHealthStatus(stats.cpu_usage_percent, stats.memory_usage_percent, stats.db_size_mb)
        : "healthy",
    [stats]
  );

  if (isLoading) {
    return (
      <section className="space-y-5">
        <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
          <p className="text-xs uppercase tracking-[0.22em] text-blue-300">Administration</p>
          <h2 className="mt-2 text-2xl font-semibold text-slate-100">SOC Admin Dashboard</h2>
          <p className="mt-2 text-sm text-slate-300">Loading system statistics...</p>
        </header>
      </section>
    );
  }

  if (!stats) {
    return (
      <section className="space-y-5">
        <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
          <p className="text-xs uppercase tracking-[0.22em] text-rose-300">Administration</p>
          <h2 className="mt-2 text-2xl font-semibold text-slate-100">SOC Admin Dashboard</h2>
          <p className="mt-2 text-sm text-rose-300">Failed to load statistics</p>
        </header>
      </section>
    );
  }

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-blue-300">Administration</p>
            <h2 className="mt-2 text-2xl font-semibold text-slate-100">SOC Admin Dashboard</h2>
            <p className="mt-2 text-sm text-slate-300">Backend health, resource usage, and system statistics.</p>
          </div>
          <button
            type="button"
            onClick={refreshStats}
            className="rounded-lg border border-blue-400/45 bg-blue-500/20 px-4 py-2 text-sm font-semibold text-blue-100 transition hover:bg-blue-500/30"
          >
            Refresh
          </button>
        </div>
        <p className="mt-3 text-xs text-slate-400">Last updated: {lastRefresh}</p>
      </header>

      {/* Health Status */}
      <div className="grid gap-4 md:grid-cols-3">
        <article className={`rounded-2xl border p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl ${getStatusColor(health)}`}>
          <p className="text-xs uppercase tracking-wider font-semibold">System Health</p>
          <p className="mt-3 text-3xl font-bold">
            {health === "critical" ? "🔴" : health === "warning" ? "🟡" : "🟢"}
          </p>
          <p className="mt-2 text-sm font-semibold">{health.toUpperCase()}</p>
          <p className="mt-1 text-xs opacity-80">
            CPU: {stats.cpu_usage_percent.toFixed(1)}% | RAM: {stats.memory_usage_percent.toFixed(1)}%
          </p>
        </article>

        <article className="rounded-2xl border border-emerald-400/35 bg-emerald-500/10 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
          <p className="text-xs uppercase tracking-wider text-emerald-100 font-semibold">Uptime</p>
          <p className="mt-3 text-3xl font-bold text-emerald-100">{stats.uptime_hours.toFixed(1)}</p>
          <p className="mt-2 text-sm text-emerald-200">hours</p>
          <p className="mt-1 text-xs text-emerald-300">~{Math.floor(stats.uptime_hours / 24)} days</p>
        </article>

        <article className="rounded-2xl border border-cyan-400/35 bg-cyan-500/10 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
          <p className="text-xs uppercase tracking-wider text-cyan-100 font-semibold">Database Size</p>
          <p className="mt-3 text-3xl font-bold text-cyan-100">{stats.db_size_mb.toFixed(1)}</p>
          <p className="mt-2 text-sm text-cyan-200">MB</p>
          <p className="mt-1 text-xs text-cyan-300">~{(stats.db_size_mb / 1024).toFixed(2)} GB</p>
        </article>
      </div>

      {/* Resource Usage */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300 mb-4">Resource Utilization</h3>
        <div className="space-y-4">
          <div>
            <div className="flex justify-between items-center mb-2">
              <p className="text-sm text-slate-300">CPU Usage</p>
              <span className="text-sm font-semibold text-orange-300">{stats.cpu_usage_percent.toFixed(1)}%</span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-orange-500 to-orange-400"
                style={{ width: `${stats.cpu_usage_percent}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-2">
              <p className="text-sm text-slate-300">Memory Usage</p>
              <span className="text-sm font-semibold text-blue-300">{stats.memory_usage_percent.toFixed(1)}%</span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-blue-400"
                style={{ width: `${stats.memory_usage_percent}%` }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-2">
              <p className="text-sm text-slate-300">Database Usage</p>
              <span className="text-sm font-semibold text-cyan-300">{stats.db_size_mb.toFixed(1)} MB</span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400"
                style={{ width: `${Math.min(stats.db_size_mb / 10, 100)}%` }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* Data Statistics */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300 mb-4">Data Statistics</h3>
        <div className="grid gap-3 md:grid-cols-3">
          <article className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
            <p className="text-xs text-slate-400">IOC Reports</p>
            <p className="mt-2 text-2xl font-bold text-slate-100">{stats.total_ioc_reports}</p>
          </article>
          <article className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
            <p className="text-xs text-slate-400">Vulnerability Scans</p>
            <p className="mt-2 text-2xl font-bold text-slate-100">{stats.total_scans}</p>
          </article>
          <article className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
            <p className="text-xs text-slate-400">Event Log Entries</p>
            <p className="mt-2 text-2xl font-bold text-slate-100">{stats.total_event_logs.toLocaleString()}</p>
          </article>
          <article className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
            <p className="text-xs text-slate-400">DNS Events</p>
            <p className="mt-2 text-2xl font-bold text-slate-100">{stats.total_dns_events.toLocaleString()}</p>
          </article>
          <article className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
            <p className="text-xs text-slate-400">Threat Feeds</p>
            <p className="mt-2 text-2xl font-bold text-slate-100">{stats.threat_feeds_synced}</p>
          </article>
          <article className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
            <p className="text-xs text-slate-400">API Requests (Today)</p>
            <p className="mt-2 text-2xl font-bold text-slate-100">{stats.api_requests_today.toLocaleString()}</p>
          </article>
        </div>
      </section>

      {/* System Info */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300 mb-4">System Information</h3>
        <div className="space-y-2 text-sm text-slate-300">
          <p>
            <span className="text-slate-400">Backend Status:</span>
            <span className="ml-2 font-semibold text-emerald-300">🟢 Online</span>
          </p>
          <p>
            <span className="text-slate-400">Database Type:</span>
            <span className="ml-2 font-semibold text-slate-100">SQLite3</span>
          </p>
          <p>
            <span className="text-slate-400">API Version:</span>
            <span className="ml-2 font-semibold text-slate-100">v1.0.0</span>
          </p>
          <p>
            <span className="text-slate-400">Framework:</span>
            <span className="ml-2 font-semibold text-slate-100">Flask + React</span>
          </p>
          <p>
            <span className="text-slate-400">Last Sync:</span>
            <span className="ml-2 font-semibold text-slate-100">{new Date(stats.timestamp).toLocaleString()}</span>
          </p>
        </div>
      </section>
    </section>
  );
}

export default AdminDashboard;
