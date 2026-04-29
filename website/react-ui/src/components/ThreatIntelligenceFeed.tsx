import { useEffect, useMemo, useState } from "react";
import { syncThreatFeeds, fetchThreatIndicators } from "../api/client";

type ThreatIndicator = {
  id: string;
  type: "malware_hash" | "c2_domain" | "malicious_ip" | "phishing_url" | "suspicious_file";
  value: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  confidence: number;
  added_at: string;
  last_seen: string;
};

type ThreatFeedSource = {
  id: string;
  name: string;
  url: string;
  description: string;
  enabled: boolean;
  update_interval_hours: number;
  last_synced?: string;
  indicator_count: number;
  format: "json" | "csv" | "txt";
};

const DEFAULT_THREAT_FEEDS: ThreatFeedSource[] = [
  {
    id: "alienvault-otx",
    name: "AlienVault OTX",
    url: "https://otx.alienvault.com/api/v1/pulses",
    description: "Open Threat Exchange - Community threat intelligence",
    enabled: true,
    update_interval_hours: 1,
    last_synced: new Date(Date.now() - 3600000).toISOString(),
    indicator_count: 4521,
    format: "json"
  },
  {
    id: "abuse-urlhaus",
    name: "Abuse.ch URLhaus",
    url: "https://urlhaus-api.abuse.ch/v1/urls/",
    description: "Curated malware distribution site database",
    enabled: true,
    update_interval_hours: 6,
    last_synced: new Date(Date.now() - 21600000).toISOString(),
    indicator_count: 2341,
    format: "json"
  },
  {
    id: "abuse-sslbl",
    name: "Abuse.ch SSL Blacklist",
    url: "https://sslbl.abuse.ch/api/",
    description: "Malicious SSL certificates & C2 servers",
    enabled: true,
    update_interval_hours: 12,
    indicator_count: 1567,
    format: "csv"
  },
  {
    id: "sans-isc",
    name: "SANS ISC Logs",
    url: "https://isc.sans.edu/api/",
    description: "Internet Storm Center threat activity logs",
    enabled: true,
    update_interval_hours: 24,
    last_synced: new Date(Date.now() - 86400000).toISOString(),
    indicator_count: 1234,
    format: "json"
  },
  {
    id: "greynoise",
    name: "GreyNoise Community",
    url: "https://api.greynoise.io/v3/community/",
    description: "Internet noise classification and scanning activity",
    enabled: true,
    update_interval_hours: 12,
    last_synced: new Date(Date.now() - 43200000).toISOString(),
    indicator_count: 3456,
    format: "json"
  },
  {
    id: "cybercrime-tracker",
    name: "Cybercrime Tracker",
    url: "https://cybercrime-tracker.net/api.php",
    description: "C2 & malware distribution URLs",
    enabled: true,
    update_interval_hours: 6,
    indicator_count: 892,
    format: "txt"
  },
  {
    id: "phishtank",
    name: "PhishTank",
    url: "https://api.phishtank.com/api/fetch.json",
    description: "Verified phishing URLs database",
    enabled: true,
    update_interval_hours: 4,
    indicator_count: 2145,
    format: "json"
  },
  {
    id: "emergingthreats",
    name: "Emerging Threats",
    url: "https://rules.emergingthreats.net/open/suricata/",
    description: "Emerging threats ruleset & IOCs",
    enabled: true,
    update_interval_hours: 1,
    indicator_count: 5234,
    format: "json"
  },
  {
    id: "cisa-aes",
    name: "CISA Known Exploited Vulnerabilities",
    url: "https://www.cisa.gov/sites/default/files/",
    description: "CISA KEV catalog with active exploitation data",
    enabled: true,
    update_interval_hours: 8,
    indicator_count: 1876,
    format: "json"
  },
  {
    id: "malc0de",
    name: "Malc0de Database",
    url: "https://malc0de.com/database/",
    description: "Malware command & control servers",
    enabled: false,
    update_interval_hours: 24,
    indicator_count: 0,
    format: "csv"
  }
];

const SAMPLE_INDICATORS: ThreatIndicator[] = [
  {
    id: "ind-001",
    type: "c2_domain",
    value: "command.malicious-actors.ru",
    severity: "critical",
    source: "AlienVault OTX",
    confidence: 98,
    added_at: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date(Date.now() - 1800000).toISOString()
  },
  {
    id: "ind-002",
    type: "malware_hash",
    value: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    severity: "critical",
    source: "Abuse.ch",
    confidence: 99,
    added_at: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date(Date.now() - 3600000).toISOString()
  },
  {
    id: "ind-003",
    type: "malicious_ip",
    value: "203.0.113.45",
    severity: "high",
    source: "GreyNoise Community",
    confidence: 94,
    added_at: new Date(Date.now() - 86400000).toISOString(),
    last_seen: new Date(Date.now() - 43200000).toISOString()
  },
  {
    id: "ind-004",
    type: "phishing_url",
    value: "https://secure-verify-paypal-account.example.net",
    severity: "high",
    source: "AlienVault OTX",
    confidence: 87,
    added_at: new Date(Date.now() - 172800000).toISOString(),
    last_seen: new Date(Date.now() - 86400000).toISOString()
  }
];

function getSeverityColor(severity: "critical" | "high" | "medium" | "low"): string {
  if (severity === "critical") return "border-rose-500/60 bg-rose-500/20 text-rose-200";
  if (severity === "high") return "border-orange-500/60 bg-orange-500/20 text-orange-100";
  if (severity === "medium") return "border-amber-400/60 bg-amber-500/20 text-amber-100";
  return "border-blue-400/60 bg-blue-500/20 text-blue-100";
}

function getTypeIcon(type: string): string {
  if (type === "malware_hash") return "🔐";
  if (type === "c2_domain") return "🎯";
  if (type === "malicious_ip") return "🌐";
  if (type === "phishing_url") return "🎣";
  if (type === "suspicious_file") return "📄";
  return "❓";
}

function ThreatIntelligenceFeed() {
  const [feeds, setFeeds] = useState<ThreatFeedSource[]>(DEFAULT_THREAT_FEEDS);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>(SAMPLE_INDICATORS);
  const [filteredType, setFilteredType] = useState<string | "ALL">("ALL");
  const [syncInProgress, setSyncInProgress] = useState(false);
  const [syncStatus, setSyncStatus] = useState("");

  const filteredIndicators = useMemo(() => {
    if (filteredType === "ALL") return indicators;
    return indicators.filter((ind) => ind.type === filteredType);
  }, [indicators, filteredType]);

  const indicatorStats = useMemo(() => {
    return {
      critical: indicators.filter((i) => i.severity === "critical").length,
      high: indicators.filter((i) => i.severity === "high").length,
      medium: indicators.filter((i) => i.severity === "medium").length,
      low: indicators.filter((i) => i.severity === "low").length,
      total: indicators.length
    };
  }, [indicators]);

  function toggleFeed(feedId: string) {
    setFeeds((current) =>
      current.map((feed) => (feed.id === feedId ? { ...feed, enabled: !feed.enabled } : feed))
    );
  }

  const handleSyncFeeds = async () => {
    setSyncInProgress(true);
    setSyncStatus("Syncing threat feeds...");

    try {
      const enabledFeedIds = feeds.filter((f) => f.enabled).map((f) => f.id);
      const response = await syncThreatFeeds(enabledFeedIds);

      setFeeds((current) =>
        current.map((feed) => ({
          ...feed,
          last_synced: feed.enabled ? new Date().toISOString() : feed.last_synced
        }))
      );

      setSyncStatus(
        `✓ Successfully synced ${response.feeds_synced} feeds. Added ${response.new_indicators} new indicators.`
      );
    } catch (error) {
      setSyncStatus(`✗ Sync failed: ${String(error)}`);
    } finally {
      setSyncInProgress(false);
    }
  };

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-purple-300">Threat Intelligence</p>
            <h2 className="mt-2 text-2xl font-semibold text-slate-100">Threat Feed Auto-Ingest</h2>
            <p className="mt-2 text-sm text-slate-300">
              Automatically sync malware hashes, C2 domains, and threat indicators from multiple sources.
            </p>
          </div>
          <button
            type="button"
            onClick={handleSyncFeeds}
            disabled={syncInProgress}
            className="rounded-lg border border-purple-400/45 bg-purple-500/20 px-4 py-2 text-sm font-semibold text-purple-100 transition hover:bg-purple-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {syncInProgress ? "Syncing..." : "Sync All Feeds"}
          </button>
        </div>
        {syncStatus && <p className="mt-3 text-xs text-slate-400">{syncStatus}</p>}
      </header>

      {/* Threat Feed Sources */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300 mb-4">Feed Sources</h3>
        <div className="space-y-2">
          {feeds.map((feed) => (
            <div key={feed.name} className="flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-950/70 p-4">
              <label className="flex items-center gap-3 flex-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={feed.enabled}
                  onChange={() => toggleFeed(feed.name)}
                  className="h-4 w-4"
                />
                <div>
                  <p className="text-sm font-medium text-slate-100">{feed.name}</p>
                  <p className="text-xs text-slate-400">{feed.url}</p>
                </div>
              </label>
              <div className="text-right">
                <p className="text-sm font-semibold text-slate-100">{feed.indicator_count}</p>
                <p className="text-xs text-slate-400">indicators</p>
              </div>
              <div className="ml-4 text-right">
                {feed.enabled ? (
                  <p className="text-xs text-emerald-300">
                    ✓ {feed.last_synced ? `${Math.round((Date.now() - new Date(feed.last_synced).getTime()) / 3600000)}h ago` : "Never"}
                  </p>
                ) : (
                  <p className="text-xs text-slate-400">Disabled</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Threat Statistics */}
      <div className="grid gap-3 md:grid-cols-5">
        <article className="rounded-xl border border-rose-400/35 bg-rose-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-rose-100">Critical</p>
          <p className="mt-2 text-2xl font-bold text-rose-100">{indicatorStats.critical}</p>
        </article>
        <article className="rounded-xl border border-orange-400/35 bg-orange-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-orange-100">High</p>
          <p className="mt-2 text-2xl font-bold text-orange-100">{indicatorStats.high}</p>
        </article>
        <article className="rounded-xl border border-amber-400/35 bg-amber-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-amber-100">Medium</p>
          <p className="mt-2 text-2xl font-bold text-amber-100">{indicatorStats.medium}</p>
        </article>
        <article className="rounded-xl border border-blue-400/35 bg-blue-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-blue-100">Low</p>
          <p className="mt-2 text-2xl font-bold text-blue-100">{indicatorStats.low}</p>
        </article>
        <article className="rounded-xl border border-cyan-400/35 bg-cyan-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-cyan-100">Total</p>
          <p className="mt-2 text-2xl font-bold text-cyan-100">{indicatorStats.total}</p>
        </article>
      </div>

      {/* Threat Indicators Table */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Threat Indicators</h3>
          <select
            value={filteredType}
            onChange={(e) => setFilteredType(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-purple-500/60"
          >
            <option value="ALL">All Types</option>
            <option value="malware_hash">Malware Hash</option>
            <option value="c2_domain">C2 Domain</option>
            <option value="malicious_ip">Malicious IP</option>
            <option value="phishing_url">Phishing URL</option>
          </select>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-950/80 text-slate-300">
              <tr>
                <th className="px-4 py-3 text-left font-semibold">Type</th>
                <th className="px-4 py-3 text-left font-semibold">Value</th>
                <th className="px-4 py-3 text-left font-semibold">Severity</th>
                <th className="px-4 py-3 text-left font-semibold">Confidence</th>
                <th className="px-4 py-3 text-left font-semibold">Source</th>
                <th className="px-4 py-3 text-left font-semibold">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/45">
              {filteredIndicators.map((indicator) => (
                <tr key={indicator.id} className="hover:bg-slate-800/35">
                  <td className="px-4 py-3">
                    <span className="text-lg">{getTypeIcon(indicator.type)}</span>
                  </td>
                  <td className="px-4 py-3 text-slate-100 truncate font-mono text-xs">{indicator.value}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold border ${getSeverityColor(indicator.severity)}`}>
                      {indicator.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-200">{Math.round(indicator.confidence)}%</td>
                  <td className="px-4 py-3 text-slate-300">{indicator.source}</td>
                  <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                    {Math.round((Date.now() - new Date(indicator.last_seen).getTime()) / 3600000)}h ago
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-slate-400">
          Showing {filteredIndicators.length} of {indicators.length} indicators
        </p>
      </section>
    </section>
  );
}

export default ThreatIntelligenceFeed;
