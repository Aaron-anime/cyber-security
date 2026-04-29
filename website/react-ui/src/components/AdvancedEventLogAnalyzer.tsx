import { useMemo, useState } from "react";

type ParsedEvent = {
  id: string;
  lineNumber: number;
  timestamp: string;
  severity: "CRITICAL" | "ERROR" | "WARN" | "INFO";
  eventType: string;
  source: string;
  message: string;
};

type CorrelationRule = {
  id: string;
  name: string;
  enabled: boolean;
  pattern: string; // Regex for message matching
  minOccurrences: number;
  timeWindowSeconds: number;
};

type CorrelationMatch = {
  ruleId: string;
  ruleName: string;
  matchCount: number;
  events: ParsedEvent[];
  severity: "HIGH" | "MEDIUM" | "LOW";
};

const DEFAULT_CORRELATION_RULES: CorrelationRule[] = [
  {
    id: "brute-force",
    name: "Brute Force Attack",
    enabled: true,
    pattern: "Failed login|authentication failed|denied",
    minOccurrences: 5,
    timeWindowSeconds: 300
  },
  {
    id: "dns-exfil",
    name: "DNS Exfiltration Pattern",
    enabled: true,
    pattern: "DNS query.*suspicious|malicious domain|sinkhole",
    minOccurrences: 3,
    timeWindowSeconds: 600
  },
  {
    id: "process-injection",
    name: "Process Injection Indicators",
    enabled: true,
    pattern: "process.*inject|remote thread|dll inject",
    minOccurrences: 2,
    timeWindowSeconds: 120
  },
  {
    id: "privilege-escalation",
    name: "Privilege Escalation Attempts",
    enabled: true,
    pattern: "privilege|elevated|sudo|admin|root",
    minOccurrences: 3,
    timeWindowSeconds: 300
  }
];

function parseTimestampToEpoch(timestamp: string): number | null {
  if (timestamp === "N/A") return null;
  const parsed = Date.parse(timestamp);
  return Number.isNaN(parsed) ? null : parsed;
}

function detectCorrelations(events: ParsedEvent[], rules: CorrelationRule[]): CorrelationMatch[] {
  const matches: CorrelationMatch[] = [];

  for (const rule of rules) {
    if (!rule.enabled) continue;

    try {
      const regex = new RegExp(rule.pattern, "i");
      const matchingEvents = events.filter((event) => regex.test(event.message));

      if (matchingEvents.length < rule.minOccurrences) continue;

      // Check time window clustering
      const clusters: ParsedEvent[][] = [];
      let currentCluster: ParsedEvent[] = [matchingEvents[0]];

      for (let i = 1; i < matchingEvents.length; i += 1) {
        const current = matchingEvents[i];
        const previous = matchingEvents[i - 1];

        const currentEpoch = parseTimestampToEpoch(current.timestamp);
        const prevEpoch = parseTimestampToEpoch(previous.timestamp);

        if (currentEpoch !== null && prevEpoch !== null) {
          const timeDiffSeconds = (currentEpoch - prevEpoch) / 1000;
          if (timeDiffSeconds <= rule.timeWindowSeconds) {
            currentCluster.push(current);
          } else {
            if (currentCluster.length >= rule.minOccurrences) {
              clusters.push(currentCluster);
            }
            currentCluster = [current];
          }
        } else {
          currentCluster.push(current);
        }
      }

      if (currentCluster.length >= rule.minOccurrences) {
        clusters.push(currentCluster);
      }

      // Add matches for each qualifying cluster
      for (const cluster of clusters) {
        matches.push({
          ruleId: rule.id,
          ruleName: rule.name,
          matchCount: cluster.length,
          events: cluster,
          severity: rule.minOccurrences >= 5 ? "HIGH" : rule.minOccurrences >= 3 ? "MEDIUM" : "LOW"
        });
      }
    } catch {
      // Skip invalid regex patterns
    }
  }

  return matches.sort((a, b) => {
    const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}

export function AdvancedEventLogAnalyzer({ events }: { events: ParsedEvent[] }) {
  const [rules, setRules] = useState<CorrelationRule[]>(DEFAULT_CORRELATION_RULES);
  const [customRegex, setCustomRegex] = useState("");
  const [regexError, setRegexError] = useState("");
  const [showRuleEditor, setShowRuleEditor] = useState(false);

  const correlations = useMemo(() => detectCorrelations(events, rules), [events, rules]);

  const regexMatches = useMemo(() => {
    if (!customRegex.trim()) return [];
    try {
      const regex = new RegExp(customRegex, "i");
      setRegexError("");
      return events.filter((event) => regex.test(event.message));
    } catch (error) {
      setRegexError(`Invalid regex: ${String(error)}`);
      return [];
    }
  }, [customRegex, events]);

  function toggleRule(ruleId: string) {
    setRules((current) =>
      current.map((rule) => (rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule))
    );
  }

  function getSeverityColor(severity: "HIGH" | "MEDIUM" | "LOW"): string {
    if (severity === "HIGH") return "border-rose-400/60 bg-rose-500/20 text-rose-200";
    if (severity === "MEDIUM") return "border-orange-400/60 bg-orange-500/20 text-orange-100";
    return "border-amber-400/60 bg-amber-500/20 text-amber-100";
  }

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <p className="text-xs uppercase tracking-[0.22em] text-cyan-300">Advanced Analytics</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-100">Event Correlation & Threat Detection</h2>
        <p className="mt-2 text-sm text-slate-300">
          Detect attack patterns, behavioral anomalies, and threat indicators through intelligent event correlation.
        </p>
      </header>

      {/* Regex Filter Section */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Custom Regex Filter</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={customRegex}
            onChange={(e) => setCustomRegex(e.target.value)}
            placeholder="e.g., (error|critical).*timeout|malicious.*detected"
            className="w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
          />
          {regexError && <p className="text-xs text-rose-300">{regexError}</p>}
          <p className="text-xs text-slate-400">
            Matched: <span className="font-semibold text-cyan-300">{regexMatches.length}</span> events
          </p>
        </div>
      </section>

      {/* Correlation Rules Section */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Correlation Rules</h3>
          <button
            type="button"
            onClick={() => setShowRuleEditor(!showRuleEditor)}
            className="rounded-lg border border-blue-400/45 bg-blue-500/20 px-3 py-1 text-xs font-semibold text-blue-100 transition hover:bg-blue-500/30"
          >
            {showRuleEditor ? "Hide" : "Edit Rules"}
          </button>
        </div>

        {showRuleEditor && (
          <div className="mb-4 space-y-2 border-t border-slate-700 pt-4">
            {rules.map((rule) => (
              <div
                key={rule.id}
                className="flex items-center gap-3 rounded-lg border border-slate-700/50 bg-slate-950/70 p-3"
              >
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={() => toggleRule(rule.id)}
                  className="h-4 w-4"
                />
                <div className="flex-1">
                  <p className="text-sm font-medium text-slate-100">{rule.name}</p>
                  <p className="text-xs text-slate-400">
                    Pattern: {rule.pattern} | Min: {rule.minOccurrences} events | Window: {rule.timeWindowSeconds}s
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Detected Correlations */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">
          Threat Detections ({correlations.length})
        </h3>

        {correlations.length === 0 ? (
          <p className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-4 text-sm text-slate-400">
            No correlation patterns detected.
          </p>
        ) : (
          <div className="space-y-3">
            {correlations.map((correlation, idx) => (
              <div
                key={`${correlation.ruleId}-${idx}`}
                className={`rounded-lg border p-3 ${getSeverityColor(correlation.severity)}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <p className="font-semibold text-sm">{correlation.ruleName}</p>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${getSeverityColor(correlation.severity)}`}>
                    {correlation.severity} ({correlation.matchCount} events)
                  </span>
                </div>
                <div className="text-xs space-y-1">
                  {correlation.events.slice(0, 3).map((event) => (
                    <p key={event.id} className="text-slate-200 truncate">
                      {event.timestamp} | {event.source} | {event.message.substring(0, 60)}...
                    </p>
                  ))}
                  {correlation.events.length > 3 && (
                    <p className="text-slate-400">+{correlation.events.length - 3} more events</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Regex Matches Table */}
      {customRegex && (
        <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">
            Regex Match Results ({regexMatches.length})
          </h3>
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-950/80 text-slate-300">
                <tr>
                  <th className="px-3 py-3 text-left font-semibold">Timestamp</th>
                  <th className="px-3 py-3 text-left font-semibold">Severity</th>
                  <th className="px-3 py-3 text-left font-semibold">Source</th>
                  <th className="px-3 py-3 text-left font-semibold">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-900/45">
                {regexMatches.slice(0, 20).map((event) => (
                  <tr key={event.id} className="hover:bg-slate-800/35">
                    <td className="px-3 py-2 whitespace-nowrap text-slate-300 text-xs">{event.timestamp}</td>
                    <td className="px-3 py-2">
                      <span className="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold border">
                        {event.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-200">{event.source}</td>
                    <td className="px-3 py-2 text-slate-100 truncate">{event.message.substring(0, 80)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {regexMatches.length > 20 && (
            <p className="mt-2 text-xs text-slate-400">Showing 20 of {regexMatches.length} matches</p>
          )}
        </section>
      )}
    </section>
  );
}

export default AdvancedEventLogAnalyzer;
