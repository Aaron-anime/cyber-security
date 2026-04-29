import { useMemo, useState } from "react";

type YaraRule = {
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  strings: string[];
  condition: string;
};

type IocEventRecord = Record<string, unknown>;

type YaraMatch = {
  ruleName: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  matchedStrings: string[];
  affectedEvents: IocEventRecord[];
  eventCount: number;
};

const SAMPLE_YARA_RULES: YaraRule[] = [
  {
    name: "Suspicious_PowerShell_EncodedCommand",
    description: "Detects common encoded PowerShell command patterns",
    severity: "high",
    strings: ["powershell", "-enc", "FromBase64String"],
    condition: "1 of them"
  },
  {
    name: "Suspicious_Lolbin_Download",
    description: "Detects common LOLBIN download/execute strings",
    severity: "high",
    strings: ["certutil -urlcache", "bitsadmin /transfer", "mshta http", "regsvr32 /s /n /u /i:http"],
    condition: "any of them"
  },
  {
    name: "Suspicious_Ransomware_Behavior_Strings",
    description: "Detects strings commonly associated with ransomware behavior",
    severity: "critical",
    strings: ["vssadmin delete shadows", "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled"],
    condition: "1 of them"
  },
  {
    name: "Suspicious_Registry_Modification",
    description: "Detects suspicious registry modifications",
    severity: "medium",
    strings: ["HKLM\\Software\\Microsoft\\Windows\\Run", "HKCU\\Software\\Microsoft\\Windows\\Run", "SetValue"],
    condition: "2 of them"
  },
  {
    name: "C2_Communication_Patterns",
    description: "Detects common Command & Control communication patterns",
    severity: "critical",
    strings: ["POST /api/", "User-Agent: Mozilla", "Content-Disposition", "beacon"],
    condition: "2 of them"
  }
];

function evaluateYaraCondition(condition: string, matchCount: number): boolean {
  if (condition.toLowerCase() === "any of them") return matchCount > 0;
  if (condition.toLowerCase() === "1 of them") return matchCount >= 1;
  if (condition.toLowerCase() === "2 of them") return matchCount >= 2;
  if (condition.toLowerCase() === "all of them") return matchCount > 0;
  return matchCount > 0;
}

function scanEventAgainstRule(event: IocEventRecord, rule: YaraRule): string[] {
  const eventText = JSON.stringify(event).toLowerCase();
  return rule.strings.filter((str) => eventText.includes(str.toLowerCase()));
}

function scanEventsWithYara(events: IocEventRecord[], rules: YaraRule[]): YaraMatch[] {
  const matches: YaraMatch[] = [];

  for (const rule of rules) {
    const affectedEvents: IocEventRecord[] = [];
    const matchedStringsSet = new Set<string>();

    for (const event of events) {
      const matched = scanEventAgainstRule(event, rule);
      if (matched.length > 0 && evaluateYaraCondition(rule.condition, matched.length)) {
        affectedEvents.push(event);
        matched.forEach((str) => matchedStringsSet.add(str));
      }
    }

    if (affectedEvents.length > 0) {
      matches.push({
        ruleName: rule.name,
        description: rule.description,
        severity: rule.severity,
        matchedStrings: Array.from(matchedStringsSet),
        affectedEvents,
        eventCount: affectedEvents.length
      });
    }
  }

  return matches.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}

export function YaraRuleMatcher({ events }: { events: IocEventRecord[] }) {
  const [activeRules, setActiveRules] = useState<string[]>(SAMPLE_YARA_RULES.map((r) => r.name));
  const [customRule, setCustomRule] = useState("");
  const [ruleError, setRuleError] = useState("");

  const yaraMatches = useMemo(() => {
    const rulesToScan = SAMPLE_YARA_RULES.filter((rule) => activeRules.includes(rule.name));
    return scanEventsWithYara(events, rulesToScan);
  }, [events, activeRules]);

  function toggleRule(ruleName: string) {
    setActiveRules((current) =>
      current.includes(ruleName) ? current.filter((r) => r !== ruleName) : [...current, ruleName]
    );
  }

  function getSeverityColor(severity: "critical" | "high" | "medium" | "low"): string {
    if (severity === "critical") return "border-rose-500/60 bg-rose-500/20 text-rose-200";
    if (severity === "high") return "border-orange-500/60 bg-orange-500/20 text-orange-100";
    if (severity === "medium") return "border-amber-400/60 bg-amber-500/20 text-amber-100";
    return "border-blue-400/60 bg-blue-500/20 text-blue-100";
  }

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <p className="text-xs uppercase tracking-[0.22em] text-amber-300">YARA Threat Scanning</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-100">Malware Detection Engine</h2>
        <p className="mt-2 text-sm text-slate-300">
          Scan IOC data against YARA rules to detect malware signatures and threat patterns.
        </p>
      </header>

      {/* Rule Management */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Active Rules</h3>
        <div className="space-y-2">
          {SAMPLE_YARA_RULES.map((rule) => (
            <label key={rule.name} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={activeRules.includes(rule.name)}
                onChange={() => toggleRule(rule.name)}
                className="h-4 w-4"
              />
              <div className="flex-1">
                <p className="text-sm font-medium text-slate-100">{rule.name}</p>
                <p className="text-xs text-slate-400">{rule.description}</p>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${getSeverityColor(rule.severity)}`}>
                {rule.severity.toUpperCase()}
              </span>
            </label>
          ))}
        </div>
      </section>

      {/* Scan Results */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">
          Threat Matches ({yaraMatches.length})
        </h3>

        {yaraMatches.length === 0 ? (
          <div className="rounded-lg border border-emerald-400/35 bg-emerald-500/10 px-4 py-6 text-center">
            <p className="text-sm font-medium text-emerald-100">✓ Clean</p>
            <p className="text-xs text-emerald-200 mt-1">No YARA matches detected</p>
          </div>
        ) : (
          <div className="space-y-3">
            {yaraMatches.map((match) => (
              <div
                key={match.ruleName}
                className={`rounded-lg border p-4 ${getSeverityColor(match.severity)}`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <p className="font-semibold text-sm">{match.ruleName}</p>
                    <p className="text-xs text-slate-300 mt-1">{match.description}</p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-semibold border whitespace-nowrap ${getSeverityColor(match.severity)}`}>
                    {match.severity.toUpperCase()}
                  </span>
                </div>

                <div className="mt-2 text-xs">
                  <p className="text-slate-200 font-semibold mb-1">Matched Strings ({match.matchedStrings.length}):</p>
                  <div className="flex flex-wrap gap-1 mb-2">
                    {match.matchedStrings.map((str) => (
                      <code key={str} className="bg-slate-950/60 px-2 py-1 rounded text-slate-100">
                        {str}
                      </code>
                    ))}
                  </div>

                  <p className="text-slate-300 font-semibold">Affected Events: {match.eventCount}</p>
                  {match.affectedEvents.length > 0 && (
                    <div className="mt-2 space-y-1 max-h-24 overflow-y-auto">
                      {match.affectedEvents.slice(0, 3).map((event, idx) => (
                        <p key={idx} className="text-slate-200 truncate">
                          • {JSON.stringify(event).substring(0, 100)}...
                        </p>
                      ))}
                      {match.affectedEvents.length > 3 && (
                        <p className="text-slate-400">+{match.affectedEvents.length - 3} more</p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Rule Statistics */}
      <div className="grid gap-3 md:grid-cols-3">
        <article className="rounded-xl border border-rose-400/35 bg-rose-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-rose-100">Critical Matches</p>
          <p className="mt-1 text-2xl font-semibold text-rose-100">
            {yaraMatches.filter((m) => m.severity === "critical").length}
          </p>
        </article>
        <article className="rounded-xl border border-orange-400/35 bg-orange-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-orange-100">High Matches</p>
          <p className="mt-1 text-2xl font-semibold text-orange-100">
            {yaraMatches.filter((m) => m.severity === "high").length}
          </p>
        </article>
        <article className="rounded-xl border border-emerald-400/35 bg-emerald-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-emerald-100">Rules Enabled</p>
          <p className="mt-1 text-2xl font-semibold text-emerald-100">{activeRules.length}</p>
        </article>
      </div>
    </section>
  );
}

export default YaraRuleMatcher;
