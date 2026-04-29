import { useState, useMemo, useEffect } from "react";
import { createDetectionRule, fetchDetectionRules, updateDetectionRule, deleteDetectionRule } from "../api/client";
import EnvironmentSelector from "./EnvironmentSelector";
import { ENVIRONMENT_TEMPLATES } from "../data/detectionRuleTemplates";

type DetectionRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: "critical" | "high" | "medium" | "low";
  conditions: RuleCondition[];
  actions: string[];
  created_at: string;
  hit_count: number;
};

type RuleCondition = {
  field: string;
  operator: "equals" | "contains" | "greater_than" | "less_than" | "regex";
  value: string;
};

const DEFAULT_RULES: DetectionRule[] = [
  {
    id: "rule-001",
    name: "Excessive Failed Login Attempts",
    description: "Detects brute force attempts with 10+ failures in 5 minutes",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "event_type", operator: "equals", value: "AUTH" },
      { field: "message", operator: "contains", value: "failed" }
    ],
    actions: ["alert", "log", "block_ip"],
    created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
    hit_count: 47
  },
  {
    id: "rule-002",
    name: "Privilege Escalation Attempt",
    description: "Detects attempts to escalate user privileges",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "message", operator: "regex", value: "sudo|admin|elevated|root" },
      { field: "source", operator: "contains", value: "kernel" }
    ],
    actions: ["alert", "quarantine", "notify_soc"],
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
    hit_count: 12
  },
  {
    id: "rule-003",
    name: "DNS Exfiltration Detected",
    description: "Detects anomalous DNS query patterns suggesting data exfiltration",
    enabled: true,
    severity: "high",
    conditions: [
      { field: "event_type", operator: "equals", value: "DNS" },
      { field: "message", operator: "regex", value: "suspicious|malicious|sinkhole" }
    ],
    actions: ["alert", "block_domain", "log"],
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    hit_count: 23
  },
  {
    id: "rule-004",
    name: "Ransomware Behavior Detected",
    description: "Detects indicators of ransomware activity",
    enabled: true,
    severity: "critical",
    conditions: [
      { field: "message", operator: "regex", value: "vssadmin|wbadmin|bcdedit|encrypt" }
    ],
    actions: ["alert", "isolate_host", "notify_soc"],
    created_at: new Date(Date.now() - 86400000).toISOString(),
    hit_count: 3
  },
  {
    id: "rule-005",
    name: "Unusual Outbound Network Activity",
    description: "Alerts on non-standard ports and unusual IP destinations",
    enabled: false,
    severity: "medium",
    conditions: [
      { field: "event_type", operator: "equals", value: "NETWORK" },
      { field: "message", operator: "contains", value: "outbound" }
    ],
    actions: ["log", "investigate"],
    created_at: new Date(Date.now() - 86400000 * 15).toISOString(),
    hit_count: 89
  }
];

function getSeverityColor(severity: "critical" | "high" | "medium" | "low"): string {
  if (severity === "critical") return "border-rose-500/60 bg-rose-500/20 text-rose-200";
  if (severity === "high") return "border-orange-500/60 bg-orange-500/20 text-orange-100";
  if (severity === "medium") return "border-amber-400/60 bg-amber-500/20 text-amber-100";
  return "border-blue-400/60 bg-blue-500/20 text-blue-100";
}

function DetectionRulesEngine() {
  const [rules, setRules] = useState<DetectionRule[]>(DEFAULT_RULES);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleDescription, setNewRuleDescription] = useState("");
  const [showNewRuleForm, setShowNewRuleForm] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    const loadRules = async () => {
      try {
        const response = await fetchDetectionRules();
        if (response.rules && Array.isArray(response.rules)) {
          // Convert API response to DetectionRule format
          const apiRules = response.rules.map((r) => ({
            id: r.id,
            name: r.name,
            description: r.description,
            enabled: r.enabled,
            severity: (r.severity as DetectionRule["severity"]) || "medium",
            conditions: [],
            actions: [],
            created_at: new Date().toISOString(),
            hit_count: r.hit_count || 0
          }));
          setRules(apiRules);
        }
      } catch (error) {
        console.error("Failed to load detection rules:", error);
        // Keep default rules if API fails
      }
    };
    void loadRules();
  }, []);

  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      const matchesSeverity = filterSeverity === "ALL" || rule.severity === filterSeverity;
      const matchesStatus =
        filterStatus === "ALL" || (filterStatus === "enabled" ? rule.enabled : !rule.enabled);
      return matchesSeverity && matchesStatus;
    });
  }, [rules, filterSeverity, filterStatus]);

  const ruleStats = useMemo(() => {
    return {
      total: rules.length,
      enabled: rules.filter((r) => r.enabled).length,
      critical: rules.filter((r) => r.severity === "critical").length,
      high: rules.filter((r) => r.severity === "high").length,
      totalHits: rules.reduce((sum, r) => sum + r.hit_count, 0)
    };
  }, [rules]);

  function toggleRule(ruleId: string) {
    const rule = rules.find((r) => r.id === ruleId);
    if (!rule) return;

    // Update local state immediately for better UX
    setRules((current) =>
      current.map((r) => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r))
    );

    // Update on backend
    updateDetectionRule(ruleId, !rule.enabled).catch(() => {
      // Revert on error
      setRules((current) =>
        current.map((r) => (r.id === ruleId ? { ...r, enabled: rule.enabled } : r))
      );
    });
  }

  function addNewRule() {
    if (!newRuleName.trim()) return;

    setIsSaving(true);

    const newRule: DetectionRule = {
      id: `rule-${Date.now()}`,
      name: newRuleName,
      description: newRuleDescription,
      enabled: true,
      severity: "medium",
      conditions: [{ field: "message", operator: "contains", value: "" }],
      actions: ["alert", "log"],
      created_at: new Date().toISOString(),
      hit_count: 0
    };

    createDetectionRule(newRule)
      .then(() => {
        setRules((current) => [newRule, ...current]);
        setNewRuleName("");
        setNewRuleDescription("");
        setShowNewRuleForm(false);
      })
      .catch((error) => {
        console.error("Failed to create rule:", error);
      })
      .finally(() => {
        setIsSaving(false);
      });
  }

  function deleteRule(ruleId: string) {
    deleteDetectionRule(ruleId)
      .then(() => {
        setRules((current) => current.filter((rule) => rule.id !== ruleId));
      })
      .catch((error) => {
        console.error("Failed to delete rule:", error);
      });
  }

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-emerald-300">Rules Engine</p>
            <h2 className="mt-2 text-2xl font-semibold text-slate-100">Detection Rules Management</h2>
            <p className="mt-2 text-sm text-slate-300">
              Create and manage custom detection rules to automatically alert on security threats.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowNewRuleForm(!showNewRuleForm)}
            className="rounded-lg border border-emerald-400/45 bg-emerald-500/15 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/25"
          >
            + New Rule
          </button>
        </div>
      </header>

      {/* New Rule Form */}
      {showNewRuleForm && (
        <section className="rounded-2xl border border-emerald-400/35 bg-emerald-500/10 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.45)] backdrop-blur-xl">
          <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-emerald-300">Create Detection Rule</h3>
          <div className="space-y-3">
            <input
              type="text"
              value={newRuleName}
              onChange={(e) => setNewRuleName(e.target.value)}
              placeholder="Rule name (e.g., Detect SSH Brute Force)"
              className="w-full rounded-lg border border-emerald-700/50 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60"
            />
            <textarea
              value={newRuleDescription}
              onChange={(e) => setNewRuleDescription(e.target.value)}
              placeholder="Rule description (what it detects and why)"
              className="w-full rounded-lg border border-emerald-700/50 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/60 min-h-20"
            />
            <div className="flex gap-2">
              <button
                type="button"
                onClick={addNewRule}
                className="rounded-lg border border-emerald-400/45 bg-emerald-500/20 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/30"
              >
                Create Rule
              </button>
              <button
                type="button"
                onClick={() => setShowNewRuleForm(false)}
                className="rounded-lg border border-slate-500/50 bg-slate-700/45 px-4 py-2 text-sm font-semibold text-slate-100"
              >
                Cancel
              </button>
            </div>
          </div>
        </section>
      )}

      {/* Rule Statistics */}
      <div className="grid gap-3 md:grid-cols-5">
        <article className="rounded-xl border border-cyan-400/35 bg-cyan-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-cyan-100">Total Rules</p>
          <p className="mt-2 text-2xl font-bold text-cyan-100">{ruleStats.total}</p>
        </article>
        <article className="rounded-xl border border-emerald-400/35 bg-emerald-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-emerald-100">Enabled</p>
          <p className="mt-2 text-2xl font-bold text-emerald-100">{ruleStats.enabled}</p>
        </article>
        <article className="rounded-xl border border-rose-400/35 bg-rose-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-rose-100">Critical</p>
          <p className="mt-2 text-2xl font-bold text-rose-100">{ruleStats.critical}</p>
        </article>
        <article className="rounded-xl border border-orange-400/35 bg-orange-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-orange-100">High</p>
          <p className="mt-2 text-2xl font-bold text-orange-100">{ruleStats.high}</p>
        </article>
        <article className="rounded-xl border border-blue-400/35 bg-blue-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-blue-100">Total Hits</p>
          <p className="mt-2 text-2xl font-bold text-blue-100">{ruleStats.totalHits}</p>
        </article>
      </div>

      {/* Environment Selector */}
      <EnvironmentSelector
        onApplyTemplate={(templateId) => {
          const template = ENVIRONMENT_TEMPLATES.find((t) => t.id === templateId);
          if (template) {
            setRules(template.rules);
          }
        }}
        isLoading={isSaving}
      />

      {/* Rule Filters */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <div className="flex gap-3">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
          >
            <option value="ALL">All Statuses</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
      </section>

      {/* Rules List */}
      <section className="space-y-3">
        {filteredRules.map((rule) => (
          <div
            key={rule.id}
            className={`rounded-2xl border p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl ${getSeverityColor(rule.severity)}`}
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={() => toggleRule(rule.id)}
                    className="h-4 w-4 cursor-pointer"
                  />
                  <h4 className="text-sm font-semibold text-slate-100">{rule.name}</h4>
                </div>
                <p className="mt-1 text-sm text-slate-300">{rule.description}</p>
              </div>
              <div className="ml-4 text-right">
                <p className="text-xs text-slate-400">Hits: <span className="font-semibold text-slate-100">{rule.hit_count}</span></p>
                <p className="text-xs text-slate-400 mt-1">
                  Created: {new Date(rule.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>

            <div className="mt-3 text-xs space-y-2">
              <div>
                <p className="text-slate-200 font-semibold mb-1">Conditions:</p>
                <div className="flex flex-wrap gap-2">
                  {rule.conditions.map((cond, idx) => (
                    <code key={idx} className="bg-slate-950/60 px-2 py-1 rounded text-slate-100">
                      {cond.field} {cond.operator} {cond.value}
                    </code>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-slate-200 font-semibold mb-1">Actions:</p>
                <div className="flex flex-wrap gap-2">
                  {rule.actions.map((action, idx) => (
                    <span
                      key={idx}
                      className="inline-flex rounded-full border border-slate-600/50 bg-slate-800/50 px-2 py-1 text-slate-200"
                    >
                      {action}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => deleteRule(rule.id)}
              className="mt-3 rounded-lg border border-slate-600/50 bg-slate-800/30 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-slate-800/60"
            >
              Delete Rule
            </button>
          </div>
        ))}
      </section>
    </section>
  );
}

export default DetectionRulesEngine;
