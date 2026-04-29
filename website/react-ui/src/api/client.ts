export type ThreatIndicator = {
  type: string;
  value: string;
  severity: string;
  label: string;
};

export type IocEventRecord = Record<string, unknown>;

export type ThreatFeedResponse = {
  fetched_at_utc: string;
  source: string;
  indicators: ThreatIndicator[];
};

export type LatestIocResponse = {
  id: number;
  uploaded_at_utc: string;
  source_name: string;
  process_tree: Array<Record<string, unknown>>;
  flagged_network_connections: Array<Record<string, unknown>>;
  report: Record<string, unknown>;
  process_events: IocEventRecord[];
  network_events: IocEventRecord[];
  process_count: number;
  flagged_connection_count: number;
};

export type UploadIocResponse = {
  status: string;
  report_id: number;
  uploaded_at_utc: string;
  source_name: string;
  process_tree: Array<Record<string, unknown>>;
  flagged_network_connections: Array<Record<string, unknown>>;
};

export type HistoryResponse = {
  fetched_at_utc: string;
  count: number;
  items: Array<Record<string, unknown>>;
};

export type ScanFinding = {
  id: string;
  severity: string;
  title: string;
  recommendation: string;
};

export type ScanResponse = {
  simulation: boolean;
  scan_id: string;
  timestamp_utc: string;
  target: string;
  target_type: string;
  profile: string;
  ports: number[];
  findings: ScanFinding[];
  finding_count: number;
};

export type LoginResponse = {
  timestamp_utc: string;
  status: string;
  message?: string;
  reason?: string;
  session_fingerprint?: string;
};

export type EventLogRecord = {
  id: number;
  created_at_utc: string;
  source: string;
  raw_log_text: string;
  parsed_events: Array<Record<string, unknown>>;
  event_count: number;
  severity_counts: Record<string, number>;
};

export type EventLogAnalysisResponse = {
  status: string;
  analysis_id: number;
  created_at_utc: string;
  event_count: number;
};

export type DnsQueryEventRecord = {
  id: number;
  created_at_utc: string;
  domain: string;
  source_ip: string;
  outcome: string;
  resolved_ip: string;
  sinkhole_ip: string;
  metadata: Record<string, unknown>;
};

export type DnsSimulatorStoreResponse = {
  status: string;
  stored_count: number;
  created_at_utc: string;
};

export type YaraScanResponse = {
  status: string;
  scan_id: string;
  matches: Array<{
    rule_name: string;
    severity: string;
    matched_strings: string[];
    affected_events: number;
  }>;
  total_matches: number;
};

export type AdminStatsResponse = {
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

export type ThreatFeedSyncResponse = {
  status: string;
  feeds_synced: number;
  new_indicators: number;
  created_at_utc: string;
};

export type DetectionRuleResponse = {
  status: string;
  rule_id: string;
  created_at_utc: string;
  message?: string;
};

export type DetectionRuleListResponse = {
  rules: Array<{
    id: string;
    name: string;
    description: string;
    severity: string;
    enabled: boolean;
    hit_count: number;
  }>;
  total_count: number;
};

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {})
    },
    ...init
  });

  if (!response.ok) {
    let detail = "Request failed";
    try {
      const body = (await response.json()) as { error?: string };
      detail = body.error || detail;
    } catch {
      detail = `${detail} (${response.status})`;
    }
    throw new Error(detail);
  }

  return (await response.json()) as T;
}

export function fetchThreatFeed() {
  return requestJson<ThreatFeedResponse>("/api/threat-feed");
}

export function fetchLatestIocReport() {
  return requestJson<LatestIocResponse>("/api/reports/latest");
}

export async function uploadIocReport(file: File) {
  const formData = new FormData();
  formData.append("report", file);

  const response = await fetch("/api/ioc-reports/import", {
    method: "POST",
    body: formData
  });

  if (!response.ok) {
    let detail = "IOC upload failed";
    try {
      const body = (await response.json()) as { error?: string };
      detail = body.error || detail;
    } catch {
      detail = `${detail} (${response.status})`;
    }
    throw new Error(detail);
  }

  return (await response.json()) as UploadIocResponse;
}

export function fetchScanHistory() {
  return requestJson<HistoryResponse>("/api/history/scans");
}

export function fetchThreatFeedHistory() {
  return requestJson<HistoryResponse>("/api/history/threat-feed");
}

export function submitScan(target: string, profile: string, ports: number[]) {
  return requestJson<ScanResponse>("/api/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ target, profile, ports })
  });
}

export function submitLogin(username: string, password: string) {
  return requestJson<LoginResponse>("/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ username, password })
  });
}

export function submitEventLogAnalysis(rawLogs: string, parsedEvents: Array<Record<string, unknown>>, source = "ui-event-log-analyzer") {
  return requestJson<EventLogAnalysisResponse>("/api/event-logs/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ raw_logs: rawLogs, parsed_events: parsedEvents, source })
  });
}

export function fetchEventLogHistory() {
  return requestJson<HistoryResponse>("/api/history/event-logs");
}

export function submitDnsSimulatorEvents(
  events: Array<Record<string, unknown>>,
  sinkholeIp: string,
  source = "ui-private-dns-simulator"
) {
  return requestJson<DnsSimulatorStoreResponse>("/api/dns-simulator/events", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ events, sinkhole_ip: sinkholeIp, source })
  });
}

export function fetchDnsSimulatorHistory() {
  return requestJson<HistoryResponse>("/api/history/dns-simulator");
}

// YARA Scanning
export function submitYaraScan(events: Array<Record<string, unknown>>, source = "ui-yara-scanner") {
  return requestJson<YaraScanResponse>("/api/yara/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ events, source })
  });
}

// Admin Stats
export function fetchAdminStats() {
  return requestJson<AdminStatsResponse>("/api/admin/stats");
}

// Threat Feed Syncing
export function syncThreatFeeds(feedSources?: string[]) {
  return requestJson<ThreatFeedSyncResponse>("/api/threat-feeds/sync", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ feed_sources: feedSources || [] })
  });
}

export function fetchThreatIndicators(severity?: string, limit?: number) {
  const params = new URLSearchParams();
  if (severity) params.append("severity", severity);
  if (limit) params.append("limit", String(limit));
  return requestJson<HistoryResponse>(`/api/threat-indicators?${params.toString()}`);
}

// Detection Rules
export function createDetectionRule(rule: Record<string, unknown>) {
  return requestJson<DetectionRuleResponse>("/api/detection-rules", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(rule)
  });
}

export function fetchDetectionRules() {
  return requestJson<DetectionRuleListResponse>("/api/detection-rules");
}

export function updateDetectionRule(ruleId: string, enabled: boolean) {
  return requestJson<DetectionRuleResponse>(`/api/detection-rules/${ruleId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ enabled })
  });
}

export function deleteDetectionRule(ruleId: string) {
  return requestJson<DetectionRuleResponse>(`/api/detection-rules/${ruleId}`, {
    method: "DELETE"
  });
}