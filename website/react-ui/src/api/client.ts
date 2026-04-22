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