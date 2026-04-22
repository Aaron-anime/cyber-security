export type ThreatIndicator = {
  type: string;
  value: string;
  severity: string;
  label: string;
};

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

  const response = await fetch("/api/upload-report", {
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