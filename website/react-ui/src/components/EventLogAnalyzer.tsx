import { type ChangeEvent, useEffect, useMemo, useState } from "react";
import { fetchEventLogHistory, submitEventLogAnalysis } from "../api/client";

type Severity = "CRITICAL" | "ERROR" | "WARN" | "INFO";
type EventType = "AUTH" | "NETWORK" | "DNS" | "PROCESS" | "SYSTEM" | "APPLICATION" | "UNKNOWN";
type TimelineGranularity = "1m" | "5m" | "1h";

type ParsedEvent = {
  id: string;
  lineNumber: number;
  timestamp: string;
  severity: Severity;
  eventType: EventType;
  source: string;
  message: string;
};

const SAMPLE_LOGS = `[2026-04-23 08:45:12] ERROR auth-service Failed login for user 'guest' from 10.20.1.8
2026-04-23T08:45:32Z WARN dns-proxy Suspicious domain detected: hxxp-updates-check.net
2026-04-23T08:46:01Z INFO systemd Service restart completed for scanner-worker
2026-04-23 08:46:17 CRITICAL edr-agent Possible ransomware behavior detected on process encryptor.exe
2026-04-23 08:47:03 ERROR firewall Outbound connection blocked to 203.0.113.50:4444`;

const TIMESTAMP_PATTERNS: RegExp[] = [
  /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\b/,
  /\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\]/,
  /\b\d{2}-[A-Za-z]{3}-\d{4}\s\d{2}:\d{2}:\d{2}\b/
];

function parseTimestamp(line: string): string {
  for (const pattern of TIMESTAMP_PATTERNS) {
    const matched = line.match(pattern)?.[0];
    if (matched) {
      return matched.replace(/^\[/, "").replace(/\]$/, "");
    }
  }

  return "N/A";
}

function parseSeverity(line: string): Severity {
  const normalized = line.toUpperCase();

  if (/\bCRITICAL\b|\bFATAL\b|\bEMERGENCY\b/.test(normalized)) {
    return "CRITICAL";
  }

  if (/\bERROR\b|\bFAIL\b|\bEXCEPTION\b|\bDENIED\b/.test(normalized)) {
    return "ERROR";
  }

  if (/\bWARN\b|\bWARNING\b|\bTIMEOUT\b|\bRETRY\b/.test(normalized)) {
    return "WARN";
  }

  return "INFO";
}

function parseEventType(line: string): EventType {
  const normalized = line.toLowerCase();

  if (/auth|login|credential|mfa|token/.test(normalized)) return "AUTH";
  if (/dns|domain|sinkhole|resolver/.test(normalized)) return "DNS";
  if (/ip|port|firewall|network|connection|socket/.test(normalized)) return "NETWORK";
  if (/process|pid|exec|command/.test(normalized)) return "PROCESS";
  if (/kernel|systemd|service|host|os/.test(normalized)) return "SYSTEM";
  if (/app|application|api|worker/.test(normalized)) return "APPLICATION";

  return "UNKNOWN";
}

function parseSource(line: string): string {
  const bracketSource = line.match(/\[([a-zA-Z0-9_.\-/]+)\]/g);
  if (bracketSource && bracketSource.length > 1) {
    const source = bracketSource[1]?.replace(/[\[\]]/g, "");
    if (source) return source;
  }

  const sourceAssignment = line.match(/\bsource\s*=\s*([\w.\-/]+)/i)?.[1];
  if (sourceAssignment) {
    return sourceAssignment;
  }

  const serviceHint = line.match(/\b([a-z0-9_.-]+(?:service|agent|worker|proxy|firewall|systemd))\b/i)?.[1];
  if (serviceHint) {
    return serviceHint;
  }

  return "unclassified";
}

function sanitizeMessage(line: string): string {
  return line.replace(/\s+/g, " ").trim();
}

function parseRawLogs(rawLogs: string): ParsedEvent[] {
  const lines = rawLogs.split(/\r?\n/);
  const parsed: ParsedEvent[] = [];

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    parsed.push({
      id: `event-${index + 1}`,
      lineNumber: index + 1,
      timestamp: parseTimestamp(trimmed),
      severity: parseSeverity(trimmed),
      eventType: parseEventType(trimmed),
      source: parseSource(trimmed),
      message: sanitizeMessage(trimmed)
    });
  });

  return parsed;
}

function parseTimestampToEpoch(timestamp: string): number | null {
  if (timestamp === "N/A") {
    return null;
  }

  const parsed = Date.parse(timestamp);
  if (Number.isNaN(parsed)) {
    return null;
  }

  return parsed;
}

function formatTimelineLabel(timestamp: string): string {
  const epoch = parseTimestampToEpoch(timestamp);
  if (epoch === null) {
    return "No Time";
  }

  return new Date(epoch).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function getBucketEpoch(epoch: number, granularity: TimelineGranularity): number {
  const date = new Date(epoch);

  if (granularity === "1h") {
    date.setMinutes(0, 0, 0);
    return date.getTime();
  }

  if (granularity === "5m") {
    const bucketMinute = Math.floor(date.getMinutes() / 5) * 5;
    date.setMinutes(bucketMinute, 0, 0);
    return date.getTime();
  }

  date.setSeconds(0, 0);
  return date.getTime();
}

function formatBucketLabel(epoch: number, granularity: TimelineGranularity): string {
  const options: Intl.DateTimeFormatOptions = { hour: "2-digit", minute: "2-digit" };
  if (granularity === "1h") {
    options.month = "short";
    options.day = "numeric";
  }

  return new Date(epoch).toLocaleString([], options);
}

function csvEscape(value: string | number): string {
  const text = String(value);
  if (/[",\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }

  return text;
}

function exportEventsAsCsv(events: ParsedEvent[]) {
  if (events.length === 0) {
    return;
  }

  const headers = ["line", "timestamp", "severity", "event_type", "source", "message"];
  const rows = events.map((event) =>
    [event.lineNumber, event.timestamp, event.severity, event.eventType, event.source, event.message]
      .map((value) => csvEscape(value))
      .join(",")
  );

  const csvContent = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = `soc-event-log-analysis-${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function severityBadgeClass(severity: Severity): string {
  if (severity === "CRITICAL") return "border border-rose-400/60 bg-rose-500/20 text-rose-200";
  if (severity === "ERROR") return "border border-orange-400/60 bg-orange-500/20 text-orange-100";
  if (severity === "WARN") return "border border-amber-300/55 bg-amber-500/20 text-amber-100";
  return "border border-blue-400/55 bg-blue-500/20 text-blue-100";
}

function eventTypeBadgeClass(type: EventType): string {
  if (type === "AUTH") return "border border-violet-400/50 bg-violet-500/20 text-violet-100";
  if (type === "DNS") return "border border-cyan-400/50 bg-cyan-500/20 text-cyan-100";
  if (type === "NETWORK") return "border border-sky-400/50 bg-sky-500/20 text-sky-100";
  if (type === "PROCESS") return "border border-fuchsia-400/50 bg-fuchsia-500/20 text-fuchsia-100";
  if (type === "SYSTEM") return "border border-emerald-400/50 bg-emerald-500/20 text-emerald-100";
  if (type === "APPLICATION") return "border border-indigo-400/50 bg-indigo-500/20 text-indigo-100";
  return "border border-slate-500/60 bg-slate-700/50 text-slate-100";
}

function EventLogAnalyzer() {
  const [rawLogs, setRawLogs] = useState("");
  const [parsedEvents, setParsedEvents] = useState<ParsedEvent[]>([]);
  const [hasParsed, setHasParsed] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [typeFilter, setTypeFilter] = useState<EventType | "ALL">("ALL");
  const [searchText, setSearchText] = useState("");
  const [timelineGranularity, setTimelineGranularity] = useState<TimelineGranularity>("1m");
  const [persistStatus, setPersistStatus] = useState("");
  const [busy, setBusy] = useState(false);

  const filteredEvents = useMemo(() => {
    const normalizedSearch = searchText.trim().toLowerCase();

    return parsedEvents.filter((event) => {
      const matchesSeverity = severityFilter === "ALL" || event.severity === severityFilter;
      const matchesType = typeFilter === "ALL" || event.eventType === typeFilter;
      const matchesSearch =
        !normalizedSearch ||
        event.message.toLowerCase().includes(normalizedSearch) ||
        event.source.toLowerCase().includes(normalizedSearch) ||
        event.timestamp.toLowerCase().includes(normalizedSearch);

      return matchesSeverity && matchesType && matchesSearch;
    });
  }, [parsedEvents, severityFilter, typeFilter, searchText]);

  const counts = useMemo(() => {
    return parsedEvents.reduce(
      (acc, event) => {
        acc[event.severity] += 1;
        return acc;
      },
      { CRITICAL: 0, ERROR: 0, WARN: 0, INFO: 0 }
    );
  }, [parsedEvents]);

  const timelinePoints = useMemo(() => {
    const bucketMap = new Map<
      string,
      {
        label: string;
        total: number;
        critical: number;
        error: number;
        warn: number;
        info: number;
        epoch: number;
      }
    >();

    filteredEvents.forEach((event, index) => {
      const epoch = parseTimestampToEpoch(event.timestamp);
      const bucketEpoch = epoch === null ? null : getBucketEpoch(epoch, timelineGranularity);
      const bucketKey = bucketEpoch === null ? `unknown-${index}` : String(bucketEpoch);
      const existing =
        bucketMap.get(bucketKey) ??
        {
          label: bucketEpoch === null ? formatTimelineLabel(event.timestamp) : formatBucketLabel(bucketEpoch, timelineGranularity),
          total: 0,
          critical: 0,
          error: 0,
          warn: 0,
          info: 0,
          epoch: bucketEpoch ?? Number.MAX_SAFE_INTEGER - index
        };

      existing.total += 1;
      if (event.severity === "CRITICAL") existing.critical += 1;
      else if (event.severity === "ERROR") existing.error += 1;
      else if (event.severity === "WARN") existing.warn += 1;
      else existing.info += 1;

      bucketMap.set(bucketKey, existing);
    });

    return Array.from(bucketMap.values())
      .sort((left, right) => left.epoch - right.epoch)
      .slice(-20);
  }, [filteredEvents, timelineGranularity]);

  const timelineMax = useMemo(() => {
    return Math.max(1, ...timelinePoints.map((point) => point.total));
  }, [timelinePoints]);

  async function handleParse() {
    setBusy(true);
    setPersistStatus("");
    const nextEvents = parseRawLogs(rawLogs);
    setParsedEvents(nextEvents);
    setHasParsed(true);

    try {
      const response = await submitEventLogAnalysis(rawLogs, nextEvents as Array<Record<string, unknown>>);
      setPersistStatus(`Stored analysis #${response.analysis_id} with ${response.event_count} events.`);
    } catch (error) {
      setPersistStatus(`Storage failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  function handleClear() {
    setRawLogs("");
    setParsedEvents([]);
    setHasParsed(false);
    setSeverityFilter("ALL");
    setTypeFilter("ALL");
    setSearchText("");
  }

  async function handleLogFileUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;

    const content = await file.text();
    setRawLogs(content);
    event.target.value = "";
  }

  async function loadLatestFromHistory() {
    setBusy(true);
    setPersistStatus("");

    try {
      const history = await fetchEventLogHistory();
      const latest = history.items?.[0] as Record<string, unknown> | undefined;

      if (!latest) {
        setPersistStatus("No saved analyses found in backend history.");
        return;
      }

      const latestRawLogs = String(latest.raw_log_text ?? "");
      const latestParsed = Array.isArray(latest.parsed_events)
        ? (latest.parsed_events.filter((item): item is ParsedEvent => typeof item === "object" && item !== null) as ParsedEvent[])
        : [];

      setRawLogs(latestRawLogs);
      setParsedEvents(latestParsed);
      setHasParsed(true);
      setPersistStatus(`Loaded analysis #${String(latest.id ?? "N/A")} from history.`);
    } catch (error) {
      setPersistStatus(`History load failed: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void loadLatestFromHistory();
  }, []);

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <p className="text-xs uppercase tracking-[0.22em] text-orange-300">New Module</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-100">Event Log Analyzer</h2>
        <p className="mt-2 text-sm text-slate-300">
          Parse raw system and error logs into a normalized, color-coded analyst table for rapid triage.
        </p>
      </header>

      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <label htmlFor="soc-log-input" className="mb-2 block text-sm font-medium text-slate-200">
          Raw Logs Input
        </label>
        <textarea
          id="soc-log-input"
          value={rawLogs}
          onChange={(event) => setRawLogs(event.target.value)}
          className="min-h-56 w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
          placeholder="Paste logs here, or load a .log/.txt file below..."
        />

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleParse}
            disabled={busy}
            className="rounded-lg border border-blue-400/45 bg-blue-500/20 px-4 py-2 text-sm font-semibold text-blue-100 transition hover:bg-blue-500/30"
          >
            {busy ? "Processing..." : "Parse Logs"}
          </button>
          <button
            type="button"
            onClick={() => setRawLogs(SAMPLE_LOGS)}
            className="rounded-lg border border-orange-300/45 bg-orange-500/20 px-4 py-2 text-sm font-semibold text-orange-100 transition hover:bg-orange-500/30"
          >
            Load Sample Logs
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="rounded-lg border border-slate-500/50 bg-slate-700/45 px-4 py-2 text-sm font-semibold text-slate-100 transition hover:bg-slate-700/70"
          >
            Clear
          </button>
          <button
            type="button"
            onClick={() => exportEventsAsCsv(filteredEvents)}
            disabled={filteredEvents.length === 0}
            className="rounded-lg border border-emerald-400/45 bg-emerald-500/15 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/25 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Export CSV (Filtered)
          </button>
          <button
            type="button"
            onClick={() => void loadLatestFromHistory()}
            disabled={busy}
            className="rounded-lg border border-cyan-400/45 bg-cyan-500/15 px-4 py-2 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Load Latest History
          </button>
          <label className="rounded-lg border border-slate-600/55 bg-slate-800/50 px-4 py-2 text-sm font-medium text-slate-200">
            Upload .log/.txt
            <input type="file" accept=".log,.txt,text/plain" onChange={handleLogFileUpload} className="hidden" />
          </label>
        </div>
        {persistStatus ? <p className="mt-3 text-xs text-slate-400">{persistStatus}</p> : null}
      </section>

      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Event Timeline Chart</h3>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Last {timelinePoints.length} time buckets</span>
            <select
              value={timelineGranularity}
              onChange={(event) => setTimelineGranularity(event.target.value as TimelineGranularity)}
              className="rounded-md border border-slate-700 bg-slate-950/80 px-2 py-1 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
              aria-label="Timeline bucket granularity"
            >
              <option value="1m">1 minute</option>
              <option value="5m">5 minutes</option>
              <option value="1h">1 hour</option>
            </select>
          </div>
        </div>

        {timelinePoints.length === 0 ? (
          <p className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-4 text-sm text-slate-400">
            Parse logs to render a timeline.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <div className="flex min-w-max items-end gap-2 rounded-xl border border-slate-800 bg-slate-950/75 p-3">
              {timelinePoints.map((point, index) => {
                const height = Math.max(14, Math.round((point.total / timelineMax) * 120));
                const criticalHeight = point.total ? Math.round((point.critical / point.total) * height) : 0;
                const errorHeight = point.total ? Math.round((point.error / point.total) * height) : 0;
                const warnHeight = point.total ? Math.round((point.warn / point.total) * height) : 0;
                const infoHeight = Math.max(0, height - criticalHeight - errorHeight - warnHeight);

                return (
                  <article key={`${point.label}-${index}`} className="w-16 text-center">
                    <div className="relative mx-auto flex h-32 w-9 flex-col justify-end overflow-hidden rounded-md border border-slate-700/70 bg-slate-900/80">
                      {infoHeight > 0 ? <span style={{ height: `${infoHeight}px` }} className="block w-full bg-blue-500/80" /> : null}
                      {warnHeight > 0 ? <span style={{ height: `${warnHeight}px` }} className="block w-full bg-amber-500/85" /> : null}
                      {errorHeight > 0 ? <span style={{ height: `${errorHeight}px` }} className="block w-full bg-orange-500/85" /> : null}
                      {criticalHeight > 0 ? <span style={{ height: `${criticalHeight}px` }} className="block w-full bg-rose-500/90" /> : null}
                    </div>
                    <p className="mt-2 text-[11px] text-slate-400">{point.label}</p>
                    <p className="text-[11px] font-semibold text-slate-200">{point.total}</p>
                  </article>
                );
              })}
            </div>
          </div>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-300">
          <span className="inline-flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-rose-500" /> Critical
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-orange-500" /> Error
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-amber-500" /> Warn
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-blue-500" /> Info
          </span>
        </div>
      </section>

      <section className="grid gap-3 md:grid-cols-4">
        <article className="rounded-xl border border-rose-400/35 bg-rose-500/10 p-3">
          <p className="text-xs uppercase tracking-wider text-rose-200">Critical</p>
          <p className="mt-1 text-2xl font-semibold text-rose-100">{counts.CRITICAL}</p>
        </article>
        <article className="rounded-xl border border-orange-400/35 bg-orange-500/10 p-3">
          <p className="text-xs uppercase tracking-wider text-orange-100">Error</p>
          <p className="mt-1 text-2xl font-semibold text-orange-100">{counts.ERROR}</p>
        </article>
        <article className="rounded-xl border border-amber-300/35 bg-amber-500/10 p-3">
          <p className="text-xs uppercase tracking-wider text-amber-100">Warn</p>
          <p className="mt-1 text-2xl font-semibold text-amber-100">{counts.WARN}</p>
        </article>
        <article className="rounded-xl border border-blue-400/35 bg-blue-500/10 p-3">
          <p className="text-xs uppercase tracking-wider text-blue-100">Info</p>
          <p className="mt-1 text-2xl font-semibold text-blue-100">{counts.INFO}</p>
        </article>
      </section>

      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <input
            type="search"
            value={searchText}
            onChange={(event) => setSearchText(event.target.value)}
            placeholder="Search message, source, timestamp"
            className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
          />
          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value as Severity | "ALL")}
            className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="ERROR">Error</option>
            <option value="WARN">Warn</option>
            <option value="INFO">Info</option>
          </select>
          <select
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value as EventType | "ALL")}
            className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
          >
            <option value="ALL">All Event Types</option>
            <option value="AUTH">Auth</option>
            <option value="DNS">DNS</option>
            <option value="NETWORK">Network</option>
            <option value="PROCESS">Process</option>
            <option value="SYSTEM">System</option>
            <option value="APPLICATION">Application</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>

        <p className="mb-3 text-sm text-slate-400">
          Showing {filteredEvents.length} of {parsedEvents.length} parsed events.
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-950/80 text-slate-300">
              <tr>
                <th className="px-3 py-3 text-left font-semibold">Line</th>
                <th className="px-3 py-3 text-left font-semibold">Timestamp</th>
                <th className="px-3 py-3 text-left font-semibold">Severity</th>
                <th className="px-3 py-3 text-left font-semibold">Type</th>
                <th className="px-3 py-3 text-left font-semibold">Source</th>
                <th className="px-3 py-3 text-left font-semibold">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/45">
              {!hasParsed ? (
                <tr>
                  <td colSpan={6} className="px-3 py-7 text-center text-slate-400">
                    Paste or upload logs, then click Parse Logs.
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-7 text-center text-slate-400">
                    No events match the current filters.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => (
                  <tr key={event.id} className="align-top hover:bg-slate-800/35">
                    <td className="px-3 py-3 text-slate-400">{event.lineNumber}</td>
                    <td className="px-3 py-3 whitespace-nowrap text-slate-200">{event.timestamp}</td>
                    <td className="px-3 py-3">
                      <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${severityBadgeClass(event.severity)}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${eventTypeBadgeClass(event.eventType)}`}>
                        {event.eventType}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-slate-200">{event.source}</td>
                    <td className="px-3 py-3 text-slate-100 break-words">{event.message}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}

export default EventLogAnalyzer;