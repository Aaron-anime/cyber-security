import { type ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { fetchDnsSimulatorHistory, submitDnsSimulatorEvents } from "../api/client";

type QueryOutcome = "SINKHOLED" | "ALLOW";

type DnsQueryEvent = {
  id: string;
  domain: string;
  sourceIp: string;
  timestamp: string;
  outcome: QueryOutcome;
  resolvedIp: string;
};

type DomainStatus = "MALICIOUS" | "SAFE";

type DomainRecord = {
  domain: string;
  status: DomainStatus;
};

const DEFAULT_SINKHOLE_IP = "10.10.10.10";

const BASE_DOMAINS: DomainRecord[] = [
  { domain: "cdn.security-updates.example", status: "SAFE" },
  { domain: "auth-control.internal", status: "SAFE" },
  { domain: "malware-c2-node.bad", status: "MALICIOUS" },
  { domain: "stolen-credentials-drop.ru", status: "MALICIOUS" },
  { domain: "threat-feed.partner.local", status: "SAFE" }
];

const ENDPOINT_POOL = ["10.0.2.21", "10.0.2.34", "10.0.3.44", "10.0.4.51"];

function nowIso() {
  return new Date().toISOString();
}

function buildEvent(domain: string, sinkholeIp: string, maliciousSet: Set<string>): DnsQueryEvent {
  const isMalicious = maliciousSet.has(domain.toLowerCase());
  const resolvedIp = isMalicious
    ? sinkholeIp
    : ENDPOINT_POOL[Math.floor(Math.random() * ENDPOINT_POOL.length)] ?? "10.0.2.21";

  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    domain,
    sourceIp: `192.168.1.${Math.floor(Math.random() * 180) + 20}`,
    timestamp: nowIso(),
    outcome: isMalicious ? "SINKHOLED" : "ALLOW",
    resolvedIp
  };
}

function statusClass(status: DomainStatus): string {
  if (status === "MALICIOUS") return "border border-rose-400/60 bg-rose-500/20 text-rose-200";
  return "border border-emerald-400/60 bg-emerald-500/15 text-emerald-200";
}

function outcomeClass(outcome: QueryOutcome): string {
  if (outcome === "SINKHOLED") return "border border-orange-400/60 bg-orange-500/20 text-orange-100";
  return "border border-blue-400/60 bg-blue-500/20 text-blue-100";
}

function csvEscape(value: string): string {
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }

  return value;
}

function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];

    if (char === '"') {
      if (inQuotes && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      fields.push(current.trim());
      current = "";
      continue;
    }

    current += char;
  }

  fields.push(current.trim());
  return fields;
}

function normalizeHeader(header: string): string {
  return header.trim().toLowerCase().replace(/[^a-z0-9]/g, "");
}

function parseDnsEventsCsv(csvText: string): DnsQueryEvent[] {
  const lines = csvText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length < 2) {
    return [];
  }

  const headers = parseCsvLine(lines[0]).map((header) => normalizeHeader(header));
  const getIndex = (names: string[]) => headers.findIndex((header) => names.includes(header));

  const timestampIndex = getIndex(["timestamp", "time"]);
  const sourceIndex = getIndex(["sourceip", "source"]);
  const domainIndex = getIndex(["domain", "hostname"]);
  const outcomeIndex = getIndex(["outcome", "action", "status"]);
  const resolvedIndex = getIndex(["resolvedip", "resolved", "destinationip"]);

  if ([timestampIndex, sourceIndex, domainIndex, outcomeIndex, resolvedIndex].some((index) => index < 0)) {
    return [];
  }

  return lines.slice(1).flatMap((line, rowOffset) => {
    const cells = parseCsvLine(line);
    const timestamp = cells[timestampIndex] ?? "";
    const sourceIp = cells[sourceIndex] ?? "";
    const domain = cells[domainIndex] ?? "";
    const outcomeRaw = (cells[outcomeIndex] ?? "").toUpperCase();
    const resolvedIp = cells[resolvedIndex] ?? "";

    if (!timestamp || !sourceIp || !domain || !resolvedIp) {
      return [];
    }

    const outcome: QueryOutcome = outcomeRaw.includes("SINK") ? "SINKHOLED" : "ALLOW";

    return [
      {
        id: `imported-${Date.now()}-${rowOffset}`,
        domain,
        sourceIp,
        timestamp,
        outcome,
        resolvedIp
      }
    ];
  });
}

function exportDnsEventsCsv(events: DnsQueryEvent[]) {
  if (events.length === 0) {
    return;
  }

  const headers = ["timestamp", "source_ip", "domain", "outcome", "resolved_ip"];
  const rows = events.map((event) =>
    [event.timestamp, event.sourceIp, event.domain, event.outcome, event.resolvedIp].map((value) => csvEscape(value)).join(",")
  );
  const csvBody = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csvBody], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = `private-dns-events-${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function PrivateDnsSimulator() {
  const [records, setRecords] = useState<DomainRecord[]>(BASE_DOMAINS);
  const [queryEvents, setQueryEvents] = useState<DnsQueryEvent[]>([]);
  const [domainInput, setDomainInput] = useState("malware-c2-node.bad");
  const [sinkholeIp, setSinkholeIp] = useState(DEFAULT_SINKHOLE_IP);
  const [newDomain, setNewDomain] = useState("");
  const [importQueue, setImportQueue] = useState<DnsQueryEvent[]>([]);
  const [isReplaying, setIsReplaying] = useState(false);
  const [csvNotice, setCsvNotice] = useState("");
  const [backendNotice, setBackendNotice] = useState("");
  const replayTimerRef = useRef<number | null>(null);

  const maliciousSet = useMemo(() => {
    return new Set(records.filter((record) => record.status === "MALICIOUS").map((record) => record.domain.toLowerCase()));
  }, [records]);

  const totals = useMemo(() => {
    return queryEvents.reduce(
      (acc, event) => {
        if (event.outcome === "SINKHOLED") {
          acc.sinkholed += 1;
        } else {
          acc.allowed += 1;
        }
        return acc;
      },
      { sinkholed: 0, allowed: 0 }
    );
  }, [queryEvents]);

  useEffect(() => {
    return () => {
      if (replayTimerRef.current !== null) {
        window.clearInterval(replayTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    async function loadHistory() {
      try {
        const history = await fetchDnsSimulatorHistory();
        const mapped = history.items
          .map((item) => {
            const event = item as Record<string, unknown>;
            const timestamp = String(event.created_at_utc ?? event.timestamp ?? "");
            const sourceIp = String(event.source_ip ?? event.sourceIp ?? "");
            const domain = String(event.domain ?? "");
            const outcomeRaw = String(event.outcome ?? "ALLOW").toUpperCase();
            const resolvedIp = String(event.resolved_ip ?? event.resolvedIp ?? "");

            if (!timestamp || !sourceIp || !domain || !resolvedIp) {
              return null;
            }

            return {
              id: `history-${String(event.id ?? "unknown")}`,
              timestamp,
              sourceIp,
              domain,
              outcome: outcomeRaw.includes("SINK") ? "SINKHOLED" : "ALLOW",
              resolvedIp
            } as DnsQueryEvent;
          })
          .filter((event): event is DnsQueryEvent => event !== null)
          .slice(0, 40);

        setQueryEvents(mapped);
        setBackendNotice(mapped.length ? `Loaded ${mapped.length} recent DNS events from backend.` : "No DNS history found yet.");
      } catch (error) {
        setBackendNotice(`History load failed: ${String(error)}`);
      }
    }

    void loadHistory();
  }, []);

  async function persistEvents(events: DnsQueryEvent[]) {
    if (!events.length) {
      return;
    }

    try {
      await submitDnsSimulatorEvents(events as Array<Record<string, unknown>>, sinkholeIp.trim() || DEFAULT_SINKHOLE_IP);
      setBackendNotice(`Stored ${events.length} DNS event${events.length === 1 ? "" : "s"} to backend.`);
    } catch (error) {
      setBackendNotice(`Backend store failed: ${String(error)}`);
    }
  }

  function simulateQuery() {
    const normalizedDomain = domainInput.trim().toLowerCase();
    if (!normalizedDomain) {
      return;
    }

    const event = buildEvent(normalizedDomain, sinkholeIp.trim() || DEFAULT_SINKHOLE_IP, maliciousSet);
    setQueryEvents((current) => [event, ...current].slice(0, 40));
    void persistEvents([event]);
  }

  function addDomain(status: DomainStatus) {
    const normalized = newDomain.trim().toLowerCase();
    if (!normalized) {
      return;
    }

    setRecords((current) => {
      const existing = current.find((entry) => entry.domain.toLowerCase() === normalized);
      if (existing) {
        return current.map((entry) => (entry.domain.toLowerCase() === normalized ? { ...entry, status } : entry));
      }

      return [...current, { domain: normalized, status }];
    });
    setNewDomain("");
  }

  async function handleCsvUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const csvText = await file.text();
    const events = parseDnsEventsCsv(csvText);

    if (events.length === 0) {
      setCsvNotice("CSV import failed or no valid rows found.");
      event.target.value = "";
      return;
    }

    setImportQueue(events);
    setCsvNotice(`Imported ${events.length} DNS events. Click replay to stream them.`);
    event.target.value = "";
  }

  function stopReplay() {
    if (replayTimerRef.current !== null) {
      window.clearInterval(replayTimerRef.current);
      replayTimerRef.current = null;
    }
    setIsReplaying(false);
  }

  function replayImportedEvents() {
    if (importQueue.length === 0) {
      setCsvNotice("No imported events to replay.");
      return;
    }

    stopReplay();
    setIsReplaying(true);

    let cursor = 0;
    const ordered = [...importQueue].sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));

    replayTimerRef.current = window.setInterval(() => {
      const next = ordered[cursor];
      if (!next) {
        stopReplay();
        setCsvNotice("CSV replay complete.");
        return;
      }

      const replayEvent: DnsQueryEvent = {
        ...next,
        id: `replay-${Date.now()}-${cursor}`
      };

      setQueryEvents((current) => [replayEvent, ...current].slice(0, 40));
      void persistEvents([replayEvent]);
      cursor += 1;

      if (cursor >= ordered.length) {
        stopReplay();
        setCsvNotice("CSV replay complete.");
      }
    }, 450);
  }

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <p className="text-xs uppercase tracking-[0.22em] text-orange-300">New Module</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-100">Private DNS Simulator</h2>
        <p className="mt-2 text-sm text-slate-300">
          Visualize how malicious domains are sinkholed to a controlled endpoint while safe domains resolve normally.
        </p>
      </header>

      <section className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <article className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 backdrop-blur-xl">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Query Simulation</h3>
          <div className="mt-4 grid gap-3">
            <label className="text-sm text-slate-300">
              Domain Query
              <input
                value={domainInput}
                onChange={(event) => setDomainInput(event.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
                placeholder="example.com"
              />
            </label>
            <label className="text-sm text-slate-300">
              Sinkhole IP
              <input
                value={sinkholeIp}
                onChange={(event) => setSinkholeIp(event.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-orange-500/60"
              />
            </label>
            <button
              type="button"
              onClick={simulateQuery}
              className="rounded-lg border border-blue-400/45 bg-blue-500/20 px-4 py-2 text-sm font-semibold text-blue-100 transition hover:bg-blue-500/30"
            >
              Simulate DNS Query
            </button>
            <div className="flex flex-wrap items-center gap-2">
              <label className="rounded-lg border border-slate-600/55 bg-slate-800/50 px-4 py-2 text-xs font-medium text-slate-200">
                Import CSV
                <input type="file" accept=".csv,text/csv" onChange={handleCsvUpload} className="hidden" />
              </label>
              <button
                type="button"
                onClick={replayImportedEvents}
                className="rounded-lg border border-orange-400/45 bg-orange-500/20 px-4 py-2 text-xs font-semibold text-orange-100 transition hover:bg-orange-500/30 disabled:cursor-not-allowed disabled:opacity-50"
                disabled={importQueue.length === 0 || isReplaying}
              >
                {isReplaying ? "Replaying..." : "Replay Imported CSV"}
              </button>
              <button
                type="button"
                onClick={() => exportDnsEventsCsv(queryEvents)}
                className="rounded-lg border border-emerald-400/45 bg-emerald-500/15 px-4 py-2 text-xs font-semibold text-emerald-100 transition hover:bg-emerald-500/25 disabled:cursor-not-allowed disabled:opacity-50"
                disabled={queryEvents.length === 0}
              >
                Export Events CSV
              </button>
              {isReplaying ? (
                <button
                  type="button"
                  onClick={stopReplay}
                  className="rounded-lg border border-rose-400/45 bg-rose-500/15 px-4 py-2 text-xs font-semibold text-rose-100 transition hover:bg-rose-500/25"
                >
                  Stop Replay
                </button>
              ) : null}
            </div>
            {csvNotice ? <p className="text-xs text-slate-400">{csvNotice}</p> : null}
            {backendNotice ? <p className="text-xs text-slate-400">{backendNotice}</p> : null}
          </div>

          <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/65 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-400">Sinkhole Flow</p>
            <div className="mt-3 grid gap-3 text-sm text-slate-200 md:grid-cols-3">
              <div className="rounded-lg border border-slate-700 bg-slate-900/80 p-3">
                <p className="text-xs text-slate-400">1. Client Query</p>
                <p className="mt-1 font-medium">Endpoint requests domain</p>
              </div>
              <div className="rounded-lg border border-orange-400/35 bg-orange-500/10 p-3">
                <p className="text-xs text-orange-200">2. Policy Check</p>
                <p className="mt-1 font-medium text-orange-100">DNS list checks malicious indicators</p>
              </div>
              <div className="rounded-lg border border-blue-400/35 bg-blue-500/10 p-3">
                <p className="text-xs text-blue-200">3. Response</p>
                <p className="mt-1 font-medium text-blue-100">Resolve safe domain or redirect to sinkhole</p>
              </div>
            </div>
          </div>
        </article>

        <article className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 backdrop-blur-xl">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Domain Policy Library</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            <input
              value={newDomain}
              onChange={(event) => setNewDomain(event.target.value)}
              className="min-w-[220px] flex-1 rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/60"
              placeholder="new-domain.example"
            />
            <button
              type="button"
              onClick={() => addDomain("SAFE")}
              className="rounded-lg border border-emerald-400/45 bg-emerald-500/15 px-3 py-2 text-xs font-semibold text-emerald-100"
            >
              Add Safe
            </button>
            <button
              type="button"
              onClick={() => addDomain("MALICIOUS")}
              className="rounded-lg border border-rose-400/45 bg-rose-500/15 px-3 py-2 text-xs font-semibold text-rose-100"
            >
              Add Malicious
            </button>
          </div>

          <div className="mt-4 max-h-72 space-y-2 overflow-y-auto pr-1">
            {records.map((record) => (
              <div key={record.domain} className="flex items-center justify-between rounded-lg border border-slate-700/65 bg-slate-950/70 px-3 py-2">
                <span className="truncate pr-3 text-sm text-slate-100">{record.domain}</span>
                <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${statusClass(record.status)}`}>
                  {record.status}
                </span>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="grid gap-3 md:grid-cols-2">
        <article className="rounded-xl border border-orange-400/35 bg-orange-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-orange-100">Sinkholed Queries</p>
          <p className="mt-1 text-2xl font-semibold text-orange-100">{totals.sinkholed}</p>
        </article>
        <article className="rounded-xl border border-blue-400/35 bg-blue-500/10 p-4">
          <p className="text-xs uppercase tracking-wider text-blue-100">Allowed Queries</p>
          <p className="mt-1 text-2xl font-semibold text-blue-100">{totals.allowed}</p>
        </article>
      </section>

      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-[0_10px_35px_rgba(2,6,23,0.45)] backdrop-blur-xl">
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">DNS Query Event Stream</h3>
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-950/80 text-slate-300">
              <tr>
                <th className="px-3 py-3 text-left font-semibold">Time</th>
                <th className="px-3 py-3 text-left font-semibold">Source IP</th>
                <th className="px-3 py-3 text-left font-semibold">Domain</th>
                <th className="px-3 py-3 text-left font-semibold">Outcome</th>
                <th className="px-3 py-3 text-left font-semibold">Resolved IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/45">
              {queryEvents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-3 py-7 text-center text-slate-400">
                    Run a simulated DNS query to populate the stream.
                  </td>
                </tr>
              ) : (
                queryEvents.map((event) => (
                  <tr key={event.id} className="align-top hover:bg-slate-800/35">
                    <td className="px-3 py-3 whitespace-nowrap text-slate-300">
                      {new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>
                    <td className="px-3 py-3 text-slate-200">{event.sourceIp}</td>
                    <td className="px-3 py-3 text-slate-100">{event.domain}</td>
                    <td className="px-3 py-3">
                      <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${outcomeClass(event.outcome)}`}>
                        {event.outcome}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-slate-200">{event.resolvedIp}</td>
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

export default PrivateDnsSimulator;
