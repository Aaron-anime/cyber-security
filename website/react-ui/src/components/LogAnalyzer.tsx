import { useMemo, useState } from "react";

type Severity = "FATAL" | "ERROR" | "TIMEOUT" | "WARN";

type ParsedLogRow = {
  id: string;
  severity: Severity;
  timestamp: string;
  message: string;
};

const severityPriority: Severity[] = ["FATAL", "ERROR", "TIMEOUT", "WARN"];

const timestampPatterns: RegExp[] = [
  /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\b/,
  /\b\d{4}\/\d{2}\/\d{2}[T\s]\d{2}:\d{2}:\d{2}\b/,
  /\b\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\b/
];

function detectSeverity(line: string): Severity | null {
  const upper = line.toUpperCase();

  for (const severity of severityPriority) {
    if (upper.includes(severity)) {
      return severity;
    }
  }

  return null;
}

function extractTimestamp(line: string): string {
  for (const pattern of timestampPatterns) {
    const found = line.match(pattern);
    if (found?.[0]) {
      return found[0];
    }
  }

  return "N/A";
}

function severityClass(severity: Severity): string {
  if (severity === "FATAL") {
    return "bg-rose-600/20 text-rose-300 border border-rose-500/50";
  }

  if (severity === "ERROR") {
    return "bg-red-600/20 text-red-300 border border-red-500/50";
  }

  if (severity === "TIMEOUT") {
    return "bg-amber-600/20 text-amber-200 border border-amber-500/50";
  }

  return "bg-yellow-500/15 text-yellow-200 border border-yellow-500/45";
}

function parseLogText(rawText: string): ParsedLogRow[] {
  const rows: ParsedLogRow[] = [];
  const lines = rawText.split(/\r?\n/);

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }

    const severity = detectSeverity(trimmed);
    if (!severity) {
      return;
    }

    rows.push({
      id: `log-${index + 1}`,
      severity,
      timestamp: extractTimestamp(trimmed),
      message: trimmed
    });
  });

  return rows;
}

function LogAnalyzer() {
  const [rawLogs, setRawLogs] = useState("");
  const [parsedRows, setParsedRows] = useState<ParsedLogRow[]>([]);
  const [hasParsed, setHasParsed] = useState(false);

  const severityCounts = useMemo(() => {
    const summary: Record<Severity, number> = {
      FATAL: 0,
      ERROR: 0,
      TIMEOUT: 0,
      WARN: 0
    };

    parsedRows.forEach((row) => {
      summary[row.severity] += 1;
    });

    return summary;
  }, [parsedRows]);

  function handleParseLogs() {
    setParsedRows(parseLogText(rawLogs));
    setHasParsed(true);
  }

  return (
    <section className="rounded-2xl border border-slate-700/70 bg-slate-900/75 p-6 shadow-2xl backdrop-blur-xl space-y-5">
      <header>
        <p className="text-xs uppercase tracking-widest text-cyan-400 font-semibold">Tool Library</p>
        <h3 className="mt-2 text-xl font-bold text-slate-100">Event Log Analyzer</h3>
        <p className="mt-2 text-sm text-slate-400">
          Paste raw system logs, parse severity markers, and triage critical events quickly.
        </p>
      </header>

      <div className="space-y-3">
        <label htmlFor="event-log-input" className="text-sm font-semibold text-slate-300">
          Raw System Logs
        </label>
        <textarea
          id="event-log-input"
          value={rawLogs}
          onChange={(event) => setRawLogs(event.target.value)}
          placeholder="Paste logs here...\n2026-04-22T06:10:04Z ERROR Failed to connect to sandbox service\n2026-04-22T06:10:08Z WARN Retry attempt 1"
          className="min-h-52 w-full rounded-xl border border-slate-700 bg-slate-950/70 p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
        />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={handleParseLogs}
          className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
        >
          Parse Logs
        </button>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-full bg-slate-800 px-3 py-1 text-slate-300">FATAL: {severityCounts.FATAL}</span>
          <span className="rounded-full bg-slate-800 px-3 py-1 text-slate-300">ERROR: {severityCounts.ERROR}</span>
          <span className="rounded-full bg-slate-800 px-3 py-1 text-slate-300">TIMEOUT: {severityCounts.TIMEOUT}</span>
          <span className="rounded-full bg-slate-800 px-3 py-1 text-slate-300">WARN: {severityCounts.WARN}</span>
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-800">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-950/85 text-slate-300">
            <tr>
              <th className="px-3 py-3 text-left font-semibold">Severity</th>
              <th className="px-3 py-3 text-left font-semibold">Timestamp</th>
              <th className="px-3 py-3 text-left font-semibold">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {!hasParsed ? (
              <tr>
                <td colSpan={3} className="px-3 py-8 text-center text-slate-400">
                  Paste logs and click Parse Logs to generate analysis results.
                </td>
              </tr>
            ) : parsedRows.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-3 py-8 text-center text-slate-400">
                  No matching severity keywords found. Try logs containing ERROR, WARN, FATAL, or TIMEOUT.
                </td>
              </tr>
            ) : (
              parsedRows.map((row) => (
                <tr key={row.id} className="hover:bg-slate-800/40 align-top">
                  <td className="px-3 py-3">
                    <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${severityClass(row.severity)}`}>
                      {row.severity}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-slate-300 whitespace-nowrap">{row.timestamp}</td>
                  <td className="px-3 py-3 text-slate-100 break-words">{row.message}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default LogAnalyzer;
