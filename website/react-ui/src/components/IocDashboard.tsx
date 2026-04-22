import { useEffect, useMemo, useState } from "react";
import { fetchLatestIocReport, type IocEventRecord, type LatestIocResponse } from "../api/client";

type ActiveTable = "process" | "network";

type ColumnDefinition = {
  key: string;
  label: string;
  accessors: string[];
};

type SortDirection = "asc" | "desc";

const processColumns: ColumnDefinition[] = [
  { key: "timestamp_utc", label: "Timestamp", accessors: ["timestamp_utc", "time", "created_at_utc"] },
  { key: "pid", label: "PID", accessors: ["pid", "process_id"] },
  { key: "ppid", label: "PPID", accessors: ["ppid", "parent_pid"] },
  { key: "process_name", label: "Process", accessors: ["process_name", "name", "image"] },
  { key: "cmdline", label: "Command Line", accessors: ["cmdline", "command_line", "command"] },
  { key: "parent_name", label: "Parent", accessors: ["parent_name", "parent_process", "parent_image"] }
];

const networkColumns: ColumnDefinition[] = [
  { key: "timestamp_utc", label: "Timestamp", accessors: ["timestamp_utc", "time", "created_at_utc"] },
  { key: "pid", label: "PID", accessors: ["pid", "process_id"] },
  { key: "process_name", label: "Process", accessors: ["process_name", "name", "image"] },
  { key: "local_endpoint", label: "Local Endpoint", accessors: ["local_endpoint", "local_ip", "source"] },
  { key: "remote_endpoint", label: "Remote Endpoint", accessors: ["remote_endpoint", "remote_ip", "destination"] },
  { key: "protocol", label: "Protocol", accessors: ["protocol", "proto"] },
  { key: "status", label: "Status", accessors: ["status", "state"] }
];

function readField(record: IocEventRecord, accessors: string[], fallback = "N/A") {
  for (const accessor of accessors) {
    const value = record[accessor];

    if (value === null || value === undefined) {
      continue;
    }

    if (Array.isArray(value)) {
      const text = value.map((item) => String(item)).filter(Boolean).join(" ");
      if (text) {
        return text;
      }
      continue;
    }

    if (typeof value === "object") {
      const text = JSON.stringify(value);
      if (text && text !== "{}") {
        return text;
      }
      continue;
    }

    const text = String(value).trim();
    if (text) {
      return text;
    }
  }

  return fallback;
}

function compareValues(a: string, b: string, direction: SortDirection) {
  const result = a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
  return direction === "asc" ? result : -result;
}

function IocDashboard() {
  const [report, setReport] = useState<LatestIocResponse | null>(null);
  const [activeTable, setActiveTable] = useState<ActiveTable>("process");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [sortKey, setSortKey] = useState("timestamp_utc");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  const columns = activeTable === "process" ? processColumns : networkColumns;
  const allRows = activeTable === "process" ? report?.process_events ?? [] : report?.network_events ?? [];

  async function loadLatest() {
    setLoading(true);
    setError("");

    try {
      const data = await fetchLatestIocReport();
      setReport(data);
    } catch (err) {
      setReport(null);
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadLatest();
  }, []);

  useEffect(() => {
    setCurrentPage(1);
  }, [activeTable, search, rowsPerPage, sortKey, sortDirection]);

  const filteredRows = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    if (!normalizedSearch) {
      return allRows;
    }

    return allRows.filter((row) => JSON.stringify(row).toLowerCase().includes(normalizedSearch));
  }, [allRows, search]);

  const sortedRows = useMemo(() => {
    const activeColumn = columns.find((column) => column.key === sortKey) ?? columns[0];

    return [...filteredRows].sort((left, right) => {
      const leftValue = readField(left, activeColumn.accessors, "");
      const rightValue = readField(right, activeColumn.accessors, "");
      return compareValues(leftValue, rightValue, sortDirection);
    });
  }, [columns, filteredRows, sortDirection, sortKey]);

  const totalPages = Math.max(1, Math.ceil(sortedRows.length / rowsPerPage));
  const pageStart = (currentPage - 1) * rowsPerPage;
  const pagedRows = sortedRows.slice(pageStart, pageStart + rowsPerPage);

  function onSort(columnKey: string) {
    if (sortKey === columnKey) {
      setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }

    setSortKey(columnKey);
    setSortDirection("asc");
  }

  return (
    <section className="min-h-screen bg-slate-950 text-slate-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
          <p className="text-xs uppercase tracking-widest text-cyan-400 font-semibold">SOC Module</p>
          <h2 className="mt-2 text-2xl font-bold text-white">IOC Dashboard</h2>
          <p className="mt-2 text-slate-400">
            Fetching the latest malware analysis report from your Flask backend and rendering process/network telemetry.
          </p>

          <div className="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-3">
            <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-400">Latest Source</p>
              <p className="mt-1 font-semibold break-all">{report?.source_name ?? "N/A"}</p>
            </article>
            <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-400">Process Events</p>
              <p className="mt-1 text-xl font-bold text-cyan-300">{report?.process_events.length ?? 0}</p>
            </article>
            <article className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-400">Network Events</p>
              <p className="mt-1 text-xl font-bold text-emerald-300">{report?.network_events.length ?? 0}</p>
            </article>
          </div>
        </header>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div className="inline-flex rounded-xl border border-slate-700 bg-slate-950 p-1" role="tablist" aria-label="IOC table switcher">
              <button
                type="button"
                role="tab"
                aria-selected={activeTable === "process"}
                className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${
                  activeTable === "process" ? "bg-cyan-500/20 text-cyan-300" : "text-slate-300 hover:text-white"
                }`}
                onClick={() => setActiveTable("process")}
              >
                Process Events
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTable === "network"}
                className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${
                  activeTable === "network" ? "bg-emerald-500/20 text-emerald-300" : "text-slate-300 hover:text-white"
                }`}
                onClick={() => setActiveTable("network")}
              >
                Network Events
              </button>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search by PID, process, command, IP, protocol..."
                className="w-full sm:w-80 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
              />
              <button
                type="button"
                onClick={() => void loadLatest()}
                className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
              >
                Refresh
              </button>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-sm text-slate-400">
            <p>
              Showing {pagedRows.length} of {sortedRows.length} filtered events ({allRows.length} total)
            </p>
            <label className="inline-flex items-center gap-2">
              Rows per page
              <select
                value={rowsPerPage}
                onChange={(event) => setRowsPerPage(Number(event.target.value))}
                className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100"
              >
                {[10, 20, 50].map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {loading ? (
            <div className="space-y-3" aria-live="polite">
              {Array.from({ length: 8 }).map((_, index) => (
                <div key={`ioc-skeleton-${index}`} className="h-10 rounded-lg bg-slate-800/70 animate-pulse" />
              ))}
            </div>
          ) : null}

          {!loading && error ? (
            <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 p-3 text-rose-200">
              Failed to load latest IOC report: {error}
            </div>
          ) : null}

          {!loading && !error ? (
            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="min-w-full text-sm">
                <thead className="bg-slate-950/80 text-slate-300">
                  <tr>
                    {columns.map((column) => {
                      const isSorted = sortKey === column.key;
                      return (
                        <th key={column.key} className="px-3 py-3 text-left font-semibold whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => onSort(column.key)}
                            className="inline-flex items-center gap-2 hover:text-white"
                          >
                            <span>{column.label}</span>
                            <span className="text-xs text-slate-500">{isSorted ? (sortDirection === "asc" ? "ASC" : "DESC") : ""}</span>
                          </button>
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 bg-slate-900/40">
                  {pagedRows.length === 0 ? (
                    <tr>
                      <td colSpan={columns.length} className="px-3 py-8 text-center text-slate-400">
                        No matching events found.
                      </td>
                    </tr>
                  ) : (
                    pagedRows.map((row, rowIndex) => (
                      <tr key={`${activeTable}-${rowIndex}`} className="hover:bg-slate-800/40">
                        {columns.map((column) => (
                          <td key={`${column.key}-${rowIndex}`} className="px-3 py-3 align-top text-slate-100 whitespace-nowrap">
                            {readField(row, column.accessors)}
                          </td>
                        ))}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          ) : null}

          <div className="flex items-center justify-between">
            <p className="text-sm text-slate-400">
              Page {currentPage} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage((current) => Math.max(1, current - 1))}
                className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((current) => Math.min(totalPages, current + 1))}
                className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default IocDashboard;
