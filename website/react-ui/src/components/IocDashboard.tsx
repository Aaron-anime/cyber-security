import { Fragment, useEffect, useMemo, useState } from "react";
import { fetchLatestIocReport, type IocEventRecord, type LatestIocResponse } from "../api/client";

type ColumnDefinition = {
  key: string;
  label: string;
  accessors: string[];
};

type SortDirection = "asc" | "desc";

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

function formatEndpoint(record: IocEventRecord, ipKeys: string[], portKeys: string[]) {
  const ip = readField(record, ipKeys, "N/A");
  const port = readField(record, portKeys, "");
  return port && port !== "N/A" ? `${ip}:${port}` : ip;
}

type EventTableProps = {
  title: string;
  accentClass: string;
  description: string;
  rows: IocEventRecord[];
  columns: ColumnDefinition[];
  search: string;
  onSearchChange: (value: string) => void;
  sortKey: string;
  sortDirection: SortDirection;
  onSort: (key: string) => void;
  currentPage: number;
  rowsPerPage: number;
  onRowsPerPageChange: (value: number) => void;
  onPageChange: (value: number) => void;
  renderCell?: (row: IocEventRecord, column: ColumnDefinition) => string;
};

function EventTable({
  title,
  accentClass,
  description,
  rows,
  columns,
  search,
  onSearchChange,
  sortKey,
  sortDirection,
  onSort,
  currentPage,
  rowsPerPage,
  onRowsPerPageChange,
  onPageChange,
  renderCell
}: EventTableProps) {
  const [expandedRowKey, setExpandedRowKey] = useState<string | null>(null);

  const filteredRows = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();
    if (!normalizedSearch) {
      return rows;
    }
    return rows.filter((row) => JSON.stringify(row).toLowerCase().includes(normalizedSearch));
  }, [rows, search]);

  const sortedRows = useMemo(() => {
    const activeColumn = columns.find((column) => column.key === sortKey) ?? columns[0];

    return [...filteredRows].sort((left, right) => {
      const leftValue = readField(left, activeColumn.accessors, "");
      const rightValue = readField(right, activeColumn.accessors, "");
      return compareValues(leftValue, rightValue, sortDirection);
    });
  }, [columns, filteredRows, sortDirection, sortKey]);

  const totalPages = Math.max(1, Math.ceil(sortedRows.length / rowsPerPage));
  const safePage = Math.min(currentPage, totalPages);
  const pageStart = (safePage - 1) * rowsPerPage;
  const pagedRows = sortedRows.slice(pageStart, pageStart + rowsPerPage);

  useEffect(() => {
    setExpandedRowKey(null);
  }, [rows, search, sortKey, sortDirection, safePage, rowsPerPage]);

  return (
    <article className="rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-lg p-5 space-y-4">
      <div className="flex flex-col gap-2">
        <h3 className={`text-lg font-semibold ${accentClass}`}>{title}</h3>
        <p className="text-sm text-slate-400">{description}</p>
      </div>

      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
        <input
          type="search"
          value={search}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="Search table rows..."
          className="w-full xl:max-w-md rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
        />
        <label className="inline-flex items-center gap-2 text-sm text-slate-300">
          Rows
          <select
            value={rowsPerPage}
            onChange={(event) => onRowsPerPageChange(Number(event.target.value))}
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

      <div className="text-sm text-slate-400">
        Showing {pagedRows.length} of {sortedRows.length} filtered events ({rows.length} total)
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-800">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-950/80 text-slate-300">
            <tr>
              <th className="w-10 px-2 py-3 text-center font-semibold" aria-label="Expand row" />
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
                      <span className="text-xs text-slate-500">
                        {isSorted ? (sortDirection === "asc" ? "ASC" : "DESC") : ""}
                      </span>
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
              pagedRows.map((row, rowIndex) => {
                const rowKey = `${title}-${pageStart + rowIndex}`;
                const isExpanded = expandedRowKey === rowKey;

                return (
                  <Fragment key={rowKey}>
                    <tr
                      className="hover:bg-slate-800/40 cursor-pointer"
                      onClick={() => {
                        setExpandedRowKey((current) => (current === rowKey ? null : rowKey));
                      }}
                      aria-expanded={isExpanded}
                    >
                      <td className="px-2 py-3 text-center text-slate-400">
                        <span aria-hidden="true">{isExpanded ? "▾" : "▸"}</span>
                        <span className="sr-only">{isExpanded ? "Collapse row" : "Expand row"}</span>
                      </td>
                      {columns.map((column) => (
                        <td key={`${rowKey}-${column.key}`} className="px-3 py-3 align-top text-slate-100 whitespace-nowrap">
                          {renderCell ? renderCell(row, column) : readField(row, column.accessors)}
                        </td>
                      ))}
                    </tr>
                    {isExpanded ? (
                      <tr className="bg-slate-950/65">
                        <td colSpan={columns.length + 1} className="px-3 py-3">
                          <p className="text-xs uppercase tracking-wide text-slate-400 mb-2">Raw Event JSON</p>
                          <pre className="text-xs text-cyan-100 overflow-x-auto whitespace-pre-wrap break-words">
                            {JSON.stringify(row, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-400">
          Page {safePage} of {totalPages}
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => onPageChange(Math.max(1, safePage - 1))}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-40"
          >
            Previous
          </button>
          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => onPageChange(Math.min(totalPages, safePage + 1))}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </article>
  );
}

function IocDashboard() {
  const [report, setReport] = useState<LatestIocResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [processSearch, setProcessSearch] = useState("");
  const [networkSearch, setNetworkSearch] = useState("");
  const [processPage, setProcessPage] = useState(1);
  const [networkPage, setNetworkPage] = useState(1);
  const [processRowsPerPage, setProcessRowsPerPage] = useState(10);
  const [networkRowsPerPage, setNetworkRowsPerPage] = useState(10);
  const [processSortKey, setProcessSortKey] = useState("pid");
  const [networkSortKey, setNetworkSortKey] = useState("remote_endpoint");
  const [processSortDirection, setProcessSortDirection] = useState<SortDirection>("asc");
  const [networkSortDirection, setNetworkSortDirection] = useState<SortDirection>("asc");

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
    setProcessPage(1);
  }, [processSearch, processRowsPerPage, processSortDirection, processSortKey]);

  useEffect(() => {
    setNetworkPage(1);
  }, [networkSearch, networkRowsPerPage, networkSortDirection, networkSortKey]);

  function onProcessSort(columnKey: string) {
    if (processSortKey === columnKey) {
      setProcessSortDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }

    setProcessSortKey(columnKey);
    setProcessSortDirection("asc");
  }

  function onNetworkSort(columnKey: string) {
    if (networkSortKey === columnKey) {
      setNetworkSortDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }

    setNetworkSortKey(columnKey);
    setNetworkSortDirection("asc");
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

        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-lg p-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-slate-300">Latest report loaded from backend SQLite store.</p>
          <button
            type="button"
            onClick={() => void loadLatest()}
            className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
          >
            Refresh Report
          </button>
        </div>

        {loading ? (
          <div className="grid gap-5">
            {["process", "network"].map((section) => (
              <div key={section} className="rounded-2xl border border-slate-800 bg-slate-900/80 backdrop-blur-lg p-5 space-y-3" aria-live="polite">
                <div className="h-5 w-48 rounded bg-slate-800/70 animate-pulse" />
                <div className="h-4 w-72 rounded bg-slate-800/60 animate-pulse" />
                {Array.from({ length: 6 }).map((_, index) => (
                  <div key={`${section}-skeleton-${index}`} className="h-10 rounded-lg bg-slate-800/70 animate-pulse" />
                ))}
              </div>
            ))}
          </div>
        ) : null}

        {!loading && error ? (
          <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 p-3 text-rose-200">
            Failed to load latest IOC report: {error}
          </div>
        ) : null}

        {!loading && !error ? (
          <div className="grid gap-5">
            <EventTable
              title="Process Events"
              accentClass="text-cyan-300"
              description="Interactive process telemetry with PID, parent process, and command-line arguments."
              rows={report?.process_events ?? []}
              columns={[
                { key: "pid", label: "PID", accessors: ["pid", "process_id"] },
                { key: "parent_name", label: "Parent Process", accessors: ["parent_name", "parent_process", "parent_image"] },
                { key: "cmdline", label: "Command Line", accessors: ["cmdline", "command_line", "command"] }
              ]}
              search={processSearch}
              onSearchChange={setProcessSearch}
              sortKey={processSortKey}
              sortDirection={processSortDirection}
              onSort={onProcessSort}
              currentPage={processPage}
              rowsPerPage={processRowsPerPage}
              onRowsPerPageChange={setProcessRowsPerPage}
              onPageChange={setProcessPage}
            />

            <EventTable
              title="Network Events"
              accentClass="text-emerald-300"
              description="Interactive network telemetry with protocol plus local and remote IP:port endpoints."
              rows={report?.network_events ?? []}
              columns={[
                { key: "protocol", label: "Protocol", accessors: ["protocol", "proto"] },
                { key: "local_endpoint", label: "Local IP:Port", accessors: ["local_endpoint", "local_ip"] },
                { key: "remote_endpoint", label: "Remote IP:Port", accessors: ["remote_endpoint", "remote_ip"] }
              ]}
              search={networkSearch}
              onSearchChange={setNetworkSearch}
              sortKey={networkSortKey}
              sortDirection={networkSortDirection}
              onSort={onNetworkSort}
              currentPage={networkPage}
              rowsPerPage={networkRowsPerPage}
              onRowsPerPageChange={setNetworkRowsPerPage}
              onPageChange={setNetworkPage}
              renderCell={(row, column) => {
                if (column.key === "local_endpoint") {
                  return formatEndpoint(row, ["local_ip", "source", "local_endpoint"], ["local_port"]);
                }
                if (column.key === "remote_endpoint") {
                  return formatEndpoint(row, ["remote_ip", "destination", "remote_endpoint"], ["remote_port"]);
                }
                return readField(row, column.accessors);
              }}
            />
          </div>
        ) : null}
      </div>
    </section>
  );
}

export default IocDashboard;
