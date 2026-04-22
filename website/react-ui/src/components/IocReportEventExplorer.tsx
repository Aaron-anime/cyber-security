import { useEffect, useMemo, useState } from "react";
import { fetchLatestIocReport, type IocEventRecord, type LatestIocResponse } from "../api/client";
import SkeletonBlock from "./SkeletonBlock";
import { useToast } from "./ToastProvider";

type ActiveView = "process" | "network";

type ColumnDefinition = {
  key: string;
  label: string;
  accessors: string[];
};

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

function readFieldValue(record: IocEventRecord, accessors: string[], fallback = "N/A") {
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

function recordSearchText(record: IocEventRecord) {
  return JSON.stringify(record).toLowerCase();
}

function isSuspiciousNetworkEvent(record: IocEventRecord) {
  const remotePort = Number(record.remote_port ?? record.remotePort ?? 0);
  const status = String(record.status ?? record.state ?? "").toLowerCase();
  const remoteIp = String(record.remote_ip ?? record.destination ?? "");
  const isDnsRelated = Boolean(record.is_dns_related ?? record.dns_related ?? false);

  return (
    isDnsRelated ||
    [21, 22, 23, 25, 53, 80, 443, 4444, 5555, 8080, 1337].includes(remotePort) ||
    status.includes("dns") ||
    remoteIp.startsWith("8.8.") ||
    remoteIp.startsWith("1.1.1.")
  );
}

function IocReportEventExplorer() {
  const [report, setReport] = useState<LatestIocResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeView, setActiveView] = useState<ActiveView>("process");
  const [search, setSearch] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(true);
  const { addToast } = useToast();

  async function loadReport() {
    setLoading(true);
    setError("");

    try {
      const data = await fetchLatestIocReport();
      setReport(data);
      setSelectedIndex(0);
    } catch (err) {
      const message = String(err);
      setReport(null);
      setError(message);
      addToast({
        title: "IOC Event Load Failed",
        message,
        tone: "error"
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadReport();
  }, []);

  const columns = activeView === "process" ? processColumns : networkColumns;
  const rows = activeView === "process" ? report?.process_events ?? [] : report?.network_events ?? [];

  const filteredRows = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return rows.filter((row) => {
      const matchesSearch = !normalizedSearch || recordSearchText(row).includes(normalizedSearch);
      const matchesSuspicious = activeView === "process" || !showSuspiciousOnly || isSuspiciousNetworkEvent(row);
      return matchesSearch && matchesSuspicious;
    });
  }, [activeView, rows, search, showSuspiciousOnly]);

  const selectedRecord = filteredRows[selectedIndex] ?? null;

  function renderEventRow(row: IocEventRecord, index: number) {
    const isSelected = index === selectedIndex;

    return (
      <tr
        key={`${activeView}-${index}`}
        className={isSelected ? "event-row selected" : "event-row"}
        tabIndex={0}
        onClick={() => setSelectedIndex(index)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            setSelectedIndex(index);
          }
        }}
      >
        {activeView === "process" ? (
          <>
            <td>{readFieldValue(row, ["timestamp_utc", "time", "created_at_utc"])}</td>
            <td>{readFieldValue(row, ["pid", "process_id"])}</td>
            <td>{readFieldValue(row, ["ppid", "parent_pid"])}</td>
            <td>{readFieldValue(row, ["process_name", "name", "image"])}</td>
            <td>{readFieldValue(row, ["cmdline", "command_line", "command"])}</td>
            <td>{readFieldValue(row, ["parent_name", "parent_process", "parent_image"])}</td>
          </>
        ) : (
          <>
            <td>{readFieldValue(row, ["timestamp_utc", "time", "created_at_utc"])}</td>
            <td>{readFieldValue(row, ["pid", "process_id"])}</td>
            <td>{readFieldValue(row, ["process_name", "name", "image"])}</td>
            <td>{readFieldValue(row, ["local_endpoint", "local_ip", "source"])}</td>
            <td>{readFieldValue(row, ["remote_endpoint", "remote_ip", "destination"])}</td>
            <td>{readFieldValue(row, ["protocol", "proto"])}</td>
            <td>{readFieldValue(row, ["status", "state"])}</td>
          </>
        )}
      </tr>
    );
  }

  return (
    <section className="main-dashboard panel-reveal ioc-events-panel">
      <header className="dashboard-header">
        <p className="eyebrow">IOC Event Explorer</p>
        <h2>Process Events and Network Events</h2>
        <p className="muted-text">
          Inspect the most recent sandbox report with search, view toggles, and row selection.
        </p>
      </header>

      <div className="event-toolbar">
        <div className="event-tabs" role="tablist" aria-label="IOC event categories">
          <button
            type="button"
            className={activeView === "process" ? "event-tab active" : "event-tab"}
            onClick={() => {
              setActiveView("process");
              setSelectedIndex(0);
            }}
          >
            Process Events
          </button>
          <button
            type="button"
            className={activeView === "network" ? "event-tab active" : "event-tab"}
            onClick={() => {
              setActiveView("network");
              setSelectedIndex(0);
            }}
          >
            Network Events
          </button>
        </div>

        <div className="event-toolbar-actions">
          <input
            className="event-search"
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Search by PID, process name, IP, status..."
          />
          <div className="event-toolbar-buttons">
            {activeView === "network" ? (
              <button
                type="button"
                className={showSuspiciousOnly ? "event-chip active" : "event-chip"}
                onClick={() => {
                  setShowSuspiciousOnly((current) => !current);
                  setSelectedIndex(0);
                }}
              >
                Suspicious Only
              </button>
            ) : null}
            <button type="button" className="tool-action" onClick={() => void loadReport()}>
              Refresh Report
            </button>
          </div>
        </div>
      </div>

      {error ? <p className="error-text">{error}</p> : null}

      <div className="event-summary-row">
        <article className="metric-card panel-reveal">
          <p className="metric-label">Visible Events</p>
          <p className="metric-value">{loading ? <SkeletonBlock className="skeleton-inline" /> : filteredRows.length}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Process Events</p>
          <p className="metric-value">
            {loading ? <SkeletonBlock className="skeleton-inline" /> : report?.process_events.length ?? 0}
          </p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Network Events</p>
          <p className="metric-value">
            {loading ? <SkeletonBlock className="skeleton-inline" /> : report?.network_events.length ?? 0}
          </p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Suspicious Network Hits</p>
          <p className="metric-value">
            {loading ? (
              <SkeletonBlock className="skeleton-inline" />
            ) : (
              (report?.network_events ?? []).filter((row) => isSuspiciousNetworkEvent(row)).length
            )}
          </p>
        </article>
      </div>

      <div className="table-wrap event-table-wrap">
        <table className="event-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key}>{column.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 5 }).map((_, index) => (
                <tr key={`event-skeleton-${index}`}>
                  {columns.map((column) => (
                    <td key={`${column.key}-${index}`}>
                      <SkeletonBlock className="skeleton-cell" />
                    </td>
                  ))}
                </tr>
              ))
            ) : filteredRows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="empty-cell">
                  No matching events found.
                </td>
              </tr>
            ) : (
              filteredRows.map((row, index) => renderEventRow(row, index))
            )}
          </tbody>
        </table>
      </div>

      <div className="detail-panel">
        <div>
          <p className="eyebrow">Selected Event</p>
          <h3>
            {loading ? (
              <SkeletonBlock className="skeleton-inline skeleton-inline-wide" />
            ) : selectedRecord
              ? readFieldValue(selectedRecord, ["process_name", "name", "remote_ip", "timestamp_utc"])
              : "No event selected"}
          </h3>
        </div>
        <pre>
          {loading
            ? "Fetching report payload..."
            : selectedRecord
            ? JSON.stringify(selectedRecord, null, 2)
            : "Choose a row to inspect the raw event JSON."}
        </pre>
      </div>
    </section>
  );
}

export default IocReportEventExplorer;
