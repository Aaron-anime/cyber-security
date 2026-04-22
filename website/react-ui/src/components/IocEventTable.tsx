import { useEffect, useState } from "react";
import { fetchLatestIocReport, type IocEventRecord, type LatestIocResponse } from "../api/client";

type ActiveView = "process" | "network";

type EventColumn = {
  key: string;
  label: string;
};

const processColumns: EventColumn[] = [
  { key: "timestamp_utc", label: "Timestamp" },
  { key: "pid", label: "PID" },
  { key: "ppid", label: "PPID" },
  { key: "process_name", label: "Process" },
  { key: "cmdline", label: "Command Line" },
  { key: "parent_name", label: "Parent" }
];

const networkColumns: EventColumn[] = [
  { key: "timestamp_utc", label: "Timestamp" },
  { key: "pid", label: "PID" },
  { key: "process_name", label: "Process" },
  { key: "local_endpoint", label: "Local Endpoint" },
  { key: "remote_endpoint", label: "Remote Endpoint" },
  { key: "protocol", label: "Protocol" },
  { key: "status", label: "Status" }
];

function getFieldValue(record: IocEventRecord, keys: string[], fallback = "N/A") {
  for (const key of keys) {
    const value = record[key];
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

function eventToSearchText(record: IocEventRecord) {
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

function IocEventTable() {
  const [report, setReport] = useState<LatestIocResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeView, setActiveView] = useState<ActiveView>("process");
  const [search, setSearch] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(true);

  async function loadReport() {
    setLoading(true);
    setError("");
    try {
      const data = await fetchLatestIocReport();
      setReport(data);
      setSelectedIndex(0);
    } catch (err) {
      setReport(null);
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadReport();
  }, []);

  const rows = activeView === "process" ? report?.process_events ?? [] : report?.network_events ?? [];
  const filteredRows = rows.filter((row) => {
    const matchesSearch = !search || eventToSearchText(row).includes(search.toLowerCase());
    const matchesSuspicious =
      activeView === "process" || !showSuspiciousOnly || isSuspiciousNetworkEvent(row);

    return matchesSearch && matchesSuspicious;
  });
  const columns = activeView === "process" ? processColumns : networkColumns;
  const selectedRecord = filteredRows[selectedIndex] ?? null;

  function renderTableRow(row: IocEventRecord, index: number) {
    const isSelected = index === selectedIndex;

    if (activeView === "process") {
      return (
        <tr
          key={`process-${index}`}
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
          <td>{getFieldValue(row, ["timestamp_utc", "time", "created_at_utc"])} </td>
          <td>{getFieldValue(row, ["pid", "process_id"])} </td>
          <td>{getFieldValue(row, ["ppid", "parent_pid"])} </td>
          <td>{getFieldValue(row, ["process_name", "name", "image"])} </td>
          <td>{getFieldValue(row, ["cmdline", "command_line", "command"])} </td>
          <td>{getFieldValue(row, ["parent_name", "parent_process", "parent_image"])} </td>
        </tr>
      );
    }

    return (
      <tr
        key={`network-${index}`}
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
        <td>{getFieldValue(row, ["timestamp_utc", "time", "created_at_utc"])} </td>
        <td>{getFieldValue(row, ["pid", "process_id"])} </td>
        <td>{getFieldValue(row, ["process_name", "name", "image"])} </td>
        <td>{getFieldValue(row, ["local_endpoint", "local_ip", "source"])} </td>
        <td>{getFieldValue(row, ["remote_endpoint", "remote_ip", "destination"])} </td>
        <td>{getFieldValue(row, ["protocol", "proto"])} </td>
        <td>{getFieldValue(row, ["status", "state"])} </td>
      </tr>
    );
  }

  return (
    <section className="main-dashboard panel-reveal ioc-events-panel">
      <header className="dashboard-header">
        <p className="eyebrow">IOC Event Explorer</p>
        <h2>Process Events and Network Events</h2>
        <p className="muted-text">
          Inspect the most recent sandbox report with search, tab filtering, and row selection.
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

      {loading ? <p className="muted-text">Loading IOC report...</p> : null}
      {error ? <p className="error-text">{error}</p> : null}

      <div className="event-summary-row">
        <article className="metric-card panel-reveal">
          <p className="metric-label">Visible Events</p>
          <p className="metric-value">{filteredRows.length}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Process Events</p>
          <p className="metric-value">{report?.process_events.length ?? 0}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Network Events</p>
          <p className="metric-value">{report?.network_events.length ?? 0}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Suspicious Network Hits</p>
          <p className="metric-value">
            {(report?.network_events ?? []).filter((row) => isSuspiciousNetworkEvent(row)).length}
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
            {filteredRows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="empty-cell">
                  No matching events found.
                </td>
              </tr>
            ) : (
              filteredRows.map((row, index) => renderTableRow(row, index))
            )}
          </tbody>
        </table>
      </div>

      <div className="detail-panel">
        <div>
          <p className="eyebrow">Selected Event</p>
          <h3>{selectedRecord ? getFieldValue(selectedRecord, ["process_name", "name", "remote_ip", "timestamp_utc"]) : "No event selected"}</h3>
        </div>
        <pre>{selectedRecord ? JSON.stringify(selectedRecord, null, 2) : "Choose a row to inspect the raw event JSON."}</pre>
      </div>
    </section>
  );
}

export default IocEventTable;