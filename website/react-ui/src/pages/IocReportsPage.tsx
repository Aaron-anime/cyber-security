import { useEffect, useState } from "react";
import { fetchLatestIocReport, uploadIocReport, type LatestIocResponse } from "../api/client";
import IocEventTable from "../components/IocEventTable";

function IocReportsPage() {
  const [latest, setLatest] = useState<LatestIocResponse | null>(null);
  const [error, setError] = useState<string>("");
  const [uploading, setUploading] = useState<boolean>(false);

  const processCount = latest?.process_events.length ?? latest?.process_count ?? 0;
  const networkCount = latest?.network_events.length ?? latest?.flagged_connection_count ?? 0;
  const reportSize = latest?.report ? JSON.stringify(latest.report).length : 0;

  async function loadLatest() {
    setError("");
    try {
      const data = await fetchLatestIocReport();
      setLatest(data);
    } catch (err) {
      setLatest(null);
      setError(String(err));
    }
  }

  useEffect(() => {
    void loadLatest();
  }, []);

  async function handleUpload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = form.elements.namedItem("report") as HTMLInputElement | null;
    const file = input?.files?.[0];

    if (!file) {
      setError("Select an IOC report JSON file first.");
      return;
    }

    setUploading(true);
    setError("");
    try {
      await uploadIocReport(file);
      await loadLatest();
      form.reset();
    } catch (err) {
      setError(String(err));
    } finally {
      setUploading(false);
    }
  }

  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">IOC Reports</p>
        <h2>Upload and Review Latest Report</h2>
      </header>

      <form className="upload-form" onSubmit={handleUpload}>
        <input name="report" type="file" accept="application/json,.json" required />
        <button className="tool-action" type="submit" disabled={uploading}>
          {uploading ? "Uploading..." : "Upload IOC Report"}
        </button>
      </form>

      {error ? <p className="error-text">{error}</p> : null}

      <div className="metric-grid">
        <article className="metric-card panel-reveal">
          <p className="metric-label">Source File</p>
          <p className="metric-value metric-value-small">{latest?.source_name ?? "N/A"}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Process Count</p>
          <p className="metric-value">{processCount}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Flagged Connections</p>
          <p className="metric-value">{networkCount}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Report Size</p>
          <p className="metric-value metric-value-small">{reportSize ? `${reportSize} chars` : "N/A"}</p>
        </article>
      </div>

      <div className="report-meta-grid">
        <article className="meta-card panel-reveal">
          <p className="metric-label">Uploaded At</p>
          <p className="metric-value metric-value-small">{latest?.uploaded_at_utc ?? "N/A"}</p>
        </article>
        <article className="meta-card panel-reveal">
          <p className="metric-label">Raw Process Tree Nodes</p>
          <p className="metric-value">{latest?.process_tree.length ?? 0}</p>
        </article>
        <article className="meta-card panel-reveal">
          <p className="metric-label">Process Events</p>
          <p className="metric-value">{processCount}</p>
        </article>
        <article className="meta-card panel-reveal">
          <p className="metric-label">Network Events</p>
          <p className="metric-value">{latest?.network_events.length ?? 0}</p>
        </article>
      </div>

      <IocEventTable />
    </section>
  );
}

export default IocReportsPage;