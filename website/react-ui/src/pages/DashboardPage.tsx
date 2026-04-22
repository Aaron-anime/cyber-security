import { useEffect, useState } from "react";
import MainDashboard from "../components/MainDashboard";
import { fetchLatestIocReport, fetchThreatFeed } from "../api/client";
import { dashboardMetrics } from "../data/controlCenterContent";

type Snapshot = {
  threatIndicatorCount: number;
  latestThreatSource: string;
  latestIocProcessCount: number;
  latestIocFlaggedConnections: number;
};

function DashboardPage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let active = true;

    async function loadSnapshot() {
      try {
        const [feed, latestIoc] = await Promise.all([
          fetchThreatFeed(),
          fetchLatestIocReport().catch(() => null)
        ]);

        if (!active) {
          return;
        }

        setSnapshot({
          threatIndicatorCount: feed.indicators.length,
          latestThreatSource: feed.source,
          latestIocProcessCount: latestIoc?.process_count ?? 0,
          latestIocFlaggedConnections: latestIoc?.flagged_connection_count ?? 0
        });
      } catch (err) {
        if (active) {
          setError(String(err));
        }
      }
    }

    void loadSnapshot();
    return () => {
      active = false;
    };
  }, []);

  return (
    <>
      <MainDashboard metrics={dashboardMetrics} />
      <section className="panel-reveal main-dashboard">
        <header className="dashboard-header">
          <p className="eyebrow">Live Snapshot</p>
          <h2>Backend Data at a Glance</h2>
        </header>
        {error ? (
          <p className="error-text">{error}</p>
        ) : (
          <div className="metric-grid">
            <article className="metric-card panel-reveal">
              <p className="metric-label">Threat Indicators</p>
              <p className="metric-value">{snapshot?.threatIndicatorCount ?? "..."}</p>
            </article>
            <article className="metric-card panel-reveal">
              <p className="metric-label">Threat Source</p>
              <p className="metric-value metric-value-small">{snapshot?.latestThreatSource ?? "..."}</p>
            </article>
            <article className="metric-card panel-reveal">
              <p className="metric-label">Latest IOC Processes</p>
              <p className="metric-value">{snapshot?.latestIocProcessCount ?? "..."}</p>
            </article>
            <article className="metric-card panel-reveal">
              <p className="metric-label">Latest Flagged Connections</p>
              <p className="metric-value">{snapshot?.latestIocFlaggedConnections ?? "..."}</p>
            </article>
          </div>
        )}
      </section>
    </>
  );
}

export default DashboardPage;