import { useEffect, useState } from "react";
import { fetchThreatFeed, type ThreatIndicator } from "../api/client";

function ThreatFeedPage() {
  const [source, setSource] = useState<string>("");
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);

  async function loadFeed() {
    setLoading(true);
    setError("");
    try {
      const feed = await fetchThreatFeed();
      setSource(feed.source);
      setIndicators(feed.indicators);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadFeed();
  }, []);

  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">Threat Intelligence</p>
        <h2>Live Threat Feed</h2>
        <p className="muted-text">Current source: {source || "loading..."}</p>
      </header>

      <button type="button" className="tool-action" onClick={() => void loadFeed()}>
        Refresh Feed
      </button>

      {loading ? <p className="muted-text">Loading threat indicators...</p> : null}
      {error ? <p className="error-text">{error}</p> : null}

      <div className="table-wrap panel-reveal">
        <table className="data-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Severity</th>
              <th>Label</th>
            </tr>
          </thead>
          <tbody>
            {indicators.map((item) => (
              <tr key={`${item.type}-${item.value}`}>
                <td>{item.type}</td>
                <td>{item.value}</td>
                <td>{item.severity}</td>
                <td>{item.label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default ThreatFeedPage;