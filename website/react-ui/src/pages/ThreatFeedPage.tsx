import { useEffect, useState } from "react";
import { fetchThreatFeed, type ThreatIndicator } from "../api/client";
import SkeletonBlock from "../components/SkeletonBlock";
import { useToast } from "../components/ToastProvider";

function ThreatFeedPage() {
  const [source, setSource] = useState<string>("");
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);
  const { addToast } = useToast();

  async function loadFeed() {
    setLoading(true);
    setError("");
    try {
      const feed = await fetchThreatFeed();
      setSource(feed.source);
      setIndicators(feed.indicators);
    } catch (err) {
      const message = String(err);
      setError(message);
      addToast({
        title: "Threat Feed Error",
        message,
        tone: "error"
      });
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
        <p className="muted-text">
          Current source:{" "}
          {loading ? <SkeletonBlock className="skeleton-inline" /> : source || "N/A"}
        </p>
      </header>

      <button type="button" className="tool-action" onClick={() => void loadFeed()}>
        Refresh Feed
      </button>

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
            {loading
              ? Array.from({ length: 5 }).map((_, index) => (
                  <tr key={`skeleton-${index}`}>
                    <td>
                      <SkeletonBlock className="skeleton-cell" />
                    </td>
                    <td>
                      <SkeletonBlock className="skeleton-cell skeleton-cell-wide" />
                    </td>
                    <td>
                      <SkeletonBlock className="skeleton-cell" />
                    </td>
                    <td>
                      <SkeletonBlock className="skeleton-cell" />
                    </td>
                  </tr>
                ))
              : indicators.map((item) => (
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