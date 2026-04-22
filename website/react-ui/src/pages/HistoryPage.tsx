import { useEffect, useState } from "react";
import { fetchScanHistory, fetchThreatFeedHistory, type HistoryResponse } from "../api/client";

function HistoryPanel({ title, data }: { title: string; data: HistoryResponse | null }) {
  return (
    <section className="history-panel panel-reveal">
      <h3>{title}</h3>
      <p className="muted-text">Entries: {data?.count ?? 0}</p>
      <pre>{JSON.stringify(data?.items ?? [], null, 2)}</pre>
    </section>
  );
}

function HistoryPage() {
  const [scanHistory, setScanHistory] = useState<HistoryResponse | null>(null);
  const [threatHistory, setThreatHistory] = useState<HistoryResponse | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let active = true;
    async function loadAll() {
      try {
        const [scans, threat] = await Promise.all([fetchScanHistory(), fetchThreatFeedHistory()]);
        if (!active) {
          return;
        }
        setScanHistory(scans);
        setThreatHistory(threat);
      } catch (err) {
        if (active) {
          setError(String(err));
        }
      }
    }

    void loadAll();
    return () => {
      active = false;
    };
  }, []);

  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">History</p>
        <h2>SQLite-backed Audit Streams</h2>
      </header>

      {error ? <p className="error-text">{error}</p> : null}

      <div className="history-grid-react">
        <HistoryPanel title="Scan History" data={scanHistory} />
        <HistoryPanel title="Threat Feed Audit History" data={threatHistory} />
      </div>
    </section>
  );
}

export default HistoryPage;