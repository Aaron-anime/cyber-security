import { type FormEvent, useMemo, useState } from "react";
import { submitScan, type ScanResponse } from "../api/client";

const scanProfiles = ["quick", "standard", "deep"] as const;

function parsePorts(rawValue: string) {
  const cleaned = rawValue.trim();
  if (!cleaned) {
    return [80, 443];
  }

  const values = cleaned.split(",").map((entry) => entry.trim()).filter(Boolean);
  const ports: number[] = [];

  for (const value of values) {
    if (!/^\d{1,5}$/.test(value)) {
      return null;
    }

    const port = Number(value);
    if (port < 1 || port > 65535) {
      return null;
    }

    ports.push(port);
  }

  return [...new Set(ports)].slice(0, 10);
}

function ScannerPage() {
  const [target, setTarget] = useState("https://target.example");
  const [profile, setProfile] = useState<(typeof scanProfiles)[number]>("standard");
  const [ports, setPorts] = useState("80,443,8080");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const parsedPorts = useMemo(() => parsePorts(ports), [ports]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");

    const normalizedTarget = target.trim();
    if (!/^https?:\/\//i.test(normalizedTarget)) {
      setLoading(false);
      setError("Invalid target URL. Use http:// or https:// only.");
      return;
    }

    if (!parsedPorts) {
      setLoading(false);
      setError("Invalid ports list. Use comma-separated numbers within 1-65535.");
      return;
    }

    try {
      const data = await submitScan(normalizedTarget, profile, parsedPorts);
      setResult(data);
    } catch (err) {
      setError(String(err));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">Scanner</p>
        <h2>Vulnerability Scanner Simulation</h2>
        <p className="muted-text">Server-backed simulation with strict validation and structured findings.</p>
      </header>

      <form className="utility-form glass-panel" onSubmit={handleSubmit}>
        <label className="field-label" htmlFor="scanner-target">
          Target URL
        </label>
        <input
          id="scanner-target"
          className="lab-input"
          type="url"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          placeholder="https://target.example"
          required
        />

        <label className="field-label" htmlFor="scanner-profile">
          Scan profile
        </label>
        <select
          id="scanner-profile"
          className="lab-input"
          value={profile}
          onChange={(event) => setProfile(event.target.value as (typeof scanProfiles)[number])}
        >
          {scanProfiles.map((item) => (
            <option key={item} value={item}>
              {item.charAt(0).toUpperCase() + item.slice(1)}
            </option>
          ))}
        </select>

        <label className="field-label" htmlFor="scanner-ports">
          Ports (comma separated)
        </label>
        <input
          id="scanner-ports"
          className="lab-input"
          type="text"
          value={ports}
          onChange={(event) => setPorts(event.target.value)}
          placeholder="80,443,8080"
        />

        <p className="module-note">Only numeric ports 1-65535 are accepted.</p>
        <button className="tool-action" type="submit" disabled={loading}>
          {loading ? "Running scan..." : "Start Simulated Scan"}
        </button>
      </form>

      {error ? <p className="error-text">{error}</p> : null}

      <div className="metric-grid">
        <article className="metric-card panel-reveal">
          <p className="metric-label">Target</p>
          <p className="metric-value metric-value-small">{target}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Profile</p>
          <p className="metric-value">{profile}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Parsed Ports</p>
          <p className="metric-value">{parsedPorts?.length ?? 0}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Finding Count</p>
          <p className="metric-value">{result?.finding_count ?? 0}</p>
        </article>
      </div>

      <div className="result glass-panel">
        <h3>Scan Result</h3>
        <pre>{result ? JSON.stringify(result, null, 2) : "No scan started yet."}</pre>
      </div>
    </section>
  );
}

export default ScannerPage;