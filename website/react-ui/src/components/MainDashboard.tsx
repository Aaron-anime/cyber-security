const metrics = [
  { label: "Live Threat Indicators", value: "128", trend: "+12%" },
  { label: "Flagged Connections", value: "37", trend: "+4%" },
  { label: "IOC Uploads (24h)", value: "19", trend: "+22%" },
  { label: "Scan Requests Blocked", value: "54", trend: "+31%" }
];

function MainDashboard() {
  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">Main Dashboard</p>
        <h2>Cyber Security Control Center</h2>
        <p className="muted-text">
          Phase 1 React refactor with GSAP animation hooks and component architecture.
        </p>
      </header>

      <div className="metric-grid">
        {metrics.map((metric) => (
          <article key={metric.label} className="metric-card panel-reveal">
            <p className="metric-label">{metric.label}</p>
            <p className="metric-value">{metric.value}</p>
            <p className="metric-trend">{metric.trend}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export default MainDashboard;