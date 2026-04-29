import { Navigate, NavLink, Route, Routes } from "react-router-dom";
import CryptographyHashGenerator from "./components/CryptographyHashGenerator";
import EventLogAnalyzer from "./components/EventLogAnalyzer";
import IocDashboard from "./components/IocDashboard";
import PasswordEntropyLab from "./components/PasswordEntropyLab";
import PrivateDnsSimulator from "./components/PrivateDnsSimulator";
import ScannerPage from "./pages/ScannerPage";
import AdvancedEventLogAnalyzer from "./components/AdvancedEventLogAnalyzer";
import YaraRuleMatcher from "./components/YaraRuleMatcher";
import AdminDashboard from "./components/AdminDashboard";
import ThreatIntelligenceFeed from "./components/ThreatIntelligenceFeed";
import DetectionRulesEngine from "./components/DetectionRulesEngine";
import ExportAndReporting from "./components/ExportAndReporting";

type SocNavItem = {
  path: string;
  label: string;
  icon: string;
  description: string;
  category?: "core" | "enhanced" | "advanced";
};

const SOC_NAV_ITEMS: SocNavItem[] = [
  {
    path: "/ioc-dashboard",
    label: "IOC Dashboard",
    icon: "01",
    description: "Parse and inspect IOC report intelligence",
    category: "core"
  },
  {
    path: "/scanner",
    label: "Vulnerability Scanner",
    icon: "02",
    description: "Simulated scan UI linked to backend route",
    category: "core"
  },
  {
    path: "/cryptography-lab",
    label: "Cryptography Lab",
    icon: "03",
    description: "Hash generation and password entropy testing",
    category: "core"
  },
  {
    path: "/event-log-analyzer",
    label: "Event Log Analyzer",
    icon: "04",
    description: "Normalize raw logs into analyst-ready events",
    category: "core"
  },
  {
    path: "/private-dns-simulator",
    label: "Private DNS Simulator",
    icon: "05",
    description: "Visual sinkhole flow for malicious domains",
    category: "core"
  },
  {
    path: "/yara-scanner",
    label: "YARA Rule Matcher",
    icon: "🔍",
    description: "Scan IOCs against YARA signatures",
    category: "enhanced"
  },
  {
    path: "/event-correlation",
    label: "Event Correlation",
    icon: "🔗",
    description: "Detect attack patterns and correlations",
    category: "enhanced"
  },
  {
    path: "/threat-feeds",
    label: "Threat Intelligence",
    icon: "📡",
    description: "Auto-ingest threat indicators",
    category: "advanced"
  },
  {
    path: "/detection-rules",
    label: "Detection Rules",
    icon: "⚔️",
    description: "Create custom alert rules",
    category: "advanced"
  },
  {
    path: "/reports",
    label: "Export & Reporting",
    icon: "📊",
    description: "Generate compliance reports",
    category: "advanced"
  },
  {
    path: "/admin",
    label: "Admin Dashboard",
    icon: "⚙️",
    description: "System health & statistics",
    category: "advanced"
  }
];

function CryptographyLabPage() {
  return (
    <section className="space-y-6">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.55)] backdrop-blur-xl">
        <p className="text-xs uppercase tracking-[0.22em] text-blue-300">Cryptography Lab</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-100">Hashing and Password Entropy Workbench</h2>
        <p className="mt-2 text-sm text-slate-300">
          Compare algorithm outputs and estimate password resilience under multiple attacker models.
        </p>
      </header>
      <CryptographyHashGenerator />
      <PasswordEntropyLab />
    </section>
  );
}

function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_15%_15%,rgba(30,64,175,0.25),transparent_45%),radial-gradient(circle_at_85%_0%,rgba(249,115,22,0.12),transparent_35%),linear-gradient(145deg,#020617,#0f172a_38%,#111827)]" />
      <div className="relative mx-auto grid min-h-screen max-w-[1700px] grid-cols-1 gap-4 p-4 lg:grid-cols-[290px_1fr]">
        <aside className="rounded-2xl border border-slate-700/60 bg-slate-900/65 p-4 shadow-[0_10px_40px_rgba(2,6,23,0.55)] backdrop-blur-xl">
          <p className="text-xs uppercase tracking-[0.25em] text-orange-300">Library of Cyber Security</p>
          <h1 className="mt-2 text-lg font-semibold text-slate-100">SOC Control Center</h1>
          <p className="mt-2 text-sm text-slate-400">Unified command view for detection, triage, analysis, and simulation.</p>

          <nav className="mt-6 space-y-3 overflow-y-auto" style={{ maxHeight: "calc(100vh - 300px)" }} aria-label="SOC modules">
            {/* Core Tools */}
            <div>
              <p className="px-3 text-xs uppercase tracking-widest text-orange-300 font-semibold mb-2">Core Tools</p>
              <div className="space-y-2">
                {SOC_NAV_ITEMS.filter((i) => i.category === "core").map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      [
                        "group flex items-start gap-3 rounded-xl border px-3 py-3 transition-all",
                        isActive
                          ? "border-blue-400/50 bg-blue-500/15 shadow-[0_0_0_1px_rgba(59,130,246,0.25)]"
                          : "border-slate-700/70 bg-slate-900/40 hover:border-orange-300/50 hover:bg-slate-800/60"
                      ].join(" ")
                    }
                  >
                    <span className="mt-0.5 inline-flex h-7 w-7 flex-none items-center justify-center rounded-md border border-slate-600 bg-slate-900 text-xs font-semibold text-orange-200">
                      {item.icon}
                    </span>
                    <span>
                      <span className="block text-sm font-medium text-slate-100">{item.label}</span>
                      <span className="mt-0.5 block text-xs text-slate-400 group-hover:text-slate-300">{item.description}</span>
                    </span>
                  </NavLink>
                ))}
              </div>
            </div>

            {/* Enhanced Tools */}
            <div>
              <p className="px-3 text-xs uppercase tracking-widest text-cyan-300 font-semibold mb-2">Enhanced</p>
              <div className="space-y-2">
                {SOC_NAV_ITEMS.filter((i) => i.category === "enhanced").map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      [
                        "group flex items-start gap-3 rounded-xl border px-3 py-3 transition-all",
                        isActive
                          ? "border-cyan-400/50 bg-cyan-500/15 shadow-[0_0_0_1px_rgba(34,211,238,0.25)]"
                          : "border-slate-700/70 bg-slate-900/40 hover:border-cyan-300/50 hover:bg-slate-800/60"
                      ].join(" ")
                    }
                  >
                    <span className="mt-0.5 text-lg">{item.icon}</span>
                    <span>
                      <span className="block text-sm font-medium text-slate-100">{item.label}</span>
                      <span className="mt-0.5 block text-xs text-slate-400 group-hover:text-slate-300">{item.description}</span>
                    </span>
                  </NavLink>
                ))}
              </div>
            </div>

            {/* Advanced Tools */}
            <div>
              <p className="px-3 text-xs uppercase tracking-widest text-purple-300 font-semibold mb-2">Advanced</p>
              <div className="space-y-2">
                {SOC_NAV_ITEMS.filter((i) => i.category === "advanced").map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      [
                        "group flex items-start gap-3 rounded-xl border px-3 py-3 transition-all",
                        isActive
                          ? "border-purple-400/50 bg-purple-500/15 shadow-[0_0_0_1px_rgba(168,85,247,0.25)]"
                          : "border-slate-700/70 bg-slate-900/40 hover:border-purple-300/50 hover:bg-slate-800/60"
                      ].join(" ")
                    }
                  >
                    <span className="mt-0.5 text-lg">{item.icon}</span>
                    <span>
                      <span className="block text-sm font-medium text-slate-100">{item.label}</span>
                      <span className="mt-0.5 block text-xs text-slate-400 group-hover:text-slate-300">{item.description}</span>
                    </span>
                  </NavLink>
                ))}
              </div>
            </div>
          </nav>
        </aside>

        <main className="space-y-4">
          <header className="flex flex-col gap-3 rounded-2xl border border-slate-700/60 bg-slate-900/65 px-5 py-4 shadow-[0_10px_40px_rgba(2,6,23,0.55)] backdrop-blur-xl md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.22em] text-blue-300">Security Operations Dashboard</p>
              <h2 className="mt-1 text-xl font-semibold text-slate-100">Analyst Workspace</h2>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="rounded-full border border-emerald-400/40 bg-emerald-500/15 px-3 py-1 font-medium text-emerald-200">
                Backend: Connected
              </span>
              <span className="rounded-full border border-orange-400/40 bg-orange-500/15 px-3 py-1 font-medium text-orange-100">
                Theme: Dark SOC
              </span>
            </div>
          </header>

          <div className="rounded-2xl border border-slate-700/60 bg-slate-900/45 p-4 shadow-[0_10px_40px_rgba(2,6,23,0.45)] backdrop-blur-xl">
            <Routes>
              <Route path="/" element={<Navigate to="/ioc-dashboard" replace />} />
              {/* Core Tools */}
              <Route path="/ioc-dashboard" element={<IocDashboard />} />
              <Route path="/scanner" element={<ScannerPage />} />
              <Route path="/cryptography-lab" element={<CryptographyLabPage />} />
              <Route path="/event-log-analyzer" element={<EventLogAnalyzer />} />
              <Route path="/private-dns-simulator" element={<PrivateDnsSimulator />} />
              {/* Enhanced Tools */}
              <Route path="/yara-scanner" element={<YaraRuleMatcher events={[]} />} />
              <Route path="/event-correlation" element={<AdvancedEventLogAnalyzer events={[]} />} />
              {/* Advanced Tools */}
              <Route path="/threat-feeds" element={<ThreatIntelligenceFeed />} />
              <Route path="/detection-rules" element={<DetectionRulesEngine />} />
              <Route path="/reports" element={<ExportAndReporting />} />
              <Route path="/admin" element={<AdminDashboard />} />
              <Route path="*" element={<Navigate to="/ioc-dashboard" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;