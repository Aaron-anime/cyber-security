import { Navigate, Route, Routes } from "react-router-dom";
import NavigationSidebar from "./components/NavigationSidebar";
import { useGsapAnimations } from "./hooks/useGsapAnimations";
import DashboardPage from "./pages/DashboardPage";
import ToolLibraryPage from "./pages/ToolLibraryPage";
import ThreatFeedPage from "./pages/ThreatFeedPage";
import IocReportsPage from "./pages/IocReportsPage";
import HistoryPage from "./pages/HistoryPage";

function App() {
  const { containerRef } = useGsapAnimations();

  return (
    <div ref={containerRef} className="control-center">
      <div className="light-ray-layer light-ray-layer-a" aria-hidden="true" />
      <div className="light-ray-layer light-ray-layer-b" aria-hidden="true" />

      <NavigationSidebar />

      <main className="content-shell">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/tools" element={<ToolLibraryPage />} />
          <Route path="/threat-intelligence" element={<ThreatFeedPage />} />
          <Route path="/ioc-reports" element={<IocReportsPage />} />
          <Route path="/history" element={<HistoryPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;