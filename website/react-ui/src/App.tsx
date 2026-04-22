import { Navigate, Route, Routes } from "react-router-dom";
import ControlCenterLayout from "./components/ControlCenterLayout";
import { useGsapAnimations } from "./hooks/useGsapAnimations";
import DashboardPage from "./pages/DashboardPage";
import ToolLibraryPage from "./pages/ToolLibraryPage";
import ThreatFeedPage from "./pages/ThreatFeedPage";
import IocReportsPage from "./pages/IocReportsPage";
import HistoryPage from "./pages/HistoryPage";

function App() {
  const { rootRef, lightRayARef, lightRayBRef } = useGsapAnimations();

  return (
    <ControlCenterLayout rootRef={rootRef} lightRayARef={lightRayARef} lightRayBRef={lightRayBRef}>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/tools" element={<ToolLibraryPage />} />
        <Route path="/threat-intelligence" element={<ThreatFeedPage />} />
        <Route path="/ioc-reports" element={<IocReportsPage />} />
        <Route path="/history" element={<HistoryPage />} />
      </Routes>
    </ControlCenterLayout>
  );
}

export default App;