import { useMemo, useState } from "react";

type ReportType = "executive" | "technical" | "threat_intel" | "compliance";
type ReportFormat = "pdf" | "html" | "csv" | "json";

type ReportConfig = {
  type: ReportType;
  format: ReportFormat;
  timeRange: {
    start: string;
    end: string;
  };
  includeMetrics: boolean;
  includeFindings: boolean;
  includeRecommendations: boolean;
  includeThreatIntel: boolean;
  signature: boolean;
};

const REPORT_TEMPLATES = {
  executive: {
    name: "Executive Summary",
    description: "High-level overview for management and leadership",
    icon: "📊",
    sections: ["Statistics", "Top Threats", "Recommendations", "Risk Score"]
  },
  technical: {
    name: "Technical Deep Dive",
    description: "Detailed technical analysis for security teams",
    icon: "🔬",
    sections: ["Event Timeline", "Indicators", "Root Cause Analysis", "Detection Rules Fired"]
  },
  threat_intel: {
    name: "Threat Intelligence Report",
    description: "IOC analysis and threat landscape summary",
    icon: "🎯",
    sections: ["IOC Summary", "Threat Feeds", "YARA Matches", "Attribution"]
  },
  compliance: {
    name: "Compliance Report",
    description: "Evidence for regulatory compliance (HIPAA, PCI-DSS, SOC2)",
    icon: "✅",
    sections: ["Policy Violations", "Audit Trail", "Remediation", "Sign-off"]
  }
};

function getFormatIcon(format: ReportFormat): string {
  if (format === "pdf") return "📄";
  if (format === "html") return "🌐";
  if (format === "csv") return "📊";
  return "{ }";
}

function ExportAndReporting() {
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [reportFormat, setReportFormat] = useState<ReportFormat>("pdf");
  const [startDate, setStartDate] = useState(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0]);
  const [endDate, setEndDate] = useState(new Date().toISOString().split("T")[0]);
  const [includeMetrics, setIncludeMetrics] = useState(true);
  const [includeFindings, setIncludeFindings] = useState(true);
  const [includeRecommendations, setIncludeRecommendations] = useState(true);
  const [includeThreatIntel, setIncludeThreatIntel] = useState(true);
  const [signature, setSignature] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationStatus, setGenerationStatus] = useState("");

  const currentTemplate = REPORT_TEMPLATES[reportType];
  const selectedConfig: ReportConfig = useMemo(
    () => ({
      type: reportType,
      format: reportFormat,
      timeRange: { start: startDate, end: endDate },
      includeMetrics,
      includeFindings,
      includeRecommendations,
      includeThreatIntel,
      signature
    }),
    [reportType, reportFormat, startDate, endDate, includeMetrics, includeFindings, includeRecommendations, includeThreatIntel, signature]
  );

  async function generateReport() {
    setIsGenerating(true);
    setGenerationStatus("Generating report...");

    // Simulate report generation
    setTimeout(() => {
      const filename = `soc-report-${reportType}-${Date.now()}.${reportFormat === "pdf" ? "pdf" : reportFormat === "html" ? "html" : reportFormat === "csv" ? "csv" : "json"}`;

      // Create mock report content
      let content = "";
      if (reportFormat === "json") {
        content = JSON.stringify(selectedConfig, null, 2);
      } else if (reportFormat === "csv") {
        content = "Report Type,Format,Time Range,Generated At\n";
        content += `"${reportType}","${reportFormat}","${startDate} to ${endDate}","${new Date().toISOString()}"\n`;
      } else {
        content = `SOC Report - ${currentTemplate.name}\n\n`;
        content += `Time Range: ${startDate} to ${endDate}\n`;
        content += `Generated: ${new Date().toISOString()}\n`;
        content += `Sections: ${currentTemplate.sections.join(", ")}\n`;
      }

      // Create and download file
      const mimeType = reportFormat === "pdf" ? "application/pdf" : reportFormat === "html" ? "text/html" : reportFormat === "csv" ? "text/csv" : "application/json";
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      setGenerationStatus(`✓ Report generated: ${filename}`);
      setIsGenerating(false);
    }, 1500);
  }

  return (
    <section className="space-y-5">
      <header className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-indigo-300">Export & Reports</p>
            <h2 className="mt-2 text-2xl font-semibold text-slate-100">Report Generation Engine</h2>
            <p className="mt-2 text-sm text-slate-300">
              Generate comprehensive SOC reports in multiple formats for stakeholders and compliance audits.
            </p>
          </div>
          <button
            type="button"
            onClick={generateReport}
            disabled={isGenerating}
            className="rounded-lg border border-indigo-400/45 bg-indigo-500/20 px-4 py-2 text-sm font-semibold text-indigo-100 transition hover:bg-indigo-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isGenerating ? "Generating..." : "Generate Report"}
          </button>
        </div>
        {generationStatus && <p className="mt-3 text-xs text-slate-400">{generationStatus}</p>}
      </header>

      {/* Report Type Selection */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Report Type</h3>
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          {(Object.entries(REPORT_TEMPLATES) as const).map(([key, template]) => (
            <button
              key={key}
              type="button"
              onClick={() => setReportType(key)}
              className={`rounded-xl border p-4 text-left transition ${
                reportType === key
                  ? "border-indigo-400/60 bg-indigo-500/20 shadow-[0_0_0_1px_rgba(99,102,241,0.25)]"
                  : "border-slate-700/70 bg-slate-900/40 hover:border-indigo-300/50 hover:bg-slate-800/60"
              }`}
            >
              <p className="text-2xl">{template.icon}</p>
              <p className="mt-2 text-sm font-semibold text-slate-100">{template.name}</p>
              <p className="mt-1 text-xs text-slate-400">{template.description}</p>
            </button>
          ))}
        </div>
      </section>

      {/* Report Sections Preview */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Report Sections</h3>
        <div className="flex flex-wrap gap-2">
          {currentTemplate.sections.map((section) => (
            <span
              key={section}
              className="inline-flex rounded-full border border-indigo-400/40 bg-indigo-500/15 px-3 py-1.5 text-sm font-medium text-indigo-100"
            >
              {section}
            </span>
          ))}
        </div>
      </section>

      {/* Format & Time Range */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Format Selection */}
        <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
          <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Export Format</h3>
          <div className="space-y-2">
            {(["pdf", "html", "csv", "json"] as const).map((format) => (
              <label key={format} className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border border-slate-700/50 hover:bg-slate-800/40">
                <input
                  type="radio"
                  name="format"
                  value={format}
                  checked={reportFormat === format}
                  onChange={(e) => setReportFormat(e.target.value as ReportFormat)}
                  className="h-4 w-4"
                />
                <span className="text-lg">{getFormatIcon(format)}</span>
                <span className="text-sm font-medium text-slate-100">{format.toUpperCase()}</span>
              </label>
            ))}
          </div>
        </section>

        {/* Time Range */}
        <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
          <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Time Range</h3>
          <div className="space-y-3">
            <label className="text-sm text-slate-300">
              Start Date
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500/60"
              />
            </label>
            <label className="text-sm text-slate-300">
              End Date
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500/60"
              />
            </label>
          </div>
        </section>
      </div>

      {/* Content Options */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Content Options</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border border-slate-700/50 hover:bg-slate-800/40">
            <input
              type="checkbox"
              checked={includeMetrics}
              onChange={(e) => setIncludeMetrics(e.target.checked)}
              className="h-4 w-4"
            />
            <span className="text-sm font-medium text-slate-100">Include Metrics & Statistics</span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border border-slate-700/50 hover:bg-slate-800/40">
            <input
              type="checkbox"
              checked={includeFindings}
              onChange={(e) => setIncludeFindings(e.target.checked)}
              className="h-4 w-4"
            />
            <span className="text-sm font-medium text-slate-100">Include Findings & Alerts</span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border border-slate-700/50 hover:bg-slate-800/40">
            <input
              type="checkbox"
              checked={includeRecommendations}
              onChange={(e) => setIncludeRecommendations(e.target.checked)}
              className="h-4 w-4"
            />
            <span className="text-sm font-medium text-slate-100">Include Recommendations</span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border border-slate-700/50 hover:bg-slate-800/40">
            <input
              type="checkbox"
              checked={includeThreatIntel}
              onChange={(e) => setIncludeThreatIntel(e.target.checked)}
              className="h-4 w-4"
            />
            <span className="text-sm font-medium text-slate-100">Include Threat Intelligence</span>
          </label>
        </div>

        <div className="mt-4 border-t border-slate-700 pt-4">
          <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg border border-slate-700/50 hover:bg-slate-800/40">
            <input
              type="checkbox"
              checked={signature}
              onChange={(e) => setSignature(e.target.checked)}
              className="h-4 w-4"
            />
            <span className="text-sm font-medium text-slate-100">Include Digital Signature (for compliance)</span>
          </label>
        </div>
      </section>

      {/* Report Preview */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Report Preview</h3>
        <div className="rounded-lg border border-slate-700 bg-slate-950/80 p-4 space-y-2 text-xs text-slate-300">
          <p>
            <span className="font-semibold">Type:</span> {currentTemplate.name}
          </p>
          <p>
            <span className="font-semibold">Format:</span> {reportFormat.toUpperCase()}
          </p>
          <p>
            <span className="font-semibold">Time Range:</span> {startDate} to {endDate}
          </p>
          <p>
            <span className="font-semibold">Sections:</span> {currentTemplate.sections.join(", ")}
          </p>
          <p className="mt-3 text-slate-400">
            {`File will be generated as: soc-report-${reportType}-${new Date().toISOString().split("T")[0]}.${reportFormat}`}
          </p>
        </div>
      </section>

      {/* Recent Reports */}
      <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300">Recent Reports</h3>
        <div className="space-y-2 text-sm text-slate-300">
          <div className="flex items-center justify-between p-3 rounded-lg border border-slate-700/50 bg-slate-950/70">
            <span>📊 Executive Summary (2025-04-22)</span>
            <span className="text-xs text-slate-400">2.3 MB</span>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg border border-slate-700/50 bg-slate-950/70">
            <span>🔬 Technical Report (2025-04-20)</span>
            <span className="text-xs text-slate-400">5.8 MB</span>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg border border-slate-700/50 bg-slate-950/70">
            <span>✅ Compliance Report (2025-04-15)</span>
            <span className="text-xs text-slate-400">3.1 MB</span>
          </div>
        </div>
      </section>
    </section>
  );
}

export default ExportAndReporting;
