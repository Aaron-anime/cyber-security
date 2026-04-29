"use strict";

(function initSecurityWebsite(globalScope) {
  const { SecurityUtils } = globalScope;

  if (!SecurityUtils) {
    throw new Error("Security utilities are not available.");
  }

  const form = document.getElementById("securityForm");
  const urlInput = document.getElementById("urlInput");
  const noteInput = document.getElementById("noteInput");
  const resultOutput = document.getElementById("resultOutput");
  const dashboardSummaryGrid = document.getElementById("dashboardSummaryGrid");
  const dashboardSummaryOutput = document.getElementById("dashboardSummaryOutput");
  const refreshDashboardSummary = document.getElementById("refreshDashboardSummary");
  const threatFeedOutput = document.getElementById("threatFeedOutput");
  const refreshThreatFeed = document.getElementById("refreshThreatFeed");
  const scanHistoryOutput = document.getElementById("scanHistoryOutput");
  const threatAuditHistoryOutput = document.getElementById("threatAuditHistoryOutput");
  const refreshScanHistory = document.getElementById("refreshScanHistory");
  const refreshThreatAuditHistory = document.getElementById("refreshThreatAuditHistory");
  const rayToggleBtn = document.getElementById("rayToggleBtn");
  const iocUploadForm = document.getElementById("iocUploadForm");
  const iocFileInput = document.getElementById("iocFileInput");
  const iocUploadOutput = document.getElementById("iocUploadOutput");
  const processTreeOutput = document.getElementById("processTreeOutput");
  const networkTableBody = document.getElementById("networkTableBody");
  const hashInput = document.getElementById("hashInput");
  const hashOutput = document.getElementById("hashOutput");

  if (!form || !urlInput || !noteInput || !resultOutput) {
    return;
  }

  const RATE_WINDOW_MS = 3000;
  const MAX_ATTEMPTS_IN_WINDOW = 5;
  const attempts = [];

  function enforceRateLimit(nowMs) {
    while (attempts.length && nowMs - attempts[0] > RATE_WINDOW_MS) {
      attempts.shift();
    }

    if (attempts.length >= MAX_ATTEMPTS_IN_WINDOW) {
      return false;
    }

    attempts.push(nowMs);
    return true;
  }

  // ===== TOAST NOTIFICATION SYSTEM =====
  function showToast(message, type = "info", duration = 4000) {
    const container = document.getElementById("toastContainer");
    if (!container) {
      console.warn("Toast container not found");
      return;
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    toast.textContent = message;

    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
      toast.classList.add("toast-exit");
      setTimeout(() => {
        container.removeChild(toast);
      }, 300);
    }, duration);

    return toast;
  }

  function showSpinner(element) {
    const spinner = document.createElement("div");
    spinner.className = "spinner";
    spinner.innerHTML = `
      <div class="spinner-inner">
        <div class="spinner-track"></div>
        <div class="spinner-thumb"></div>
      </div>
      <p>Processing...</p>
    `;
    element.textContent = "";
    element.appendChild(spinner);
    return spinner;
  }

  function hideSpinner(element) {
    const spinner = element.querySelector(".spinner");
    if (spinner) {
      element.removeChild(spinner);
    }
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function escapeForText(value) {
    return SecurityUtils.sanitizeText(String(value ?? ""), 500);
  }

  function renderProcessTreeNodes(parentElement, nodes, depth = 0) {
    if (!Array.isArray(nodes) || nodes.length === 0) {
      return;
    }

    const list = document.createElement("ul");
    list.className = "process-tree-list";
    list.setAttribute("data-depth", String(depth));

    for (const node of nodes) {
      const item = document.createElement("li");
      item.className = "process-tree-item";

      const title = document.createElement("div");
      title.className = "process-tree-title";
      const pid = Number(node.pid) || 0;
      const ppid = Number(node.ppid) || 0;
      title.textContent = `${escapeForText(node.name || "unknown")} (PID ${pid}, PPID ${ppid})`;
      item.appendChild(title);

      if (Array.isArray(node.cmdline) && node.cmdline.length) {
        const cmdline = document.createElement("div");
        cmdline.className = "process-tree-cmdline";
        cmdline.textContent = escapeForText(node.cmdline.join(" "));
        item.appendChild(cmdline);
      }

      renderProcessTreeNodes(item, node.children, depth + 1);
      list.appendChild(item);
    }

    parentElement.appendChild(list);
  }

  function renderProcessTree(nodes) {
    if (!processTreeOutput) {
      return;
    }

    processTreeOutput.textContent = "";
    if (!Array.isArray(nodes) || nodes.length === 0) {
      processTreeOutput.textContent = "No process tree data found in report.";
      return;
    }

    renderProcessTreeNodes(processTreeOutput, nodes);
  }

  function renderFlaggedNetworkRows(rows) {
    if (!networkTableBody) {
      return;
    }

    networkTableBody.textContent = "";
    if (!Array.isArray(rows) || rows.length === 0) {
      const emptyRow = document.createElement("tr");
      const emptyCell = document.createElement("td");
      emptyCell.colSpan = 6;
      emptyCell.textContent = "No flagged connections found.";
      emptyRow.appendChild(emptyCell);
      networkTableBody.appendChild(emptyRow);
      return;
    }

    for (const row of rows) {
      const tr = document.createElement("tr");
      const cells = [
        escapeForText(row.timestamp_utc || ""),
        `${escapeForText(row.process_name || "unknown")} (#${Number(row.pid) || 0})`,
        `${escapeForText(row.remote_ip || "")} : ${Number(row.remote_port) || 0}`,
        escapeForText(row.protocol || ""),
        escapeForText(row.status || ""),
        escapeForText(row.reason || ""),
      ];

      for (const value of cells) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }
      networkTableBody.appendChild(tr);
    }
  }

  function renderIocDashboard(reportPayload) {
    renderProcessTree(reportPayload?.process_tree || []);
    renderFlaggedNetworkRows(reportPayload?.flagged_network_connections || []);
  }

  function renderSummaryCard(label, value, detail, tone = "default") {
    const card = document.createElement("article");
    card.className = `summary-card ${tone}`;

    const heading = document.createElement("span");
    heading.className = "summary-card-label";
    heading.textContent = label;

    const metric = document.createElement("strong");
    metric.className = "summary-card-value";
    metric.textContent = value;

    const supporting = document.createElement("p");
    supporting.className = "summary-card-detail";
    supporting.textContent = detail;

    card.appendChild(heading);
    card.appendChild(metric);
    card.appendChild(supporting);
    return card;
  }

  function renderDashboardSummary(summaryPayload) {
    if (dashboardSummaryGrid) {
      dashboardSummaryGrid.textContent = "";

      const counts = summaryPayload?.counts || {};
      const latest = summaryPayload?.latest || {};
      const latestScan = latest.scan || {};
      const latestAudit = latest.threat_feed_audit || {};
      const latestIoc = latest.ioc_report || {};

      dashboardSummaryGrid.appendChild(
        renderSummaryCard(
          "Stored scans",
          String(counts.scan_history ?? 0),
          latestScan.scan_id ? `Latest scan: ${latestScan.scan_id}` : "No scan history yet.",
          "accent"
        )
      );
      dashboardSummaryGrid.appendChild(
        renderSummaryCard(
          "Threat audits",
          String(counts.threat_feed_audits ?? 0),
          latestAudit.source ? `Latest source: ${latestAudit.source}` : "No threat audits yet.",
          "warning"
        )
      );
      dashboardSummaryGrid.appendChild(
        renderSummaryCard(
          "IOC reports",
          String(counts.ioc_reports ?? 0),
          latestIoc.source_name ? `Latest report: ${latestIoc.source_name}` : "No IOC reports yet.",
          "success"
        )
      );
      dashboardSummaryGrid.appendChild(
        renderSummaryCard(
          "Freshness",
          summaryPayload?.fetched_at_utc ? "Live" : "Unknown",
          summaryPayload?.fetched_at_utc ? `Updated at ${summaryPayload.fetched_at_utc}` : "Snapshot not loaded.",
          "neutral"
        )
      );
    }

    if (dashboardSummaryOutput) {
      SecurityUtils.safeRender(dashboardSummaryOutput, JSON.stringify(summaryPayload, null, 2));
    }
  }

  function setRayMode(enabled) {
    document.body.classList.toggle("rays-off", !enabled);
    if (rayToggleBtn) {
      rayToggleBtn.textContent = enabled ? "Light Rays: ON" : "Light Rays: OFF";
      rayToggleBtn.setAttribute("aria-pressed", String(!enabled));
    }
  }

  function initRayToggle() {
    if (!rayToggleBtn) {
      return;
    }

    const saved = globalScope.localStorage.getItem("cyber_light_rays");
    const initialEnabled = saved !== "off";
    setRayMode(initialEnabled);

    rayToggleBtn.addEventListener("click", () => {
      const currentlyEnabled = !document.body.classList.contains("rays-off");
      const nextEnabled = !currentlyEnabled;
      setRayMode(nextEnabled);
      globalScope.localStorage.setItem("cyber_light_rays", nextEnabled ? "on" : "off");
    });
  }

  async function loadThreatFeed() {
    if (!threatFeedOutput) {
      return;
    }

    try {
      const response = await fetch("/api/threat-feed", {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Threat feed request failed (${response.status})`);
      }

      const data = await response.json();
      SecurityUtils.safeRender(threatFeedOutput, JSON.stringify(data, null, 2));
    } catch (error) {
      SecurityUtils.safeRender(
        threatFeedOutput,
        JSON.stringify(
          {
            fetched_at_utc: nowIso(),
            error: "Unable to load threat feed from backend API.",
            detail: String(error),
          },
          null,
          2
        )
      );
    }
  }

  async function loadScanHistory() {
    if (!scanHistoryOutput) {
      return;
    }

    try {
      const response = await fetch("/api/history/scans", {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Scan history request failed (${response.status})`);
      }

      const data = await response.json();
      SecurityUtils.safeRender(scanHistoryOutput, JSON.stringify(data, null, 2));
    } catch (error) {
      SecurityUtils.safeRender(
        scanHistoryOutput,
        JSON.stringify(
          {
            fetched_at_utc: nowIso(),
            error: "Unable to load scan history from backend API.",
            detail: String(error),
          },
          null,
          2
        )
      );
    }
  }

  async function loadThreatAuditHistory() {
    if (!threatAuditHistoryOutput) {
      return;
    }

    try {
      const response = await fetch("/api/history/threat-feed", {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Threat audit history request failed (${response.status})`);
      }

      const data = await response.json();
      SecurityUtils.safeRender(threatAuditHistoryOutput, JSON.stringify(data, null, 2));
    } catch (error) {
      SecurityUtils.safeRender(
        threatAuditHistoryOutput,
        JSON.stringify(
          {
            fetched_at_utc: nowIso(),
            error: "Unable to load threat audit history from backend API.",
            detail: String(error),
          },
          null,
          2
        )
      );
    }
  }

  async function loadDashboardSummary() {
    if (!dashboardSummaryOutput) {
      return;
    }

    try {
      const response = await fetch("/api/dashboard/summary", {
        method: "GET",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Dashboard summary request failed (${response.status})`);
      }

      const data = await response.json();
      renderDashboardSummary(data);
    } catch (error) {
      renderDashboardSummary({
        fetched_at_utc: nowIso(),
        error: "Unable to load operational snapshot from backend API.",
        detail: String(error),
      });
    }
  }

  async function loadLatestIocReport() {
    if (!iocUploadOutput) {
      return;
    }

    try {
      const response = await fetch("/api/reports/latest", {
        method: "GET",
        headers: { Accept: "application/json" },
      });

      if (response.status === 404) {
        iocUploadOutput.textContent = "";
        const emptyState = document.createElement("div");
        emptyState.className = "empty-state";
        emptyState.innerHTML = `
          <p class="empty-icon">📋</p>
          <p>No IOC reports uploaded yet. Upload a report to get started.</p>
        `;
        iocUploadOutput.appendChild(emptyState);
        renderIocDashboard({ process_tree: [], flagged_network_connections: [] });
        return;
      }

      if (!response.ok) {
        throw new Error(`Latest IOC request failed (${response.status})`);
      }

      const data = await response.json();
      renderIocDashboard(data);
      
      const infoCard = document.createElement("div");
      infoCard.className = "ioc-info-card";
      infoCard.innerHTML = `
        <h3>Latest IOC Report</h3>
        <div class="ioc-info-grid">
          <div><strong>Report ID:</strong> ${SecurityUtils.escapeHtml(data.id || "N/A")}</div>
          <div><strong>Source:</strong> ${SecurityUtils.escapeHtml(data.source_name || "Unknown")}</div>
          <div><strong>Uploaded:</strong> ${SecurityUtils.escapeHtml(data.uploaded_at_utc || "Unknown")}</div>
          <div><strong>Processes:</strong> ${Number(data.process_count) || 0}</div>
          <div><strong>Flagged Connections:</strong> ${Number(data.flagged_connection_count) || 0}</div>
        </div>
      `;
      iocUploadOutput.textContent = "";
      iocUploadOutput.appendChild(infoCard);
    } catch (error) {
      const errorCard = document.createElement("div");
      errorCard.className = "error-card";
      errorCard.innerHTML = `
        <h3>Error Loading IOC Report</h3>
        <p>${SecurityUtils.escapeHtml(String(error))}</p>
      `;
      iocUploadOutput.textContent = "";
      iocUploadOutput.appendChild(errorCard);
    }
  }

  async function uploadIocReport(file) {
    const formData = new FormData();
    formData.append("report", file);

    const response = await fetch("/api/upload-report", {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`IOC upload failed (${response.status})`);
    }

    return response.json();
  }

  let hashTimer = null;
  
  function renderHashResults(data) {
    if (!hashOutput) {
      return;
    }

    const hashTable = document.createElement("div");
    hashTable.className = "hash-results";

    if (data.error) {
      hashTable.innerHTML = `
        <div class="error-card">
          <p>Error: ${SecurityUtils.escapeHtml(String(data.error))}</p>
        </div>
      `;
      hashOutput.textContent = "";
      hashOutput.appendChild(hashTable);
      return;
    }

    const content = document.createElement("div");
    content.className = "hash-grid";

    const hashes = [
      { name: "SHA-256", value: data.sha256 },
      { name: "SHA-512", value: data.sha512 },
      { name: "MD5", value: data.md5 },
      { name: "BLAKE3", value: data.blake3 },
    ];

    for (const hash of hashes) {
      if (hash.value) {
        const card = document.createElement("div");
        card.className = "hash-card";
        card.innerHTML = `
          <div class="hash-algorithm">${SecurityUtils.escapeHtml(hash.name)}</div>
          <div class="hash-value" title="${SecurityUtils.escapeHtml(hash.value)}">
            ${SecurityUtils.escapeHtml(hash.value)}
          </div>
          <button type="button" class="copy-btn" data-value="${SecurityUtils.escapeHtml(hash.value)}" aria-label="Copy ${hash.name}">
            Copy
          </button>
        `;
        content.appendChild(card);
      }
    }

    hashTable.appendChild(content);
    hashOutput.textContent = "";
    hashOutput.appendChild(hashTable);

    // Add copy functionality
    const copyButtons = hashTable.querySelectorAll(".copy-btn");
    for (const btn of copyButtons) {
      btn.addEventListener("click", () => {
        const value = btn.getAttribute("data-value");
        navigator.clipboard.writeText(value).then(() => {
          showToast("Hash copied to clipboard!", "success");
          btn.textContent = "Copied!";
          setTimeout(() => {
            btn.textContent = "Copy";
          }, 2000);
        });
      });
    }
  }

  async function fetchHashes(inputValue) {
    if (!hashOutput) {
      return;
    }

    try {
      const response = await fetch("/api/hash", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ value: inputValue }),
      });

      if (!response.ok) {
        throw new Error(`Hash request failed (${response.status})`);
      }

      const data = await response.json();
      renderHashResults(data);
    } catch (error) {
      renderHashResults({
        timestamp_utc: nowIso(),
        status: "error",
        error: String(error),
      });
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const current = Date.now();
    if (!enforceRateLimit(current)) {
      SecurityUtils.safeRender(
        resultOutput,
        "Too many requests. Please wait a few seconds and try again."
      );
      return;
    }

    const url = SecurityUtils.sanitizeText(urlInput.value, 200);
    const note = SecurityUtils.sanitizeText(noteInput.value, 300);

    if (!SecurityUtils.isSafeUrl(url)) {
      SecurityUtils.safeRender(
        resultOutput,
        "Blocked: URL is invalid or uses an unsafe scheme. Allowed: http, https."
      );
      return;
    }

    const escapedNote = SecurityUtils.escapeHtml(note);
    const noteHash = await SecurityUtils.sha256Hex(escapedNote);

    const payload = {
      checked_at_utc: nowIso(),
      url,
      url_status: "accepted",
      note_preview: escapedNote,
      note_sha256: noteHash,
      security_flags: {
        csp_expected: true,
        escaped_rendering: true,
        rate_limited_form: true,
      },
    };

    SecurityUtils.safeRender(resultOutput, JSON.stringify(payload, null, 2));
  });

  if (refreshThreatFeed && threatFeedOutput) {
    refreshThreatFeed.addEventListener("click", async () => {
      const current = Date.now();
      if (!enforceRateLimit(current)) {
        SecurityUtils.safeRender(
          threatFeedOutput,
          "Too many feed refresh requests. Please wait and retry."
        );
        return;
      }
      await loadThreatFeed();
    });
    void loadThreatFeed();
  }

  if (refreshScanHistory && scanHistoryOutput) {
    refreshScanHistory.addEventListener("click", async () => {
      const current = Date.now();
      if (!enforceRateLimit(current)) {
        SecurityUtils.safeRender(
          scanHistoryOutput,
          "Too many scan history refresh requests. Please wait and retry."
        );
        return;
      }
      await loadScanHistory();
    });
    void loadScanHistory();
  }

  if (refreshThreatAuditHistory && threatAuditHistoryOutput) {
    refreshThreatAuditHistory.addEventListener("click", async () => {
      const current = Date.now();
      if (!enforceRateLimit(current)) {
        SecurityUtils.safeRender(
          threatAuditHistoryOutput,
          "Too many audit history refresh requests. Please wait and retry."
        );
        return;
      }
      await loadThreatAuditHistory();
    });
    void loadThreatAuditHistory();
  }

  if (refreshDashboardSummary && dashboardSummaryOutput) {
    refreshDashboardSummary.addEventListener("click", async () => {
      const current = Date.now();
      if (!enforceRateLimit(current)) {
        renderDashboardSummary({
          fetched_at_utc: nowIso(),
          error: "Too many snapshot refresh requests. Please wait and retry.",
        });
        return;
      }
      await loadDashboardSummary();
    });
    void loadDashboardSummary();
  }

  if (iocUploadForm && iocFileInput && iocUploadOutput) {
    iocUploadForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const current = Date.now();
      if (!enforceRateLimit(current)) {
        showToast("Too many upload attempts. Please wait and retry.", "error");
        return;
      }

      const file = iocFileInput.files && iocFileInput.files[0];
      if (!file) {
        showToast("Please select a JSON IOC report file before uploading.", "warning");
        return;
      }

      // Show loading spinner
      showSpinner(iocUploadOutput);

      try {
        const result = await uploadIocReport(file);
        hideSpinner(iocUploadOutput);
        
        // Render the IOC dashboard data
        renderIocDashboard(result);
        
        // Display upload success info as a structured card
        const successCard = document.createElement("div");
        successCard.className = "upload-success-card";
        successCard.innerHTML = `
          <div class="success-icon">✓</div>
          <h3>IOC Report Uploaded Successfully</h3>
          <div class="success-details">
            <p><strong>Report ID:</strong> ${SecurityUtils.escapeHtml(result.id || "N/A")}</p>
            <p><strong>Source:</strong> ${SecurityUtils.escapeHtml(result.source_name || "Unknown")}</p>
            <p><strong>Uploaded:</strong> ${SecurityUtils.escapeHtml(result.uploaded_at_utc || "Unknown")}</p>
            <p><strong>Processes Found:</strong> ${Number(result.process_count) || 0}</p>
            <p><strong>Flagged Connections:</strong> ${Number(result.flagged_connection_count) || 0}</p>
          </div>
        `;
        iocUploadOutput.textContent = "";
        iocUploadOutput.appendChild(successCard);
        
        showToast("IOC report uploaded successfully!", "success");
        iocFileInput.value = ""; // Clear file input
      } catch (error) {
        hideSpinner(iocUploadOutput);
        
        const errorCard = document.createElement("div");
        errorCard.className = "upload-error-card";
        errorCard.innerHTML = `
          <div class="error-icon">✕</div>
          <h3>Upload Failed</h3>
          <p>${SecurityUtils.escapeHtml(String(error))}</p>
        `;
        iocUploadOutput.textContent = "";
        iocUploadOutput.appendChild(errorCard);
        
        showToast("Failed to upload IOC report. See details above.", "error");
      }
    });

    void loadLatestIocReport();
  }

  if (hashInput && hashOutput) {
    hashInput.addEventListener("input", () => {
      const clean = SecurityUtils.sanitizeText(hashInput.value, 1000);
      if (!clean) {
        const emptyState = document.createElement("div");
        emptyState.className = "empty-state";
        emptyState.innerHTML = `<p>Start typing to generate hashes...</p>`;
        hashOutput.textContent = "";
        hashOutput.appendChild(emptyState);
        return;
      }

      if (hashTimer) {
        globalScope.clearTimeout(hashTimer);
      }
      hashTimer = globalScope.setTimeout(() => {
        void fetchHashes(clean);
      }, 220);
    });
  }

  initRayToggle();
})(window);
