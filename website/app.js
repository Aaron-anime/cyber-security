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
        SecurityUtils.safeRender(iocUploadOutput, "No IOC reports uploaded yet.");
        renderIocDashboard({ process_tree: [], flagged_network_connections: [] });
        return;
      }

      if (!response.ok) {
        throw new Error(`Latest IOC request failed (${response.status})`);
      }

      const data = await response.json();
      renderIocDashboard(data);
      SecurityUtils.safeRender(
        iocUploadOutput,
        JSON.stringify(
          {
            status: "loaded",
            report_id: data.id,
            source_name: data.source_name,
            uploaded_at_utc: data.uploaded_at_utc,
            process_count: data.process_count,
            flagged_connection_count: data.flagged_connection_count,
          },
          null,
          2
        )
      );
    } catch (error) {
      SecurityUtils.safeRender(
        iocUploadOutput,
        JSON.stringify(
          {
            fetched_at_utc: nowIso(),
            error: "Unable to load latest IOC report.",
            detail: String(error),
          },
          null,
          2
        )
      );
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
      SecurityUtils.safeRender(hashOutput, JSON.stringify(data, null, 2));
    } catch (error) {
      SecurityUtils.safeRender(
        hashOutput,
        JSON.stringify(
          {
            timestamp_utc: nowIso(),
            status: "error",
            detail: String(error),
          },
          null,
          2
        )
      );
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

  if (iocUploadForm && iocFileInput && iocUploadOutput) {
    iocUploadForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const current = Date.now();
      if (!enforceRateLimit(current)) {
        SecurityUtils.safeRender(
          iocUploadOutput,
          "Too many IOC upload attempts. Please wait and retry."
        );
        return;
      }

      const file = iocFileInput.files && iocFileInput.files[0];
      if (!file) {
        SecurityUtils.safeRender(iocUploadOutput, "Select a JSON IOC report file before uploading.");
        return;
      }

      try {
        const result = await uploadIocReport(file);
        renderIocDashboard(result);
        SecurityUtils.safeRender(iocUploadOutput, JSON.stringify(result, null, 2));
      } catch (error) {
        SecurityUtils.safeRender(
          iocUploadOutput,
          JSON.stringify(
            {
              uploaded_at_utc: nowIso(),
              status: "error",
              message: "Unable to upload IOC report.",
              detail: String(error),
            },
            null,
            2
          )
        );
      }
    });

    void loadLatestIocReport();
  }

  if (hashInput && hashOutput) {
    hashInput.addEventListener("input", () => {
      const clean = SecurityUtils.sanitizeText(hashInput.value, 1000);
      if (!clean) {
        SecurityUtils.safeRender(hashOutput, "Start typing to generate hashes...");
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
