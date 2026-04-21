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
})(window);
