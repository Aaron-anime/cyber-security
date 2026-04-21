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

  function mockThreatFeedApi() {
    // Simulate a local API call with static indicators.
    const data = {
      fetched_at_utc: nowIso(),
      source: "mock-local-feed",
      indicators: [
        {
          type: "ip",
          value: "185.199.108.153",
          severity: "high",
          label: "Known C2 infrastructure",
        },
        {
          type: "domain",
          value: "update-check-secure.net",
          severity: "medium",
          label: "Suspicious updater domain",
        },
        {
          type: "hash_sha256",
          value: "8b8c740bb7f4f4f9187a5ee4b6fce1a3a6764b64f2fcae5abf2527be13d7f3e7",
          severity: "high",
          label: "Malware sample fingerprint",
        },
      ],
    };

    return new Promise((resolve) => {
      setTimeout(() => resolve(data), 300);
    });
  }

  async function loadThreatFeed() {
    if (!threatFeedOutput) {
      return;
    }

    const data = await mockThreatFeedApi();
    SecurityUtils.safeRender(threatFeedOutput, JSON.stringify(data, null, 2));
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
})(window);
