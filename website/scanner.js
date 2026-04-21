"use strict";

(function initScannerSimulation(globalScope) {
  const { SecurityUtils } = globalScope;
  if (!SecurityUtils) {
    throw new Error("Security utilities are not available.");
  }

  const form = document.getElementById("scannerForm");
  const targetInput = document.getElementById("targetInput");
  const profileInput = document.getElementById("profileInput");
  const portsInput = document.getElementById("portsInput");
  const output = document.getElementById("scanResultOutput");

  if (!form || !targetInput || !profileInput || !portsInput || !output) {
    return;
  }

  const RATE_WINDOW_MS = 4000;
  const MAX_ATTEMPTS = 4;
  const attempts = [];

  function allowRequest() {
    const now = Date.now();
    while (attempts.length && now - attempts[0] > RATE_WINDOW_MS) {
      attempts.shift();
    }
    if (attempts.length >= MAX_ATTEMPTS) {
      return false;
    }
    attempts.push(now);
    return true;
  }

  function parsePorts(rawValue) {
    const sanitized = SecurityUtils.sanitizeText(rawValue, 80);
    if (!sanitized) {
      return [80, 443];
    }

    const tokens = sanitized.split(",").map((t) => t.trim()).filter(Boolean);
    const valid = [];

    for (const token of tokens) {
      if (!/^\d{1,5}$/.test(token)) {
        return null;
      }
      const port = Number(token);
      if (port < 1 || port > 65535) {
        return null;
      }
      valid.push(port);
    }

    return [...new Set(valid)].slice(0, 10);
  }

  async function requestServerScan(target, profile, ports) {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        target,
        profile,
        ports,
      }),
    });

    if (!response.ok) {
      throw new Error(`Scan request failed (${response.status})`);
    }

    return response.json();
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!allowRequest()) {
      SecurityUtils.safeRender(output, "Rate limit exceeded. Wait a few seconds and retry.");
      return;
    }

    const target = SecurityUtils.sanitizeText(targetInput.value, 200);
    const profile = SecurityUtils.sanitizeText(profileInput.value, 20);
    const ports = parsePorts(portsInput.value);

    if (!SecurityUtils.isSafeUrl(target)) {
      SecurityUtils.safeRender(output, "Invalid target URL. Use http:// or https:// only.");
      return;
    }

    if (!ports) {
      SecurityUtils.safeRender(output, "Invalid ports list. Use comma-separated numbers within 1-65535.");
      return;
    }

    try {
      const result = await requestServerScan(target, profile, ports);
      SecurityUtils.safeRender(output, JSON.stringify(result, null, 2));
    } catch (error) {
      SecurityUtils.safeRender(
        output,
        JSON.stringify(
          {
            timestamp_utc: new Date().toISOString(),
            status: "error",
            message: "Unable to run server-powered scan.",
            detail: String(error),
          },
          null,
          2
        )
      );
    }
  });
})(window);
