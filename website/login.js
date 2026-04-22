"use strict";

(function initSecureLogin(globalScope) {
  const { SecurityUtils } = globalScope;
  if (!SecurityUtils) {
    throw new Error("Security utilities are not available.");
  }

  const form = document.getElementById("loginForm");
  const usernameInput = document.getElementById("usernameInput");
  const passwordInput = document.getElementById("passwordInput");
  const loginOutput = document.getElementById("loginOutput");
  const entropySummary = document.getElementById("entropySummary");
  const entropyCrackTime = document.getElementById("entropyCrackTime");
  const entropyMeterFill = document.getElementById("entropyMeterFill");

  if (!form || !usernameInput || !passwordInput || !loginOutput) {
    return;
  }

  const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;
  const RATE_WINDOW_MS = 60_000;
  const MAX_FAILED_ATTEMPTS = 5;
  const failedAttempts = [];

  function isStrongPassword(password) {
    if (password.length < 12) {
      return false;
    }
    if (!/[A-Z]/.test(password)) {
      return false;
    }
    if (!/[a-z]/.test(password)) {
      return false;
    }
    if (!/[0-9]/.test(password)) {
      return false;
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
      return false;
    }
    return true;
  }

  function lockoutActive(nowMs) {
    while (failedAttempts.length && nowMs - failedAttempts[0] > RATE_WINDOW_MS) {
      failedAttempts.shift();
    }
    return failedAttempts.length >= MAX_FAILED_ATTEMPTS;
  }

  function renderResult(payload) {
    SecurityUtils.safeRender(loginOutput, JSON.stringify(payload, null, 2));
  }

  function updateEntropyLab(passwordValue) {
    if (!entropySummary || !entropyCrackTime || !entropyMeterFill) {
      return;
    }

    const emptyState = !passwordValue;
    if (emptyState) {
      entropySummary.textContent = "Start typing to see crack-time estimates.";
      entropyCrackTime.textContent = "Estimated crack time: N/A";
      entropyMeterFill.style.width = "0%";
      entropyMeterFill.setAttribute("data-score", "0");
      return;
    }

    const evaluator = globalScope.zxcvbn;
    if (typeof evaluator !== "function") {
      entropySummary.textContent = "Entropy tool failed to load.";
      entropyCrackTime.textContent = "Estimated crack time: unavailable";
      return;
    }

    const result = evaluator(passwordValue);
    const score = Number(result.score) || 0;
    const crackTime = result.crack_times_display?.offline_slow_hashing_1e4_per_second || "unknown";
    const feedback = result.feedback?.warning || "Password strength analyzed.";

    entropySummary.textContent = `Strength score ${score}/4. ${feedback}`;
    entropyCrackTime.textContent = `Estimated crack time: ${crackTime}`;
    entropyMeterFill.style.width = `${((score + 1) / 5) * 100}%`;
    entropyMeterFill.setAttribute("data-score", String(score));
  }

  async function requestLogin(username, password) {
    const response = await fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    let body = {};
    try {
      body = await response.json();
    } catch (_err) {
      body = { error: "Unable to parse server response." };
    }

    if (!response.ok) {
      const message = body && typeof body === "object" ? body : { error: "Login failed." };
      throw {
        status: response.status,
        ...message,
      };
    }

    return body;
  }

  passwordInput.addEventListener("input", () => {
    const password = SecurityUtils.sanitizeText(passwordInput.value, 72);
    updateEntropyLab(password);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const now = Date.now();
    if (lockoutActive(now)) {
      renderResult({
        timestamp_utc: new Date().toISOString(),
        status: "blocked",
        reason: "Too many failed attempts. Try again later.",
      });
      return;
    }

    const username = SecurityUtils.sanitizeText(usernameInput.value, 32);
    const password = SecurityUtils.sanitizeText(passwordInput.value, 72);

    if (!USERNAME_RE.test(username)) {
      failedAttempts.push(now);
      renderResult({
        timestamp_utc: new Date().toISOString(),
        status: "rejected",
        reason: "Username format is invalid.",
      });
      return;
    }

    if (!isStrongPassword(password)) {
      failedAttempts.push(now);
      renderResult({
        timestamp_utc: new Date().toISOString(),
        status: "rejected",
        reason: "Password does not meet complexity policy.",
      });
      return;
    }

    try {
      const response = await requestLogin(username, password);
      renderResult({
        ...response,
        security_flags: {
          safe_rendering: true,
          username_validation: true,
          lockout_policy: true,
          server_rate_limited_login: true,
        },
      });
      form.reset();
      updateEntropyLab("");
    } catch (error) {
      failedAttempts.push(now);
      const statusCode = Number(error?.status) || 0;
      renderResult({
        timestamp_utc: new Date().toISOString(),
        status: statusCode === 429 ? "blocked" : "rejected",
        reason: String(error?.reason || error?.error || "Invalid credentials."),
        server_status_code: statusCode || "unknown",
      });
    }
  });
})(window);
