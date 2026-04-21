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

  if (!form || !usernameInput || !passwordInput || !loginOutput) {
    return;
  }

  const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;
  const RATE_WINDOW_MS = 60_000;
  const MAX_FAILED_ATTEMPTS = 5;
  const failedAttempts = [];

  const EXPECTED_USERNAME = "analyst_user";
  const EXPECTED_PASSWORD = "CyberLab#2026";

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

  function timingSafeEqual(a, b) {
    const left = String(a);
    const right = String(b);
    const max = Math.max(left.length, right.length);
    let diff = left.length ^ right.length;

    for (let i = 0; i < max; i += 1) {
      const l = i < left.length ? left.charCodeAt(i) : 0;
      const r = i < right.length ? right.charCodeAt(i) : 0;
      diff |= l ^ r;
    }

    return diff === 0;
  }

  function renderResult(payload) {
    SecurityUtils.safeRender(loginOutput, JSON.stringify(payload, null, 2));
  }

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

    const userOk = timingSafeEqual(username, EXPECTED_USERNAME);
    const passOk = timingSafeEqual(password, EXPECTED_PASSWORD);
    const success = userOk && passOk;

    if (!success) {
      failedAttempts.push(now);
      renderResult({
        timestamp_utc: new Date().toISOString(),
        status: "rejected",
        reason: "Invalid credentials.",
      });
      return;
    }

    const tokenSeed = `${username}:${new Date().toISOString()}`;
    const sessionFingerprint = await SecurityUtils.sha256Hex(tokenSeed);

    renderResult({
      timestamp_utc: new Date().toISOString(),
      status: "accepted",
      message: "Login successful (demo mode).",
      session_fingerprint: sessionFingerprint,
      security_flags: {
        safe_rendering: true,
        username_validation: true,
        lockout_policy: true,
      },
    });

    form.reset();
  });
})(window);
