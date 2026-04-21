"use strict";

/**
 * Security utility module used by app.js.
 * These helpers enforce safe handling of user input and output.
 */
(function registerSecurityUtils(globalScope) {
  const SAFE_SCHEMES = new Set(["http:", "https:"]);

  function isSafeUrl(value) {
    try {
      const candidate = new URL(value);
      return SAFE_SCHEMES.has(candidate.protocol);
    } catch {
      return false;
    }
  }

  function sanitizeText(value, maxLength) {
    const normalized = String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, "");
    return normalized.trim().slice(0, maxLength);
  }

  function escapeHtml(value) {
    const text = String(value ?? "");
    const replacements = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };

    return text.replace(/[&<>"']/g, (char) => replacements[char]);
  }

  async function sha256Hex(value) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(String(value ?? ""));
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function safeRender(element, content) {
    if (!(element instanceof HTMLElement)) {
      return;
    }

    // Render escaped text using textContent to avoid script injection.
    element.textContent = content;
  }

  globalScope.SecurityUtils = {
    isSafeUrl,
    sanitizeText,
    escapeHtml,
    sha256Hex,
    safeRender,
  };
})(window);
