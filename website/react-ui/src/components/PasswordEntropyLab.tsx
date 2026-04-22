import { useMemo, useState } from "react";

type EntropyMetrics = {
  score: number;
  entropyBits: number;
  charsetSize: number;
  crackTimeOfflineFast: string;
  crackTimeOfflineSlow: string;
  crackTimeOnlineThrottled: string;
  label: string;
  factors: string[];
};

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "instant";
  }

  const units = [
    { name: "year", value: 60 * 60 * 24 * 365 },
    { name: "day", value: 60 * 60 * 24 },
    { name: "hour", value: 60 * 60 },
    { name: "minute", value: 60 },
    { name: "second", value: 1 }
  ];

  for (const unit of units) {
    if (seconds >= unit.value) {
      const amount = seconds / unit.value;
      const rounded = amount >= 10 ? Math.round(amount) : Math.round(amount * 10) / 10;
      return `${rounded.toLocaleString()} ${unit.name}${rounded === 1 ? "" : "s"}`;
    }
  }

  return "instant";
}

function estimatePasswordMetrics(password: string): EntropyMetrics {
  if (!password) {
    return {
      score: 0,
      entropyBits: 0,
      charsetSize: 0,
      crackTimeOfflineFast: "N/A",
      crackTimeOfflineSlow: "N/A",
      crackTimeOnlineThrottled: "N/A",
      label: "Start typing to evaluate strength.",
      factors: ["No password entered yet."]
    };
  }

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);

  let charsetSize = 0;
  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasNumber) charsetSize += 10;
  if (hasSymbol) charsetSize += 32;

  charsetSize = Math.max(charsetSize, 10);

  const entropyBits = password.length * Math.log2(charsetSize);
  const guesses = Math.pow(charsetSize, password.length);
  const offlineFastSeconds = guesses / 1_000_000_000;
  const offlineSlowSeconds = guesses / 10_000;
  const onlineThrottledSeconds = guesses / 100;

  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (hasLower && hasUpper) score += 1;
  if (hasNumber) score += 1;
  if (hasSymbol) score += 1;
  score = Math.min(score, 4);

  const labels = ["Very Weak", "Weak", "Fair", "Strong", "Excellent"];
  const factors = [
    `Length: ${password.length} characters`,
    hasLower ? "Contains lowercase letters" : "Missing lowercase letters",
    hasUpper ? "Contains uppercase letters" : "Missing uppercase letters",
    hasNumber ? "Contains numbers" : "Missing numbers",
    hasSymbol ? "Contains symbols" : "Missing symbols"
  ];

  return {
    score,
    entropyBits,
    charsetSize,
    crackTimeOfflineFast: formatDuration(offlineFastSeconds),
    crackTimeOfflineSlow: formatDuration(offlineSlowSeconds),
    crackTimeOnlineThrottled: formatDuration(onlineThrottledSeconds),
    label: labels[score],
    factors
  };
}

function PasswordEntropyLab() {
  const [password, setPassword] = useState("");

  const metrics = useMemo(() => estimatePasswordMetrics(password), [password]);

  return (
    <section className="lab-module glass-panel panel-reveal">
      <header className="module-header">
        <p className="eyebrow">Password Entropy Lab</p>
        <h3>Evaluate password strength and crack-time estimates</h3>
        <p className="muted-text">
          Input stays local in the browser. The lab estimates entropy using character-set coverage,
          length, and simple attack models.
        </p>
      </header>

      <div className="lab-layout">
        <div className="lab-input-card">
          <label className="field-label" htmlFor="entropy-password-input">
            Password input
          </label>
          <input
            id="entropy-password-input"
            className="lab-input"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Type a password to score it"
            autoComplete="off"
          />

          <div
            className="entropy-meter"
            aria-label="Password strength meter"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={4}
            aria-valuenow={metrics.score}
          >
            <div className="entropy-meter-fill" style={{ width: `${(metrics.score / 4) * 100}%` }} />
          </div>

          <p className="metric-caption">
            Strength: <strong>{metrics.label}</strong> ({metrics.score}/4)
          </p>

          <div className="factor-list">
            <p className="metric-label">Why this score</p>
            <ul>
              {metrics.factors.map((factor) => (
                <li key={factor}>{factor}</li>
              ))}
            </ul>
          </div>
        </div>

        <div className="lab-results-grid">
          <article className="lab-result-card">
            <span className="metric-label">Estimated entropy</span>
            <strong className="metric-value metric-value-small">{metrics.entropyBits.toFixed(1)} bits</strong>
          </article>
          <article className="lab-result-card">
            <span className="metric-label">Charset size</span>
            <strong className="metric-value metric-value-small">{metrics.charsetSize}</strong>
          </article>
          <article className="lab-result-card">
            <span className="metric-label">Offline fast hash</span>
            <strong className="metric-value metric-value-small">{metrics.crackTimeOfflineFast}</strong>
          </article>
          <article className="lab-result-card">
            <span className="metric-label">Offline slow hash</span>
            <strong className="metric-value metric-value-small">{metrics.crackTimeOfflineSlow}</strong>
          </article>
          <article className="lab-result-card">
            <span className="metric-label">Online throttled</span>
            <strong className="metric-value metric-value-small">{metrics.crackTimeOnlineThrottled}</strong>
          </article>
          <article className="lab-result-card">
            <span className="metric-label">Assessment</span>
            <strong className="metric-value metric-value-small">{metrics.label}</strong>
          </article>
        </div>
      </div>

      <p className="module-note">
        The crack-time estimates use simplified models to illustrate relative risk, not to
        predict a precise real-world break time.
      </p>
    </section>
  );
}

export default PasswordEntropyLab;