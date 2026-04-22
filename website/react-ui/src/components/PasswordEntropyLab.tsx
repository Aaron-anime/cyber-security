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

type AttackProfile = {
  label: string;
  rate: number;
  description: string;
};

const ATTACK_PROFILES: AttackProfile[] = [
  {
    label: "Offline fast",
    rate: 10_000_000_000,
    description: "A modern GPU cluster against a fast hash"
  },
  {
    label: "Offline slow",
    rate: 10_000,
    description: "A slower hash that forces more work per guess"
  },
  {
    label: "Online throttled",
    rate: 100,
    description: "A login form protected by rate limiting"
  }
];

const SECONDS_PER_MINUTE = 60;
const SECONDS_PER_HOUR = SECONDS_PER_MINUTE * 60;
const SECONDS_PER_DAY = SECONDS_PER_HOUR * 24;
const SECONDS_PER_YEAR = SECONDS_PER_DAY * 365.25;

function formatDurationFromLog10Seconds(log10Seconds: number) {
  if (!Number.isFinite(log10Seconds)) {
    return "N/A";
  }

  if (log10Seconds < -3) {
    return "under 1 millisecond";
  }

  if (log10Seconds < 0) {
    return "under 1 second";
  }

  if (log10Seconds < Math.log10(SECONDS_PER_MINUTE)) {
    const seconds = Math.pow(10, log10Seconds);
    return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds).toLocaleString()} second${
      seconds === 1 ? "" : "s"
    }`;
  }

  if (log10Seconds < Math.log10(SECONDS_PER_HOUR)) {
    const minutes = Math.pow(10, log10Seconds - Math.log10(SECONDS_PER_MINUTE));
    return `${minutes < 10 ? minutes.toFixed(1) : Math.round(minutes).toLocaleString()} minute${
      minutes === 1 ? "" : "s"
    }`;
  }

  if (log10Seconds < Math.log10(SECONDS_PER_DAY)) {
    const hours = Math.pow(10, log10Seconds - Math.log10(SECONDS_PER_HOUR));
    return `${hours < 10 ? hours.toFixed(1) : Math.round(hours).toLocaleString()} hour${hours === 1 ? "" : "s"}`;
  }

  if (log10Seconds < Math.log10(SECONDS_PER_YEAR)) {
    const days = Math.pow(10, log10Seconds - Math.log10(SECONDS_PER_DAY));
    return `${days < 10 ? days.toFixed(1) : Math.round(days).toLocaleString()} day${days === 1 ? "" : "s"}`;
  }

  if (log10Seconds < 15) {
    const years = Math.pow(10, log10Seconds - Math.log10(SECONDS_PER_YEAR));
    return `${years < 10 ? years.toFixed(1) : Math.round(years).toLocaleString()} year${years === 1 ? "" : "s"}`;
  }

  const exponent = Math.floor(log10Seconds);
  const mantissa = Math.pow(10, log10Seconds - exponent);
  return `~${mantissa.toFixed(2)}e${exponent} seconds`;
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

  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (hasLower && hasUpper) score += 1;
  if (hasNumber) score += 1;
  if (hasSymbol) score += 1;
  score = Math.min(score, 4);

  const labels = ["Very Weak", "Weak", "Fair", "Strong", "Excellent"];
  const log10Guesses = entropyBits * Math.LOG10E * Math.log(2);
  const attackTimes = ATTACK_PROFILES.map((profile) => {
    const log10Seconds = log10Guesses - Math.log10(profile.rate);
    return `${profile.label}: ${formatDurationFromLog10Seconds(log10Seconds)}`;
  });
  const factors = [
    `Length: ${password.length} characters`,
    hasLower ? "Contains lowercase letters" : "Missing lowercase letters",
    hasUpper ? "Contains uppercase letters" : "Missing uppercase letters",
    hasNumber ? "Contains numbers" : "Missing numbers",
    hasSymbol ? "Contains symbols" : "Missing symbols",
    `Character set size: ${charsetSize}`
  ];

  return {
    score,
    entropyBits,
    charsetSize,
    crackTimeOfflineFast: attackTimes[0],
    crackTimeOfflineSlow: attackTimes[1],
    crackTimeOnlineThrottled: attackTimes[2],
    label: labels[score],
    factors
  };
}

function PasswordEntropyLab() {
  const [password, setPassword] = useState("");

  const metrics = useMemo(() => estimatePasswordMetrics(password), [password]);
  const inputSummary = useMemo(
    () => ({
      length: password.length,
      words: password.trim() ? password.trim().split(/\s+/).length : 0,
      spaces: (password.match(/\s/g) || []).length
    }),
    [password]
  );

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

          <div className="input-summary-grid" aria-label="Password summary">
            <article className="input-summary-chip">
              <span className="metric-label">Length</span>
              <strong>{inputSummary.length}</strong>
            </article>
            <article className="input-summary-chip">
              <span className="metric-label">Words</span>
              <strong>{inputSummary.words}</strong>
            </article>
            <article className="input-summary-chip">
              <span className="metric-label">Spaces</span>
              <strong>{inputSummary.spaces}</strong>
            </article>
          </div>

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

      <div className="attack-profile-strip" aria-label="Attack model assumptions">
        {ATTACK_PROFILES.map((profile) => (
          <article key={profile.label} className="attack-profile-chip">
            <span className="metric-label">{profile.label}</span>
            <strong>{profile.description}</strong>
          </article>
        ))}
      </div>

      <p className="module-note">
        The crack-time estimates use simplified models to illustrate relative risk, not to
        predict a precise real-world break time.
      </p>
    </section>
  );
}

export default PasswordEntropyLab;