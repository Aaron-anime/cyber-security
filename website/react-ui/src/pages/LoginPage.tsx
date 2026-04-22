import { type FormEvent, useMemo, useState } from "react";
import { submitLogin } from "../api/client";

function evaluatePassword(password: string) {
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);

  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (hasLower && hasUpper) score += 1;
  if (hasNumber) score += 1;
  if (hasSymbol) score += 1;

  const summary =
    score >= 4 ? "Strong password profile" : score >= 3 ? "Improving" : "Needs more complexity";
  const crackTime = password ? (score >= 4 ? "centuries" : score >= 3 ? "months" : score >= 2 ? "hours" : "minutes") : "N/A";

  return {
    score: Math.min(score, 4),
    summary,
    crackTime
  };
}

function LoginPage() {
  const [username, setUsername] = useState("analyst_user");
  const [password, setPassword] = useState("CyberLab#2026");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [failedAttempts, setFailedAttempts] = useState<number[]>([]);

  const strength = useMemo(() => evaluatePassword(password), [password]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const now = Date.now();
    const recentAttempts = failedAttempts.filter((attempt) => now - attempt < 60_000);
    if (recentAttempts.length >= 5) {
      setError("Too many failed attempts. Try again later.");
      return;
    }

    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
      setFailedAttempts([...recentAttempts, now]);
      setError("Username format is invalid.");
      return;
    }

    if (strength.score < 3) {
      setFailedAttempts([...recentAttempts, now]);
      setError("Password does not meet complexity policy.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const data = await submitLogin(username.trim(), password);
      setResult({
        ...data,
        security_flags: {
          safe_rendering: true,
          username_validation: true,
          lockout_policy: true,
          server_rate_limited_login: true
        }
      });
      setPassword("");
    } catch (err) {
      setFailedAttempts([...recentAttempts, now]);
      setResult(null);
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">Login Demo</p>
        <h2>Secure Client-Side Authentication</h2>
        <p className="muted-text">Validation, lockout-style throttling, and safe server response rendering.</p>
      </header>

      <div className="hero-grid">
        <form className="utility-form glass-panel" onSubmit={handleSubmit}>
          <label className="field-label" htmlFor="login-username">
            Username
          </label>
          <input
            id="login-username"
            className="lab-input"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="analyst_user"
            autoComplete="username"
            maxLength={32}
            required
          />

          <label className="field-label" htmlFor="login-password">
            Password
          </label>
          <input
            id="login-password"
            className="lab-input"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="StrongPassword123!"
            autoComplete="current-password"
            maxLength={72}
            required
          />

          <div className="entropy-box glass-panel">
            <h3>Password Entropy Lab</h3>
            <p className="inline-note">Strength score {strength.score}/4. {strength.summary}</p>
            <div
              className="entropy-meter"
              role="progressbar"
              aria-label="Password strength"
              aria-valuemin={0}
              aria-valuemax={4}
              aria-valuenow={strength.score}
            >
              <div className="entropy-meter-fill" style={{ width: `${((strength.score + 1) / 5) * 100}%` }} />
            </div>
            <p className="inline-note">Estimated crack time: {strength.crackTime}</p>
          </div>

          <button className="tool-action" type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div className="result glass-panel">
          <h3>Auth Result</h3>
          {error ? <p className="error-text">{error}</p> : null}
          <pre>{result ? JSON.stringify(result, null, 2) : "Awaiting login input..."}</pre>
        </div>
      </div>
    </section>
  );
}

export default LoginPage;