import { useEffect, useMemo, useState } from "react";
import MD5 from "crypto-js/md5";
import SHA1 from "crypto-js/sha1";
import SHA256 from "crypto-js/sha256";

type HashRowProps = {
  algorithm: string;
  hash: string;
  accentClass: string;
  explanation: string;
};

function HashRow({ algorithm, hash, accentClass, explanation }: HashRowProps) {
  return (
    <article className={`hash-card ${accentClass}`}>
      <span className="metric-label">{algorithm}</span>
      <code className="hash-value">{hash}</code>
      <p className="hash-explainer">{explanation}</p>
    </article>
  );
}

function CryptographyHashGenerator() {
  const [value, setValue] = useState("");
  const [copiedAlgorithm, setCopiedAlgorithm] = useState("");

  const normalized = value ?? "";
  const hashes = useMemo(
    () => ({
      md5: normalized ? MD5(normalized).toString() : "Start typing to generate hashes...",
      sha1: normalized ? SHA1(normalized).toString() : "Start typing to generate hashes...",
      sha256: normalized ? SHA256(normalized).toString() : "Start typing to generate hashes..."
    }),
    [normalized]
  );

  const inputStats = useMemo(
    () => ({
      characters: value.length,
      lines: value ? value.split(/\r?\n/).length : 0,
      words: value.trim() ? value.trim().split(/\s+/).length : 0
    }),
    [value]
  );

  useEffect(() => {
    if (!copiedAlgorithm) {
      return;
    }

    const timer = window.setTimeout(() => setCopiedAlgorithm(""), 1500);
    return () => window.clearTimeout(timer);
  }, [copiedAlgorithm]);

  async function copyHash(hash: string, algorithm: string) {
    if (!hash || hash.startsWith("Start typing")) {
      return;
    }

    try {
      await navigator.clipboard.writeText(hash);
      setCopiedAlgorithm(algorithm);
    } catch {
      setCopiedAlgorithm("Copy failed");
    }
  }

  return (
    <section className="lab-module glass-panel panel-reveal">
      <header className="module-header">
        <p className="eyebrow">Cryptography Hash Generator</p>
        <h3>Instantly compare MD5, SHA-1, and SHA-256 outputs</h3>
        <p className="muted-text">
          Useful for seeing how one-way transformations change the same input across different hash
          algorithms.
        </p>
      </header>

      <div className="lab-input-card">
        <label className="field-label" htmlFor="hash-generator-input">
          Input text
        </label>
        <textarea
          id="hash-generator-input"
          className="lab-textarea"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="Type text to hash"
          rows={4}
        />
        <div className="input-summary-grid hash-summary-grid" aria-label="Input statistics">
          <article className="input-summary-chip">
            <span className="metric-label">Characters</span>
            <strong>{inputStats.characters}</strong>
          </article>
          <article className="input-summary-chip">
            <span className="metric-label">Words</span>
            <strong>{inputStats.words}</strong>
          </article>
          <article className="input-summary-chip">
            <span className="metric-label">Lines</span>
            <strong>{inputStats.lines}</strong>
          </article>
        </div>
      </div>

      <div className="hash-grid">
        <HashRow
          algorithm="MD5"
          hash={hashes.md5}
          accentClass="hash-accent-md5"
          explanation="Fast and compact, but cryptographically broken for collision resistance."
        />
        <HashRow
          algorithm="SHA-1"
          hash={hashes.sha1}
          accentClass="hash-accent-sha1"
          explanation="Older standard with known collision attacks. Useful for legacy recognition only."
        />
        <HashRow
          algorithm="SHA-256"
          hash={hashes.sha256}
          accentClass="hash-accent-sha256"
          explanation="Modern choice for integrity checks and security-sensitive workflows."
        />
      </div>

      <div className="hash-actions">
        <button type="button" className="tool-action" onClick={() => void copyHash(hashes.md5, "MD5")}>
          Copy MD5
        </button>
        <button type="button" className="tool-action" onClick={() => void copyHash(hashes.sha1, "SHA-1")}>
          Copy SHA-1
        </button>
        <button
          type="button"
          className="tool-action"
          onClick={() => void copyHash(hashes.sha256, "SHA-256")}
        >
          Copy SHA-256
        </button>
        <span className="copy-status" aria-live="polite">
          {copiedAlgorithm ? `${copiedAlgorithm} copied.` : "Copy a hash to the clipboard."}
        </span>
      </div>

      <p className="module-note">
        All hashes are generated locally in the browser. That keeps the module deterministic and
        safe for offline training.
      </p>
    </section>
  );
}

export default CryptographyHashGenerator;