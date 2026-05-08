import { useState } from 'react';
import './Pa17_CcaPkcPage.css';

const API_BASE = 'http://localhost:8000';

const formatBigNum = (val) => {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return String(val);
    if (Math.abs(val) > 1e10) {
      const exp = val.toExponential(4);
      const [m, e] = exp.split('e');
      return `${m} × 10^${parseInt(e, 10)}`;
    }
    return val.toLocaleString('en-US');
  }
  return String(val);
};

export default function Pa17_CcaPkcPage() {
  // Section 1 — Malleability blocked
  const [message, setMessage] = useState(42);
  const [factor, setFactor] = useState(2);
  const [malResult, setMalResult] = useState(null);
  const [malError, setMalError] = useState(null);
  const [malLoading, setMalLoading] = useState(false);

  // Section 2 — IND-CCA2 game
  const [rounds, setRounds] = useState(20);
  const [cca2Result, setCca2Result] = useState(null);
  const [cca2Error, setCca2Error] = useState(null);
  const [cca2Loading, setCca2Loading] = useState(false);

  // Section 3 — Lineage
  const [lineage, setLineage] = useState(null);
  const [lineageError, setLineageError] = useState(null);
  const [lineageLoading, setLineageLoading] = useState(false);

  const runMalleability = async () => {
    setMalLoading(true);
    setMalError(null);
    try {
      const res = await fetch(`${API_BASE}/pa17/malleability-blocked-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message,
          factor,
          elgamal_q_bits: 63,
          rsa_bits: 512,
          hash_q_bits: 31,
          seed: 0,
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setMalResult(data.result || data);
    } catch (err) {
      setMalError(err.message);
    } finally {
      setMalLoading(false);
    }
  };

  const runCca2Game = async () => {
    setCca2Loading(true);
    setCca2Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa17/ind-cca2-game`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rounds,
          elgamal_q_bits: 63,
          rsa_bits: 512,
          hash_q_bits: 31,
          seed: 0,
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setCca2Result(data.result || data);
    } catch (err) {
      setCca2Error(err.message);
    } finally {
      setCca2Loading(false);
    }
  };

  const fetchLineage = async () => {
    setLineageLoading(true);
    setLineageError(null);
    try {
      const res = await fetch(`${API_BASE}/pa17/lineage`);
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setLineage(data.result || data);
    } catch (err) {
      setLineageError(err.message);
    } finally {
      setLineageLoading(false);
    }
  };

  // Helper: render a lineage line with colored PA#XX references
  const renderLineageLine = (line, idx) => {
    const parts = line.split(/(PA#\d+)/g);
    return (
      <div key={idx} className="lineage-line">
        {parts.map((part, j) =>
          /^PA#\d+$/.test(part)
            ? <span key={j} className="lineage-pa">{part}</span>
            : <span key={j}>{part}</span>
        )}
      </div>
    );
  };

  return (
    <div className="pa17-page">
      <header className="pa17-header">
        <h1>PA#17 — CCA-Secure PKC: Encrypt-then-Sign</h1>
        <p className="pa17-subtitle">
          PA#16's malleability attack defeated. Same Eve, same multiplicative trick — but now Bob's decryption verifies a signature on the ciphertext first. Any tamper invalidates the signature, the oracle returns ⊥, and the attack lands on nothing.
        </p>
      </header>

      {/* ============ SECTION 1: MALLEABILITY BLOCKED ============ */}
      <section className="pa17-section">
        <div className="section-head">
          <h2>1. Malleability — Defeated</h2>
          <span className="status-tag tag-secure">CCA-SECURE</span>
        </div>
        <p className="section-desc">
          Run the same factor-multiplication attack against (a) plain ElGamal from PA#16 and (b) Encrypt-then-Sign from PA#17. The plain version succumbs; the signed version rejects. Backend runs both pipelines side by side and returns the verdict for each.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Message m</span>
            <input
              type="number"
              value={message}
              onChange={(e) => setMessage(Number(e.target.value))}
              disabled={malLoading}
              className="ctrl-input"
              min={1}
            />
          </label>
          <label>
            <span className="ctrl-label">Factor</span>
            <select
              value={factor}
              onChange={(e) => setFactor(Number(e.target.value))}
              disabled={malLoading}
              className="ctrl-input"
            >
              <option value={2}>2 (double)</option>
              <option value={3}>3 (triple)</option>
              <option value={5}>5</option>
              <option value={10}>10</option>
            </select>
          </label>
          <button onClick={runMalleability} disabled={malLoading} className="btn btn-primary">
            {malLoading ? 'Running…' : malResult ? 'Run again' : 'Run the comparison'}
          </button>
        </div>

        {malError && <div className="error-box">Error: {malError}</div>}

        {malResult && (
          <>
            <div className="comparison-grid">
              {/* Plain ElGamal panel — broken */}
              <div className="card scheme-card scheme-broken">
                <div className="scheme-tag scheme-tag-broken">PLAIN ELGAMAL · PA#16</div>
                <h3>BROKEN — CCA fails</h3>
                <div className="kv">
                  <span className="key">m</span>
                  <code className="val mono">{formatBigNum(malResult.plain_elgamal_original)}</code>
                </div>
                <div className="kv">
                  <span className="key">Eve tampers ×{malResult.factor}</span>
                  <code className="val mono">c₂' = factor · c₂</code>
                </div>
                <div className="kv">
                  <span className="key">Bob decrypts to</span>
                  <code className="val mono attack-succeeded">{formatBigNum(malResult.plain_elgamal_tampered)}</code>
                </div>
                <div className="status-line broken-line">
                  ✗ Attack succeeded — Eve forced plaintext = {malResult.factor} × m
                </div>
              </div>

              <div className="comparison-glyph">vs</div>

              {/* CCA-PKC panel — secure */}
              <div className="card scheme-card scheme-secure">
                <div className="scheme-tag scheme-tag-secure">ENCRYPT-THEN-SIGN · PA#17</div>
                <h3>SECURE — CCA holds</h3>
                <div className="kv">
                  <span className="key">m</span>
                  <code className="val mono">{formatBigNum(malResult.message)}</code>
                </div>
                <div className="kv">
                  <span className="key">Honest decrypt</span>
                  <code className="val mono attack-defeated">{formatBigNum(malResult.legit_decrypt)} ✓</code>
                </div>
                <div className="kv">
                  <span className="key">Eve tampers ×{malResult.factor}</span>
                  <code className="val mono">c₂' = factor · c₂</code>
                </div>
                <div className="kv">
                  <span className="key">Verify(σ, CE') first</span>
                  <code className="val mono attack-defeated">FAIL — sig invalid</code>
                </div>
                <div className="kv">
                  <span className="key">Bob decrypts to</span>
                  <code className="val mono attack-defeated">⊥ (BOTTOM)</code>
                </div>
                <div className="status-line secure-line">
                  ✓ Attack rejected — signature caught the tamper before decrypt ran
                </div>
              </div>
            </div>

            <div className={`verdict-banner ${malResult.tampered_rejected && malResult.plain_elgamal_attack_succeeded ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {malResult.tampered_rejected && malResult.plain_elgamal_attack_succeeded
                  ? '✓ CCA-PKC blocks the malleability attack that breaks plain ElGamal'
                  : '⚠ Unexpected verdict — investigate'}
              </h3>
              <p>{malResult.security_note}</p>
              <p className="contrast-note">
                <strong>Order matters: verify-before-decrypt is non-negotiable.</strong> If you decrypt first and verify second, decryption already ran on the tampered ciphertext, leaking partial state through timing channels or error patterns. Encrypt-then-Sign with verify-first is the safer composition.
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 2: IND-CCA2 GAME ============ */}
      <section className="pa17-section">
        <div className="section-head">
          <h2>2. IND-CCA2 Game</h2>
          <span className="status-tag tag-secure">ORACLE-PROOF</span>
        </div>
        <p className="section-desc">
          The full IND-CCA2 experiment with a decryption oracle. The adversary submits modified ciphertexts to the oracle, which returns ⊥ on every tampered query. With no leverage from the oracle, advantage stays ≈ 0.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Rounds</span>
            <select
              value={rounds}
              onChange={(e) => setRounds(Number(e.target.value))}
              disabled={cca2Loading}
              className="ctrl-input"
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </label>
          <button onClick={runCca2Game} disabled={cca2Loading} className="btn btn-primary">
            {cca2Loading ? 'Running game…' : cca2Result ? 'Run again' : 'Run IND-CCA2 game'}
          </button>
        </div>

        {cca2Error && <div className="error-box">Error: {cca2Error}</div>}

        {cca2Result && (
          <>
            <div className="cca2-stats">
              <div className="stat-card">
                <div className="stat-label">Rounds</div>
                <div className="stat-value">{cca2Result.rounds}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Wins</div>
                <div className="stat-value">{cca2Result.wins}</div>
              </div>
              <div className="stat-card stat-highlight">
                <div className="stat-label">Advantage</div>
                <div className="stat-value">{cca2Result.advantage.toFixed(3)}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Oracle queries</div>
                <div className="stat-value">{cca2Result.oracle_queries}</div>
              </div>
              <div className="stat-card stat-secure-card">
                <div className="stat-label">⊥ returned</div>
                <div className="stat-value oracle-rejected">{cca2Result.oracle_rejected}/{cca2Result.oracle_queries}</div>
              </div>
            </div>

            <div className={`verdict-banner ${Math.abs(cca2Result.advantage) < 0.15 ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {Math.abs(cca2Result.advantage) < 0.15
                  ? '✓ CCA-PKC is IND-CCA2 secure — adversary advantage ≈ 0'
                  : '⚠ Anomalous advantage — try more rounds or investigate'}
              </h3>
              <p>{cca2Result.security_note}</p>
              {cca2Result.all_tampered_rejected && (
                <p className="contrast-note">
                  Every one of {cca2Result.oracle_queries} tampered ciphertexts was rejected by the oracle. The adversary ends up with the same information they started with: nothing. Advantage equals the trivial guessing rate of 1/2.
                </p>
              )}
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 3: LINEAGE ============ */}
      <section className="pa17-section">
        <div className="section-head">
          <h2>3. Lineage Chain</h2>
          <span className="status-tag tag-info">SELF-HOSTED</span>
        </div>
        <p className="section-desc">
          Every primitive PA#17 calls is your own implementation from earlier PAs — no external crypto libraries anywhere in the chain. The backend exposes the full call graph for one CCA-PKC encryption.
        </p>

        <div className="control-row">
          <button onClick={fetchLineage} disabled={lineageLoading} className="btn btn-secondary">
            {lineageLoading ? 'Loading…' : lineage ? 'Refresh' : 'Show lineage'}
          </button>
        </div>

        {lineageError && <div className="error-box">Error: {lineageError}</div>}

        {lineage && (
          <div className="lineage-display">
            <div className="lineage-tree">
              {lineage.chain.map(renderLineageLine)}
            </div>
            <div className="lineage-policy">
              <strong>Policy:</strong> {lineage.policy}
            </div>
          </div>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Encrypt-then-Sign construction</h4>
          <p>
            Setup: ElGamal keypair (pk_enc, sk_enc) for confidentiality, RSA hash-then-sign keypair (vk_sign, sk_sign) for authenticity. The two key systems are independent; sk_sign and sk_enc are different secrets held by different roles in many deployments.
          </p>
          <p>
            <strong>Encrypt:</strong> CE = ElGamal_Enc<sub>pk_enc</sub>(m); σ = Sign<sub>sk_sign</sub>(CE); send (CE, σ).
          </p>
          <p>
            <strong>Decrypt:</strong> if Verify<sub>vk_sign</sub>(CE, σ) = 0, return ⊥; else return ElGamal_Dec<sub>sk_enc</sub>(CE).
          </p>

          <h4>Why this defeats malleability</h4>
          <p>
            From PA#16: given a CCA-PKC ciphertext (CE, σ) where CE = (c₁, c₂), Eve computes CE' = (c₁, factor · c₂). The ElGamal part remains a structurally valid ciphertext that would decrypt to factor · m — but σ was the signature on CE, not CE'. The verifier hashes CE' under the signature key and finds H(CE')<sup>e</sup> ≠ σ, so verification rejects. The decryption oracle returns ⊥ before any decryption code runs. Eve learns nothing about m, and the oracle has given her no leverage.
          </p>

          <h4>CPA vs CCA in one paragraph</h4>
          <p>
            <strong>CPA-secure (PA#16):</strong> protects against passive eavesdroppers who can request encryptions but not decryptions. ElGamal achieves this under DDH.
          </p>
          <p>
            <strong>CCA2-secure (PA#17):</strong> additionally protects against adversaries with a decryption oracle for any ciphertext other than the challenge. Real systems often expose decryption-oracle behavior through padding errors, timing channels, or TLS alerts — CCA2 is what you actually need in practice. Encrypt-then-Sign achieves it by making any ciphertext that wasn't built by an sk_sign-holder decrypt to ⊥.
          </p>

          <h4>Lineage in math</h4>
          <p>
            Click "Show lineage" above to fetch the live call graph from the backend. The chain that any single CCA-PKC encryption invokes is:
          </p>
          <pre className="math-block">{`PA#17 ┬── PA#16 (ElGamal_Enc) → PA#11 (DH group) → PA#13 (Miller-Rabin)
      └── PA#15 (RSA Sign)   ┬── PA#8  (DLP hash)
                             └── PA#12 (RSA modexp) → PA#13 (Miller-Rabin)`}</pre>
          <p>
            Every step is your own implementation. PA#13 appears in two branches because both ElGamal's safe-prime generation and RSA's prime generation rely on it.
          </p>
        </div>
      </details>
    </div>
  );
}
