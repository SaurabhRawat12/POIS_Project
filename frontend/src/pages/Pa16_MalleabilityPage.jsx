import { useState } from 'react';
import './Pa16_MalleabilityPage.css';

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

export default function Pa16_MalleabilityPage() {
  // Section 1 state
  const [message, setMessage] = useState(422);
  const [factor, setFactor] = useState(2);
  const [qBits, setQBits] = useState(31);
  const [malResult, setMalResult] = useState(null);
  const [malError, setMalError] = useState(null);
  const [malLoading, setMalLoading] = useState(false);

  // Section 2 state
  const [rounds, setRounds] = useState(50);
  const [cpaResult, setCpaResult] = useState(null);
  const [cpaError, setCpaError] = useState(null);
  const [cpaLoading, setCpaLoading] = useState(false);

  const runMalleability = async () => {
    setMalLoading(true);
    setMalError(null);
    try {
      const res = await fetch(`${API_BASE}/pa16/malleability-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, factor, q_bits: qBits, k: 20 }),
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

  const runCpaGame = async () => {
    setCpaLoading(true);
    setCpaError(null);
    try {
      const res = await fetch(`${API_BASE}/pa16/ind-cpa-game`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rounds, q_bits: qBits, k: 20, strategy: 'random', seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setCpaResult(data.result || data);
    } catch (err) {
      setCpaError(err.message);
    } finally {
      setCpaLoading(false);
    }
  };

  return (
    <div className="pa16-page">
      <header className="pa16-header">
        <h1>PA#16 — ElGamal Malleability &amp; CPA Security</h1>
        <p className="pa16-subtitle">
          ElGamal is multiplicatively homomorphic. Given a ciphertext (c₁, c₂), Eve can multiply c₂ by any factor and Bob's decryption returns factor·m mod p — no private key needed. That's the CCA failure that motivates Encrypt-then-Sign (PA#17). But against passive eavesdroppers (CPA), ElGamal is secure: same scheme, two security models, opposite verdicts.
        </p>
      </header>

      {/* ============ SECTION 1: MALLEABILITY ATTACK ============ */}
      <section className="pa16-section">
        <div className="section-head">
          <h2>1. Malleability Attack</h2>
          <span className="status-tag tag-broken">CCA-BROKEN</span>
        </div>
        <p className="section-desc">
          Alice encrypts m to Bob over an insecure channel. Eve intercepts the ciphertext, multiplies c₂ by a chosen factor, forwards the result. Bob decrypts to factor·m mod p — entirely unaware.
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
              <option value={1}>1 (control)</option>
              <option value={2}>2 (double)</option>
              <option value={3}>3 (triple)</option>
              <option value={5}>5</option>
              <option value={10}>10</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">q_bits</span>
            <select
              value={qBits}
              onChange={(e) => setQBits(Number(e.target.value))}
              disabled={malLoading}
              className="ctrl-input"
            >
              <option value={31}>31</option>
              <option value={63}>63</option>
            </select>
          </label>
          <button onClick={runMalleability} disabled={malLoading} className="btn btn-attack">
            {malLoading ? 'Running attack…' : malResult ? 'Run again' : 'Run the attack'}
          </button>
        </div>

        {malError && <div className="error-box">Error: {malError}</div>}

        {malResult && (
          <>
            <div className="card pubkey-card">
              <h3>Public Key (Bob's)</h3>
              <div className="pk-grid">
                <div className="kv"><span className="key">p</span><code className="val mono">{formatBigNum(malResult.public_key.p)}</code></div>
                <div className="kv"><span className="key">q</span><code className="val mono">{formatBigNum(malResult.public_key.q)}</code></div>
                <div className="kv"><span className="key">g</span><code className="val mono">{formatBigNum(malResult.public_key.g)}</code></div>
                <div className="kv"><span className="key">h = g^x mod p</span><code className="val mono">{formatBigNum(malResult.public_key.h)}</code></div>
                <div className="kv kv-full"><span className="key">x (private)</span><code className="val key-hidden">🔒 hidden</code></div>
              </div>
            </div>

            <div className="flow-cards">
              {/* Alice */}
              <div className="card alice-card">
                <h3>Alice encrypts</h3>
                <div className="kv"><span className="key">m</span><code className="val mono">{formatBigNum(malResult.original_message)}</code></div>
                <div className="kv"><span className="key">c₁ = g^r mod p</span><code className="val mono">{formatBigNum(malResult.original_ciphertext.c1)}</code></div>
                <div className="kv"><span className="key">c₂ = m·h^r mod p</span><code className="val mono">{formatBigNum(malResult.original_ciphertext.c2)}</code></div>
                <div className="ciphertext-summary">
                  ciphertext: ({formatBigNum(malResult.original_ciphertext.c1)},&nbsp;{formatBigNum(malResult.original_ciphertext.c2)})
                </div>
              </div>

              <div className="flow-arrow">↓ ciphertext travels (insecure channel)</div>

              {/* Eve */}
              <div className={`card eve-card ${malResult.malleability_success ? 'eve-success' : 'eve-defeated'}`}>
                <h3>{malResult.malleability_success ? "Eve intercepts & tampers" : "Eve attempts tamper"}</h3>
                <div className="kv"><span className="key">factor</span><code className="val mono">×{factor}</code></div>
                <div className="kv"><span className="key">c₁' (unchanged)</span><code className="val mono">{formatBigNum(malResult.modified_ciphertext.c1)}</code></div>
                <div className="kv"><span className="key">c₂' = factor · c₂ mod p</span><code className="val mono">{formatBigNum(malResult.modified_ciphertext.c2)}</code></div>
                <div className="ciphertext-summary tampered-summary">
                  tampered: ({formatBigNum(malResult.modified_ciphertext.c1)},&nbsp;{formatBigNum(malResult.modified_ciphertext.c2)})
                </div>
                <div className="actor-note eve-note">Eve never decrypts, never sees the secret key. She just multiplies one ciphertext component by an integer.</div>
              </div>

              <div className="flow-arrow">↓ tampered ciphertext continues to Bob</div>

              {/* Bob */}
              <div className="card bob-card">
                <h3>Bob decrypts</h3>
                <div className="kv"><span className="key">received</span><code className="val mono">(c₁, c₂')</code></div>
                <div className="kv"><span className="key">m' = c₂' · (c₁^x)^(-1) mod p</span><code className="val mono">{formatBigNum(malResult.decrypted_modified)}</code></div>
                <div className="kv"><span className="key">expected (factor × m)</span><code className="val mono">{formatBigNum(malResult.expected_modified_plaintext)}</code></div>
                <div className="actor-note bob-note">Bob has no idea the ciphertext was tampered. Decryption succeeded — the structure is valid ElGamal — but the plaintext is whatever Eve chose.</div>
              </div>
            </div>

            <div className={`verdict-banner ${malResult.malleability_success ? 'verdict-broken' : 'verdict-secure'}`}>
              <h3>{malResult.malleability_success ? '✗ MALLEABILITY SUCCEEDED' : '✓ Malleability defeated'}</h3>
              <p>
                {malResult.malleability_success
                  ? <>Bob decrypts to <strong>{formatBigNum(malResult.decrypted_modified)}</strong> = {factor} × {formatBigNum(malResult.original_message)}. Eve manipulated the plaintext without ever learning m or x. ElGamal is not CCA-secure. <strong>PA#17 fixes this with Encrypt-then-Sign.</strong></>
                  : <>Unexpected — the malleability flag came back false. Investigate.</>}
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 2: IND-CPA GAME ============ */}
      <section className="pa16-section">
        <div className="section-head">
          <h2>2. IND-CPA Game</h2>
          <span className="status-tag tag-secure">CPA-SECURE</span>
        </div>
        <p className="section-desc">
          But ElGamal IS secure against passive eavesdroppers — adversaries who only see ciphertexts, with no decryption oracle. This game runs the IND-CPA experiment for many rounds and reports the adversary's win rate. Random guessing wins 50%; advantage = |win_rate − 0.5| should be ≈ 0.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Rounds</span>
            <select
              value={rounds}
              onChange={(e) => setRounds(Number(e.target.value))}
              disabled={cpaLoading}
              className="ctrl-input"
            >
              <option value={20}>20</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={500}>500</option>
            </select>
          </label>
          <button onClick={runCpaGame} disabled={cpaLoading} className="btn btn-primary">
            {cpaLoading ? 'Running game…' : cpaResult ? 'Run again' : 'Run IND-CPA game'}
          </button>
        </div>

        {cpaError && <div className="error-box">Error: {cpaError}</div>}

        {cpaResult && (
          <>
            <div className="cpa-stats">
              <div className="stat-card">
                <div className="stat-label">Rounds</div>
                <div className="stat-value">{cpaResult.rounds}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Wins</div>
                <div className="stat-value">{cpaResult.wins}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Win rate</div>
                <div className="stat-value">{(cpaResult.win_rate * 100).toFixed(1)}%</div>
              </div>
              <div className="stat-card stat-highlight">
                <div className="stat-label">Advantage</div>
                <div className="stat-value">{cpaResult.advantage.toFixed(3)}</div>
              </div>
            </div>

            <div className={`verdict-banner ${Math.abs(cpaResult.advantage) < 0.15 ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {Math.abs(cpaResult.advantage) < 0.15
                  ? '✓ ElGamal is CPA-secure — adversary advantage ≈ 0'
                  : '⚠ Anomalous advantage — try more rounds or investigate'}
              </h3>
              <p>
                Adversary won {cpaResult.wins} of {cpaResult.rounds} rounds ({(cpaResult.win_rate * 100).toFixed(1)}%). Random guessing would also win 50%. The advantage <strong>{cpaResult.advantage.toFixed(3)}</strong> should converge to 0 as you increase round count.
              </p>
              <p className="contrast-note">
                <strong>This doesn't contradict Section 1.</strong> CPA ≠ CCA: the malleability attacker had a decryption oracle, this game's adversary has only ciphertexts. ElGamal achieves the security level it claims — the level just isn't enough for many real applications.
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>ElGamal cryptosystem</h4>
          <p>
            Setup: cyclic group of prime order q with generator g modulo a safe prime p. Bob's keypair: x ← Z_q (private), h = g<sup>x</sup> mod p (public).
          </p>
          <p>
            Encryption of m: sample r ← Z_q fresh, output (c₁, c₂) = (g<sup>r</sup>, m·h<sup>r</sup>).
          </p>
          <p>
            Decryption of (c₁, c₂): m = c₂ · (c₁<sup>x</sup>)<sup>−1</sup> mod p. Why it works: c₂/c₁<sup>x</sup> = m·h<sup>r</sup>/g<sup>rx</sup> = m·g<sup>xr</sup>/g<sup>rx</sup> = m.
          </p>

          <h4>Why the malleability attack works</h4>
          <p>
            ElGamal is multiplicatively homomorphic. For any factor k:
          </p>
          <pre className="math-block">(c₁, k·c₂)  =  (g^r, k·m·h^r)  =  encryption of (k·m) under the same r</pre>
          <p>
            Eve doesn't need to know m, doesn't need x, doesn't need r. She just multiplies c₂ by k and the resulting pair is a perfectly valid ElGamal ciphertext for the new plaintext k·m. Bob's decryption recovers k·m and has no signal that anything was modified.
          </p>

          <h4>CPA vs CCA</h4>
          <p>
            <strong>IND-CPA:</strong> the adversary can request encryptions of plaintexts of their choice (a "left-or-right" oracle), but cannot decrypt. ElGamal achieves IND-CPA security under the DDH assumption. Section 2 confirms it empirically.
          </p>
          <p>
            <strong>IND-CCA2:</strong> the adversary additionally has a decryption oracle for any ciphertext other than the challenge. The malleability attack exploits this: Eve modifies the challenge ciphertext, queries the oracle on the modification (which is a different ciphertext, so the oracle answers), and learns k·m. Information about m leaks through the oracle. ElGamal fails IND-CCA.
          </p>

          <h4>The fix (PA#17)</h4>
          <p>
            Encrypt-then-Sign: send (CE, σ) where CE is the ElGamal ciphertext and σ is a digital signature on CE. The verifier checks σ first; any tamper invalidates the signature, the oracle returns ⊥, and the malleability attack fails. PA#17 implements this and runs the same attack to confirm it's blocked.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#16 → PA#11 (group setup) → PA#13 (Miller-Rabin for safe-prime generation). PA#17 will compose PA#16 + PA#15 (signatures) → PA#12/PA#16 → PA#13.
          </p>
        </div>
      </details>
    </div>
  );
}
