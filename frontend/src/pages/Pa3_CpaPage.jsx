import { useState } from 'react';
import './Pa3_CpaPage.css';

const API_BASE = 'http://localhost:8000';

const isValidBinary4 = (s) => /^[01]{4}$/.test(s);

export default function Pa3_CpaPage() {
  // Shared params
  const [p, setP] = useState(65537);
  const [g, setG] = useState(3);

  // Section 1: encrypt/decrypt
  const [k, setK] = useState('0101');
  const [m, setM] = useState('1010');
  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);
  const [randomDemo, setRandomDemo] = useState(null);
  const [encError, setEncError] = useState(null);
  const [encLoading, setEncLoading] = useState(false);
  const [decLoading, setDecLoading] = useState(false);
  const [demoLoading, setDemoLoading] = useState(false);

  // Section 2: single-round challenge
  const [gameK, setGameK] = useState('0011');
  const [m0, setM0] = useState('0101');
  const [m1, setM1] = useState('1010');
  const [challenge, setChallenge] = useState(null);
  const [userGuess, setUserGuess] = useState(null);
  const [revealed, setRevealed] = useState(false);
  const [chError, setChError] = useState(null);
  const [chLoading, setChLoading] = useState(false);

  // Section 3: side-by-side experiment
  const [expK, setExpK] = useState('1111');
  const [expM0, setExpM0] = useState('1111');
  const [expM1, setExpM1] = useState('0000');
  const [rounds, setRounds] = useState(100);
  const [oracleQueries, setOracleQueries] = useState(50);
  const [secureExp, setSecureExp] = useState(null);
  const [brokenExp, setBrokenExp] = useState(null);
  const [expError, setExpError] = useState(null);
  const [expLoading, setExpLoading] = useState(false);

  const runEncrypt = async () => {
    if (!isValidBinary4(k) || !isValidBinary4(m)) {
      setEncError('k and m must each be 4 bits (0s and 1s only)');
      return;
    }
    setEncLoading(true);
    setEncError(null);
    setDecResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa3/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ k, m, method: 'dlp', p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setEncResult(data.result || data);
    } catch (err) {
      setEncError(err.message);
    } finally {
      setEncLoading(false);
    }
  };

  const runDecrypt = async () => {
    if (!encResult) return;
    setDecLoading(true);
    setEncError(null);
    try {
      const res = await fetch(`${API_BASE}/pa3/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          k,
          r: encResult.nonce,
          c: encResult.ciphertext,
          method: 'dlp',
          p,
          g,
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setDecResult(data.result || data);
    } catch (err) {
      setEncError(err.message);
    } finally {
      setDecLoading(false);
    }
  };

  const runRandomDemo = async () => {
    if (!isValidBinary4(k) || !isValidBinary4(m)) {
      setEncError('k and m must each be 4 bits (0s and 1s only)');
      return;
    }
    setDemoLoading(true);
    setEncError(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const body = JSON.stringify({ k, m, method: 'dlp', p, g });
      const promises = Array.from({ length: 5 }, () =>
        fetch(`${API_BASE}/pa3/encrypt`, { method: 'POST', headers, body }).then((r) => r.json())
      );
      const results = await Promise.all(promises);
      setRandomDemo(results.map((d) => d.result || d));
    } catch (err) {
      setEncError(err.message);
    } finally {
      setDemoLoading(false);
    }
  };

  const runChallenge = async () => {
    if (!isValidBinary4(gameK) || !isValidBinary4(m0) || !isValidBinary4(m1)) {
      setChError('k, m0, m1 must each be 4 bits');
      return;
    }
    setChLoading(true);
    setChError(null);
    setChallenge(null);
    setUserGuess(null);
    setRevealed(false);
    try {
      const res = await fetch(`${API_BASE}/pa3/ind-cpa-game`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ k: gameK, m0, m1, reuse_nonce: false, method: 'dlp', p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setChallenge(data.result || data);
    } catch (err) {
      setChError(err.message);
    } finally {
      setChLoading(false);
    }
  };

  const guessAnd = (b) => {
    setUserGuess(b);
    setRevealed(true);
  };

  const runExperiments = async () => {
    if (!isValidBinary4(expK) || !isValidBinary4(expM0) || !isValidBinary4(expM1)) {
      setExpError('k, m0, m1 must each be 4 bits');
      return;
    }
    setExpLoading(true);
    setExpError(null);
    setSecureExp(null);
    setBrokenExp(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const [secRes, brokRes] = await Promise.all([
        fetch(`${API_BASE}/pa3/dummy-adversary`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            k: expK,
            m0: expM0,
            m1: expM1,
            rounds,
            oracle_queries: oracleQueries,
            method: 'dlp',
            p,
            g,
          }),
        }),
        fetch(`${API_BASE}/pa3/nonce-reuse-attack`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            k: expK,
            m0: expM0,
            m1: expM1,
            rounds,
            reuse_nonce: true,
            method: 'dlp',
            p,
            g,
          }),
        }),
      ]);
      for (const r of [secRes, brokRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [secData, brokData] = await Promise.all([secRes.json(), brokRes.json()]);
      setSecureExp(secData.result || secData);
      setBrokenExp(brokData.result || brokData);
    } catch (err) {
      setExpError(err.message);
    } finally {
      setExpLoading(false);
    }
  };

  // Helper to compute spectrum marker position (advantage 0..0.5 → 0..100%)
  const advToPct = (a) => Math.min(100, Math.max(0, (a / 0.5) * 100));

  return (
    <div className="pa3-page">
      <header className="pa3-header">
        <h1>PA#3 — CPA-Secure Symmetric Encryption</h1>
        <p className="pa3-subtitle">
          A symmetric encryption scheme is CPA-secure if no efficient adversary, even with access to an encryption oracle, can distinguish encryptions of two messages of their choice. The construction here is <code>c = m ⊕ F<sub>k</sub>(r)</code> — XOR the message with a fresh PRF output indexed by a random nonce r. PA#3 demonstrates the mechanics, runs the security game interactively, and contrasts the secure version with the catastrophic failure that occurs when the nonce is reused.
        </p>
      </header>

      <section className="pa3-params">
        <span className="params-label">Group parameters · all sections</span>
        <label>
          <span className="ctrl-label">p</span>
          <input
            type="number"
            value={p}
            onChange={(e) => setP(Number(e.target.value))}
            className="ctrl-input"
          />
        </label>
        <label>
          <span className="ctrl-label">g</span>
          <input
            type="number"
            value={g}
            onChange={(e) => setG(Number(e.target.value))}
            className="ctrl-input"
          />
        </label>
        <span className="params-note">
          Toy params · n = 4 bits: messages, keys, nonces, ciphertexts are all 4-bit binary strings.
        </span>
      </section>

      {/* ============ SECTION 1: ENCRYPT/DECRYPT MECHANICS ============ */}
      <section className="pa3-section">
        <div className="section-head">
          <h2>1. Encryption Mechanics: Randomized CPA</h2>
          <span className="status-tag tag-info">c = m ⊕ F<sub>k</sub>(r)</span>
        </div>
        <p className="section-desc">
          Encryption draws a fresh random nonce r and outputs <code>c = m ⊕ F<sub>k</sub>(r)</code>. The nonce travels with the ciphertext so the receiver can recompute F<sub>k</sub>(r) and recover m. Because r is random per encryption, the same plaintext under the same key produces different ciphertexts — this is what makes CPA security possible.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key k (4 bits)</span>
            <input
              type="text"
              value={k}
              maxLength={4}
              onChange={(e) => setK(e.target.value.replace(/[^01]/g, ''))}
              disabled={encLoading || decLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">message m (4 bits)</span>
            <input
              type="text"
              value={m}
              maxLength={4}
              onChange={(e) => setM(e.target.value.replace(/[^01]/g, ''))}
              disabled={encLoading || decLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <button onClick={runEncrypt} disabled={encLoading} className="btn btn-primary">
            {encLoading ? 'Encrypting…' : 'Encrypt m'}
          </button>
          <button
            onClick={runDecrypt}
            disabled={decLoading || !encResult}
            className="btn btn-secondary"
          >
            {decLoading ? 'Decrypting…' : 'Decrypt (r, c)'}
          </button>
          <button onClick={runRandomDemo} disabled={demoLoading} className="btn btn-secondary">
            {demoLoading ? 'Running…' : 'Encrypt 5×'}
          </button>
        </div>

        {encError && <div className="error-box">Error: {encError}</div>}

        {encResult && (
          <div className="round-trip-grid">
            <div className="rt-card rt-card-alice">
              <div className="rt-tag rt-tag-alice">ALICE · ENCRYPT</div>
              <div className="kv">
                <span className="key">message m</span>
                <code className="val mono">{encResult.message}</code>
              </div>
              <div className="kv">
                <span className="key">key k</span>
                <code className="val mono">{encResult.key}</code>
              </div>
              <div className="rt-divider">↓ encrypt</div>
              <div className="kv">
                <span className="key">nonce r (random)</span>
                <code className="val mono nonce-val">{encResult.nonce}</code>
              </div>
              <div className="kv">
                <span className="key">ciphertext c</span>
                <code className="val mono cipher-val">{encResult.ciphertext}</code>
              </div>
            </div>

            <div className="rt-arrow">→ send (r, c) →</div>

            <div className="rt-card rt-card-bob">
              <div className="rt-tag rt-tag-bob">BOB · DECRYPT</div>
              {decResult ? (
                <>
                  <div className="kv">
                    <span className="key">received r</span>
                    <code className="val mono nonce-val">{decResult.nonce}</code>
                  </div>
                  <div className="kv">
                    <span className="key">received c</span>
                    <code className="val mono cipher-val">{decResult.ciphertext}</code>
                  </div>
                  <div className="kv">
                    <span className="key">key k</span>
                    <code className="val mono">{decResult.key}</code>
                  </div>
                  <div className="rt-divider">↓ decrypt</div>
                  <div className="kv">
                    <span className="key">recovered m'</span>
                    <code className="val mono recovered-val">{decResult.plaintext}</code>
                  </div>
                  {decResult.plaintext === encResult.message ? (
                    <div className="verdict-pill verdict-pill-secure">✓ m' = m · round-trip</div>
                  ) : (
                    <div className="verdict-pill verdict-pill-broken">✗ m' ≠ m</div>
                  )}
                </>
              ) : (
                <div className="rt-placeholder">
                  Click <strong>Decrypt (r, c)</strong> to recover m' on Bob's side.
                </div>
              )}
            </div>
          </div>
        )}

        {randomDemo && (
          <div className="random-demo-wrap">
            <h3 className="random-demo-heading">
              Same plaintext, 5 independent encryptions
            </h3>
            <p className="random-demo-blurb">
              Re-running encrypt with identical (k, m) → 5 different ciphertexts because each call draws a fresh nonce. If encryption were deterministic (PA#12 textbook RSA, or reused nonces below), repeats would all collide.
            </p>
            <div className="random-demo-table">
              <div className="rdt-header">
                <span>#</span>
                <span>nonce r</span>
                <span>ciphertext c</span>
              </div>
              {randomDemo.map((row, i) => (
                <div key={i} className="rdt-row">
                  <span className="rdt-idx">{i + 1}</span>
                  <code className="mono nonce-val">{row.nonce}</code>
                  <code className="mono cipher-val">{row.ciphertext}</code>
                </div>
              ))}
            </div>
            <div className="verdict-pill verdict-pill-secure">
              ✓ {new Set(randomDemo.map((r) => r.ciphertext)).size} distinct ciphertexts from {randomDemo.length} runs
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 2: SINGLE-ROUND CHALLENGE ============ */}
      <section className="pa3-section">
        <div className="section-head">
          <h2>2. IND-CPA Challenge · Single Round</h2>
          <span className="status-tag tag-info">YOUR TURN</span>
        </div>
        <p className="section-desc">
          You pick two 4-bit messages m<sub>0</sub> and m<sub>1</sub>. The challenger flips a hidden coin b ∈ {'{0,1}'} and encrypts m<sub>b</sub>, returning only the ciphertext. Your job: guess which one was encrypted. With a single shot and no oracle queries, the best strategy is to flip a coin yourself — that's what semantic security guarantees.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key k (4 bits)</span>
            <input
              type="text"
              value={gameK}
              maxLength={4}
              onChange={(e) => setGameK(e.target.value.replace(/[^01]/g, ''))}
              disabled={chLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">m<sub>0</sub> (4 bits)</span>
            <input
              type="text"
              value={m0}
              maxLength={4}
              onChange={(e) => setM0(e.target.value.replace(/[^01]/g, ''))}
              disabled={chLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">m<sub>1</sub> (4 bits)</span>
            <input
              type="text"
              value={m1}
              maxLength={4}
              onChange={(e) => setM1(e.target.value.replace(/[^01]/g, ''))}
              disabled={chLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <button onClick={runChallenge} disabled={chLoading} className="btn btn-primary">
            {chLoading ? 'Encrypting…' : (challenge ? 'New challenge' : 'Challenge me')}
          </button>
        </div>

        {chError && <div className="error-box">Error: {chError}</div>}

        {challenge && (
          <div className="challenge-wrap">
            <div className="challenge-msgs">
              <div
                className={`msg-card ${
                  revealed && challenge.secret_bit === 0 ? 'msg-card-correct' : ''
                } ${userGuess === 0 ? 'msg-card-guessed' : ''}`}
              >
                <div className="msg-tag">m<sub>0</sub></div>
                <code className="msg-value">{m0}</code>
                {revealed && challenge.secret_bit === 0 && (
                  <div className="msg-actual-tag">← actually encrypted</div>
                )}
              </div>
              <div className="vs-divider">OR</div>
              <div
                className={`msg-card ${
                  revealed && challenge.secret_bit === 1 ? 'msg-card-correct' : ''
                } ${userGuess === 1 ? 'msg-card-guessed' : ''}`}
              >
                <div className="msg-tag">m<sub>1</sub></div>
                <code className="msg-value">{m1}</code>
                {revealed && challenge.secret_bit === 1 && (
                  <div className="msg-actual-tag">← actually encrypted</div>
                )}
              </div>
            </div>

            <div className="challenge-cipher">
              <div className="cc-tag">CHALLENGE CIPHERTEXT</div>
              <div className="cc-row">
                <div className="cc-kv">
                  <span className="cc-key">nonce r</span>
                  <code className="cc-val">{challenge.challenge_r}</code>
                </div>
                <div className="cc-kv">
                  <span className="cc-key">ciphertext c</span>
                  <code className="cc-val">{challenge.challenge_c}</code>
                </div>
              </div>
            </div>

            {!revealed ? (
              <div className="guess-row">
                <span className="guess-prompt">Your guess?</span>
                <button onClick={() => guessAnd(0)} className="btn btn-secondary">
                  I guess m<sub>0</sub>
                </button>
                <button onClick={() => guessAnd(1)} className="btn btn-secondary">
                  I guess m<sub>1</sub>
                </button>
                <button onClick={() => setRevealed(true)} className="btn btn-ghost">
                  Reveal without guessing
                </button>
              </div>
            ) : (
              <div className="reveal-row">
                {userGuess === null ? (
                  <div className="reveal-banner reveal-info">
                    Encrypted message was m<sub>{challenge.secret_bit}</sub>
                  </div>
                ) : userGuess === challenge.secret_bit ? (
                  <div className="reveal-banner reveal-correct">
                    ✓ You guessed m<sub>{userGuess}</sub> · correct! (encrypted was m<sub>{challenge.secret_bit}</sub>)
                  </div>
                ) : (
                  <div className="reveal-banner reveal-wrong">
                    ✗ You guessed m<sub>{userGuess}</sub> · wrong (encrypted was m<sub>{challenge.secret_bit}</sub>)
                  </div>
                )}
                <p className="reveal-explanation">
                  Whether you got it right or wrong, with a single ciphertext your <em>expected</em> success rate is exactly 50% — there's no information in the ciphertext that lets you do better. Run the experiment in Section 3 to see this measured over many rounds.
                </p>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ============ SECTION 3: SIDE-BY-SIDE EMPIRICAL ============ */}
      <section className="pa3-section">
        <div className="section-head">
          <h2>3. Empirical: Random Nonce vs Reused Nonce</h2>
          <span className="status-tag tag-warn">SECURE vs BROKEN</span>
        </div>
        <p className="section-desc">
          Two empirical experiments side-by-side, identical inputs, only the nonce policy differs. Random nonces (left) keep the dummy adversary near 50% success — advantage in the secure zone. Reused nonces (right) make encryption deterministic: encrypting m<sub>0</sub> twice produces identical ciphertexts, and the adversary just queries the oracle for m<sub>0</sub> and m<sub>1</sub>, then compares against the challenge — perfect win, advantage at the maximum 0.5.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key k</span>
            <input
              type="text"
              value={expK}
              maxLength={4}
              onChange={(e) => setExpK(e.target.value.replace(/[^01]/g, ''))}
              disabled={expLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">m<sub>0</sub></span>
            <input
              type="text"
              value={expM0}
              maxLength={4}
              onChange={(e) => setExpM0(e.target.value.replace(/[^01]/g, ''))}
              disabled={expLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">m<sub>1</sub></span>
            <input
              type="text"
              value={expM1}
              maxLength={4}
              onChange={(e) => setExpM1(e.target.value.replace(/[^01]/g, ''))}
              disabled={expLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">rounds</span>
            <select
              value={rounds}
              onChange={(e) => setRounds(Number(e.target.value))}
              disabled={expLoading}
              className="ctrl-input"
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={250}>250</option>
              <option value={500}>500</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">oracle queries</span>
            <select
              value={oracleQueries}
              onChange={(e) => setOracleQueries(Number(e.target.value))}
              disabled={expLoading}
              className="ctrl-input"
            >
              <option value={10}>10</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </label>
          <button onClick={runExperiments} disabled={expLoading} className="btn btn-primary">
            {expLoading ? 'Running…' : 'Run both experiments'}
          </button>
        </div>

        {expError && <div className="error-box">Error: {expError}</div>}

        {secureExp && brokenExp && (
          <>
            <div className="exp-grid">
              {/* Secure card */}
              <div className="exp-card exp-card-secure">
                <div className="exp-tag exp-tag-secure">RANDOM NONCE · SECURE</div>
                <h3>Dummy adversary, fresh r per encryption</h3>
                <div className="mini-stats">
                  <div className="mini-stat">
                    <div className="ms-name">success rate</div>
                    <div className="ms-num">{(secureExp.success_rate * 100).toFixed(1)}%</div>
                  </div>
                  <div className="mini-stat mini-stat-highlight-secure">
                    <div className="ms-name">advantage</div>
                    <div className="ms-num">{secureExp.empirical_advantage.toFixed(3)}</div>
                  </div>
                  <div className="mini-stat">
                    <div className="ms-name">rounds</div>
                    <div className="ms-num">{secureExp.rounds}</div>
                  </div>
                </div>
                <div className="advantage-spectrum">
                  <div className="spectrum-bar">
                    <div className="spectrum-zone zone-secure"><span>secure</span></div>
                    <div className="spectrum-zone zone-warn"><span>signal</span></div>
                    <div className="spectrum-zone zone-broken"><span>broken</span></div>
                    <div className="spectrum-marker" style={{ left: `${advToPct(secureExp.empirical_advantage)}%` }}>
                      <div className="marker-pin"></div>
                      <div className="marker-label">{secureExp.empirical_advantage.toFixed(3)}</div>
                    </div>
                  </div>
                </div>
                <blockquote className="exp-quote">{secureExp.security_claim}</blockquote>
              </div>

              {/* Broken card */}
              <div className="exp-card exp-card-broken">
                <div className="exp-tag exp-tag-broken">REUSED NONCE · BROKEN</div>
                <h3>Attacker exploiting nonce determinism</h3>
                <div className="mini-stats">
                  <div className="mini-stat">
                    <div className="ms-name">attack success</div>
                    <div className="ms-num">{(brokenExp.attack_success_rate * 100).toFixed(1)}%</div>
                  </div>
                  <div className="mini-stat mini-stat-highlight-broken">
                    <div className="ms-name">advantage</div>
                    <div className="ms-num">{brokenExp.empirical_advantage.toFixed(3)}</div>
                  </div>
                  <div className="mini-stat">
                    <div className="ms-name">rounds</div>
                    <div className="ms-num">{brokenExp.rounds}</div>
                  </div>
                </div>
                <div className="advantage-spectrum">
                  <div className="spectrum-bar">
                    <div className="spectrum-zone zone-secure"><span>secure</span></div>
                    <div className="spectrum-zone zone-warn"><span>signal</span></div>
                    <div className="spectrum-zone zone-broken"><span>broken</span></div>
                    <div className="spectrum-marker" style={{ left: `${advToPct(brokenExp.empirical_advantage)}%` }}>
                      <div className="marker-pin marker-pin-red"></div>
                      <div className="marker-label marker-label-red">{brokenExp.empirical_advantage.toFixed(3)}</div>
                    </div>
                  </div>
                </div>
                <blockquote className="exp-quote">{brokenExp.attack}</blockquote>
              </div>
            </div>

            <div className="contrast-banner">
              <h3>
                {(brokenExp.empirical_advantage / Math.max(secureExp.empirical_advantage, 0.001)).toFixed(1)}× advantage gap · same scheme, only the nonce policy changed
              </h3>
              <p>
                Random nonces keep the construction <code>c = m ⊕ F<sub>k</sub>(r)</code> probabilistic, which is what the IND-CPA proof requires. Reuse the nonce and the encryption becomes a <em>deterministic</em> function of m — the attacker queries Enc(m<sub>0</sub>) and Enc(m<sub>1</sub>) on their own, sees the deterministic outputs, then matches them against the challenge ciphertext for a guaranteed win. There's nothing wrong with the cipher itself — the failure is at the protocol level. This is also why every modern AEAD scheme (AES-GCM, ChaCha20-Poly1305) treats nonce reuse as a critical security violation.
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>CPA security definition</h4>
          <p>
            A symmetric encryption scheme (Gen, Enc, Dec) is IND-CPA secure if no polynomial-time adversary, given access to an encryption oracle Enc<sub>k</sub>(·), can win the following game with non-negligible advantage: pick two messages m<sub>0</sub>, m<sub>1</sub>; receive Enc<sub>k</sub>(m<sub>b</sub>) for hidden b ←$ {'{0,1}'}; output a guess b'. Advantage = |Pr[b' = b] − 1/2|.
          </p>

          <h4>Standard CPA-from-PRF construction</h4>
          <p>
            Given a PRF F<sub>k</sub> (built from PA#2's GGM construction), define Enc<sub>k</sub>(m) = (r, m ⊕ F<sub>k</sub>(r)) where r ←$ {'{0,1}'}<sup>n</sup> is a fresh random nonce. Decryption: given (r, c), output c ⊕ F<sub>k</sub>(r) = m. Security proof: as long as r doesn't repeat, every encryption uses a fresh independent F<sub>k</sub>(r) value, and by the PRF property this looks like fresh randomness, making the ciphertext look like a one-time-pad encryption of m — which is information-theoretically secure for a single message.
          </p>

          <h4>Why nonce reuse breaks everything</h4>
          <p>
            If r repeats across two encryptions with the same key, F<sub>k</sub>(r) is the same value at both queries. Then for messages m<sub>1</sub> and m<sub>2</sub>: c<sub>1</sub> ⊕ c<sub>2</sub> = (m<sub>1</sub> ⊕ F<sub>k</sub>(r)) ⊕ (m<sub>2</sub> ⊕ F<sub>k</sub>(r)) = m<sub>1</sub> ⊕ m<sub>2</sub>. The attacker recovers the XOR of the two plaintexts. In our IND-CPA setting it's even worse: the adversary queries Enc(m<sub>0</sub>) and Enc(m<sub>1</sub>) directly; if reuse makes encryption deterministic, the challenge ciphertext is byte-for-byte identical to one of those two known values, giving a perfect identification.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#3 → PA#2 (uses F<sub>k</sub> built by GGM) → PA#1 (PRG underlying GGM). PA#5 (MAC) and PA#6 (CCA-Symmetric) sit on top of PA#3, adding integrity and active-attack resistance. The same nonce-reuse pitfall reappears in real-world AEAD schemes — e.g., AES-GCM is catastrophically broken if the IV/nonce is ever reused under the same key, which is why protocols like TLS 1.3 explicitly forbid it.
          </p>
        </div>
      </details>
    </div>
  );
}
