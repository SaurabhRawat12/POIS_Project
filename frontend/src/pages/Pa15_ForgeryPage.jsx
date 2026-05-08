import { useState } from 'react';
import './Pa15_ForgeryPage.css';

const API_BASE = 'http://localhost:8000';

// Display helper: turn an exact decimal string or JS number into "1.234×10^N" for huge values.
const formatBigNum = (val) => {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'string' && /^\d+$/.test(val)) {
    if (val.length > 10) {
      const exp = val.length - 1;
      const mantissa = `${val[0]}.${val.slice(1, 5)}`;
      return `${mantissa} × 10^${exp}`;
    }
    return val;
  }
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return String(val);
    if (Math.abs(val) > 1e10) return val.toExponential(4);
    return val.toString();
  }
  return String(val);
};

// Pull an unquoted JSON integer out of raw response text as an exact decimal string.
// JS would round-trip this lossily through JSON.parse; we keep the digits verbatim
// so we can re-inject them into the verify request body without precision loss.
const extractIntStr = (text, key) => {
  const re = new RegExp(`"${key}"\\s*:\\s*(\\d+)(?!\\d*\\.)`);
  const match = text.match(re);
  return match ? match[1] : null;
};

export default function Pa15_ForgeryPage() {
  // Section 1 state
  const [message, setMessage] = useState('hello world');
  const [bits, setBits] = useState(512);
  const [qBits, setQBits] = useState(31);
  const [seed, setSeed] = useState(1);

  const [signResult, setSignResult] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [signError, setSignError] = useState(null);
  const [verifyError, setVerifyError] = useState(null);
  const [signLoading, setSignLoading] = useState(false);
  const [verifyLoading, setVerifyLoading] = useState(false);

  // Section 2 state
  const [forgery, setForgery] = useState(null);
  const [forgeryError, setForgeryError] = useState(null);
  const [forgeryLoading, setForgeryLoading] = useState(false);

  const handleSign = async () => {
    setSignLoading(true);
    setSignError(null);
    setVerifyResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa15/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, bits, q_bits: qBits, seed }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const text = await res.text();
      const sigStr = extractIntStr(text, 'signature');
      const nStr = extractIntStr(text, 'N');
      const data = JSON.parse(text);
      const result = data.result || data;
      setSignResult({
        sigStr,
        nStr,
        e: result.public_key.e,
        group: result.group,
        hashedMessage: result.hashed_message,
        message: result.message,
      });
    } catch (err) {
      setSignError(err.message);
    } finally {
      setSignLoading(false);
    }
  };

  const runVerify = async (msgToVerify, mode) => {
    if (!signResult) return;
    setVerifyError(null);
    setVerifyLoading(true);
    try {
      // Build body manually: JSON.stringify would lose precision on signature/N.
      const groupStr = JSON.stringify(signResult.group);
      const escapedMsg = JSON.stringify(msgToVerify);
      const body = `{"message":${escapedMsg},"signature":${signResult.sigStr},"public_key":{"N":${signResult.nStr},"e":${signResult.e}},"group_params":${groupStr}}`;
      const res = await fetch(`${API_BASE}/pa15/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      const r = data.result || data;
      // Try common field spellings; backend may use any of these.
      const valid =
        r.valid ?? r.is_valid ?? r.verified ?? r.signature_valid ?? null;
      if (valid === null) {
        throw new Error(`Verify returned an unrecognized shape: ${JSON.stringify(r)}`);
      }
      setVerifyResult({ valid, mode, message: msgToVerify });
    } catch (err) {
      setVerifyError(err.message);
    } finally {
      setVerifyLoading(false);
    }
  };

  const handleVerifyOriginal = () => runVerify(signResult.message, 'original');
  const handleTamper = () => runVerify(signResult.message + '!', 'tampered');

  const handleForgery = async () => {
    setForgeryLoading(true);
    setForgeryError(null);
    try {
      const res = await fetch(`${API_BASE}/pa15/multiplicative-forgery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setForgery(data.result || data);
    } catch (err) {
      setForgeryError(err.message);
    } finally {
      setForgeryLoading(false);
    }
  };

  return (
    <div className="pa15-page">
      <header className="pa15-header">
        <h1>PA#15 — Digital Signatures &amp; Multiplicative Forgery</h1>
        <p className="pa15-subtitle">
          RSA hash-then-sign, and the existential forgery attack on raw RSA via the multiplicative homomorphism (m₁m₂)<sup>d</sup> ≡ m₁<sup>d</sup>·m₂<sup>d</sup>.
        </p>
      </header>

      {/* ====================== SECTION 1: SIGN & VERIFY ====================== */}
      <section className="pa15-section">
        <h2>1. Honest Sign &amp; Verify</h2>
        <p className="section-desc">
          Sign a message with hash-then-sign RSA, verify it, then tamper a single character to confirm verification rejects it.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Message</span>
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={signLoading}
              className="ctrl-input ctrl-input-wide"
            />
          </label>
          <label>
            <span className="ctrl-label">Bits</span>
            <select
              value={bits}
              onChange={(e) => setBits(Number(e.target.value))}
              disabled={signLoading}
              className="ctrl-input"
            >
              <option value={256}>256</option>
              <option value={512}>512</option>
              <option value={1024}>1024</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">q_bits</span>
            <input
              type="number"
              value={qBits}
              min={8}
              max={64}
              onChange={(e) => setQBits(Number(e.target.value))}
              disabled={signLoading}
              className="ctrl-input"
            />
          </label>
          <label>
            <span className="ctrl-label">Seed</span>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value))}
              disabled={signLoading}
              className="ctrl-input"
            />
          </label>
        </div>

        <div className="button-row">
          <button onClick={handleSign} disabled={signLoading} className="btn btn-primary">
            {signLoading ? 'Signing…' : 'Sign'}
          </button>
          <button
            onClick={handleVerifyOriginal}
            disabled={!signResult || verifyLoading}
            className="btn btn-secondary"
          >
            {verifyLoading && verifyResult?.mode !== 'tampered' ? 'Verifying…' : 'Verify'}
          </button>
          <button
            onClick={handleTamper}
            disabled={!signResult || verifyLoading}
            className="btn btn-tamper"
          >
            Tamper &amp; Verify
          </button>
        </div>

        {signError && <div className="error-box">Sign error: {signError}</div>}
        {verifyError && <div className="error-box">Verify error: {verifyError}</div>}

        {signResult && (
          <div className="sign-results">
            <div className="card pubkey-card">
              <h3>Public Key</h3>
              <div className="kv">
                <span className="key">N</span>
                <code className="val mono">{formatBigNum(signResult.nStr)}</code>
              </div>
              <div className="kv">
                <span className="key">e</span>
                <code className="val mono">{signResult.e}</code>
              </div>
            </div>

            <div className="card group-card">
              <h3>DLP Hash Group (PA#8)</h3>
              <div className="kv"><span className="key">p</span><code className="val mono">{signResult.group.p_hex}</code></div>
              <div className="kv"><span className="key">q</span><code className="val mono">{signResult.group.q_hex}</code></div>
              <div className="kv"><span className="key">g</span><code className="val mono">{signResult.group.g_hex}</code></div>
              <div className="kv"><span className="key">h</span><code className="val mono">{signResult.group.h_hex}</code></div>
            </div>

            <div className="card sig-card">
              <h3>Signature</h3>
              <div className="kv">
                <span className="key">message</span>
                <code className="val mono">"{signResult.message}"</code>
              </div>
              <div className="kv">
                <span className="key">H(m)</span>
                <code className="val mono">{signResult.hashedMessage}</code>
              </div>
              <div className="kv">
                <span className="key">σ = H(m)<sup>d</sup> mod N</span>
                <code className="val mono">{formatBigNum(signResult.sigStr)}</code>
              </div>
            </div>

            {verifyResult && (
              <div className={`verdict-card ${verifyResult.valid ? 'verdict-valid' : 'verdict-invalid'}`}>
                <h3>{verifyResult.valid ? '✓ Signature Valid' : '✗ Signature Invalid'}</h3>
                <div className="verdict-detail">
                  Verified message: <code>"{verifyResult.message}"</code>
                  {verifyResult.mode === 'tampered' && (
                    <span className="tampered-badge"> (tampered — appended "!")</span>
                  )}
                </div>
                <div className="verdict-explainer">
                  {verifyResult.valid
                    ? 'σ^e mod N matches H(m). Signature is authentic.'
                    : 'σ^e mod N ≠ H(m). Tampering or wrong key detected.'}
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ====================== SECTION 2: FORGERY ON RAW RSA ====================== */}
      <section className="pa15-section">
        <h2>2. Multiplicative Forgery on Raw RSA</h2>
        <p className="section-desc">
          Eve obtains two raw-RSA signatures σ₁, σ₂ on messages m₁, m₂. She computes σ₁·σ₂ mod N — a valid signature on m₁·m₂ mod N that she never asked the signer for.
          The endpoint generates fresh m₁, m₂ and a fresh keypair internally; click again for new values.
        </p>

        <div className="button-row">
          <button onClick={handleForgery} disabled={forgeryLoading} className="btn btn-attack">
            {forgeryLoading
              ? 'Running attack…'
              : forgery
              ? 'Run again with fresh values'
              : 'Run the attack'}
          </button>
        </div>

        {forgeryError && <div className="error-box">Forgery error: {forgeryError}</div>}

        {forgery && (
          <div className="forgery-grid">
            <div className="card alice-card">
              <h3>Honest signing #1</h3>
              <div className="kv">
                <span className="key">m₁</span>
                <code className="val mono">{formatBigNum(String(forgery.m1))}</code>
              </div>
              <div className="kv">
                <span className="key">σ₁ = m₁<sup>d</sup> mod N</span>
                <code className="val mono">{formatBigNum(forgery.sigma1)}</code>
              </div>
            </div>

            <div className="card bob-card">
              <h3>Honest signing #2</h3>
              <div className="kv">
                <span className="key">m₂</span>
                <code className="val mono">{formatBigNum(String(forgery.m2))}</code>
              </div>
              <div className="kv">
                <span className="key">σ₂ = m₂<sup>d</sup> mod N</span>
                <code className="val mono">{formatBigNum(forgery.sigma2)}</code>
              </div>
            </div>

            <div className={`card eve-card ${forgery.forgery_valid ? 'eve-success' : 'eve-defeated'}`}>
              <h3>{forgery.forgery_valid ? "✗ Eve's forgery — ACCEPTED" : "✓ Eve's forgery — REJECTED"}</h3>
              <div className="kv">
                <span className="key">σ_forged = σ₁·σ₂ mod N</span>
                <code className="val mono">{formatBigNum(forgery.forged_signature)}</code>
              </div>
              <div className="kv">
                <span className="key">m_forged = m₁·m₂ mod N</span>
                <code className="val mono">{formatBigNum(forgery.forged_message)}</code>
              </div>
              <div className="kv">
                <span className="key">Verify(m_forged, σ_forged)</span>
                <code className={`val mono verdict-inline ${forgery.forgery_valid ? 'bad' : 'good'}`}>
                  {forgery.forgery_valid ? 'ACCEPTED — forgery succeeded' : 'REJECTED — forgery defeated'}
                </code>
              </div>
              <div className="security-note">{forgery.security_note}</div>
            </div>
          </div>
        )}
      </section>

      {/* ====================== SECTION 3: HASH-THEN-SIGN DEFENSE ====================== */}
      <section className="pa15-section">
        <h2>3. Why Hash-then-Sign Defeats This</h2>
        <p className="section-desc">
          Same Eve, same trick — applied to hash-then-sign signatures. The trick has nowhere to land.
        </p>

        <div className="defense-explainer">
          <p>With hash-then-sign, σᵢ = H(mᵢ)<sup>d</sup> mod N. Eve again computes:</p>
          <pre className="math-block">σ_forged  =  σ₁ · σ₂ mod N  =  ( H(m₁) · H(m₂) )^d  mod N</pre>
          <p>For this to verify on some message m*, the verifier would compute H(m*) and demand:</p>
          <pre className="math-block">H(m*)  ≡  H(m₁) · H(m₂)   (mod N)</pre>
          <p>
            Eve cannot produce such an m*. Hash functions are not multiplicatively homomorphic, and they are preimage-resistant — finding any input that maps to a chosen output is the OWF problem.
            The forged signature is still a valid number, but it is a signature on no message anyone can name. It has no valid target.
          </p>

          <div className="card eve-card eve-defeated defense-card">
            <h3>✓ Forgery on hash-then-sign — REJECTED</h3>
            <div className="kv">
              <span className="key">σ_forged</span>
              <code className="val mono">computable (just a product mod N)</code>
            </div>
            <div className="kv">
              <span className="key">target message m*?</span>
              <code className="val mono error-text">none findable — preimage problem</code>
            </div>
            <div className="kv">
              <span className="key">Verify on any candidate m</span>
              <code className="val mono verdict-inline good">REJECTED — forgery has no valid target</code>
            </div>
            <div className="security-note">
              The forgery requires solving H(m*) = H(m₁)·H(m₂) mod N — preimage resistance of H makes this structurally infeasible.
            </div>
          </div>
        </div>
      </section>

      {/* ====================== PEDAGOGY ====================== */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>RSA signing</h4>
          <p>
            Key gen: pick large primes p, q; N = p·q; e is public; d = e<sup>−1</sup> mod φ(N) is private.
          </p>
          <p>
            Raw signing: σ = m<sup>d</sup> mod N. &nbsp; Verify: σ<sup>e</sup> mod N ≟ m.
          </p>
          <p>
            Hash-then-sign: σ = H(m)<sup>d</sup> mod N. &nbsp; Verify: σ<sup>e</sup> mod N ≟ H(m).
          </p>

          <h4>The attack — RSA's multiplicative homomorphism</h4>
          <p>
            For any m₁, m₂: (m₁ · m₂)<sup>d</sup> ≡ m₁<sup>d</sup> · m₂<sup>d</sup> &nbsp;(mod N).
          </p>
          <p>
            So if Eve sees σ₁ = m₁<sup>d</sup> and σ₂ = m₂<sup>d</sup>, she computes σ_forged = σ₁·σ₂ mod N, which equals (m₁·m₂)<sup>d</sup> mod N — a valid signature on m₁·m₂ mod N. She never queried the signer for it. This is an existential forgery in the EUF-CMA game.
          </p>

          <h4>Why the hash kills the attack</h4>
          <p>
            The attack works because RSA's exponent d distributes over multiplication. Hashing inserts a non-multiplicative function before the exponentiation: σᵢ = H(mᵢ)<sup>d</sup>. Eve's product σ₁·σ₂ equals (H(m₁)·H(m₂))<sup>d</sup>. For this to be valid on any message m*, she would need H(m*) = H(m₁)·H(m₂) mod N — and there is no efficient way to find such an m*. Preimage resistance and the lack of multiplicativity of H jointly block the attack.
          </p>

          <h4>Lineage</h4>
          <p>
            This page's hash-then-sign uses PA#8's DLP-based hash (group params p, q, g, h shown above). The same hash powers PA#10 HMAC. The lineage chain is PA#15 → PA#12 (RSA) + PA#8 (hash) → PA#13 (Miller-Rabin).
          </p>

          <h4>Note on display precision</h4>
          <p>
            σ and N are huge integers (≥ 2<sup>500</sup>). JavaScript Number loses precision past 2<sup>53</sup>, so any value rendered in scientific notation here is display-only. The page extracts exact decimal digits from the raw HTTP response and re-injects them when calling /pa15/verify, so the round-trip stays bit-exact.
          </p>
        </div>
      </details>
    </div>
  );
}
