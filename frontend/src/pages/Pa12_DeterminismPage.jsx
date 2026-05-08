import { useState } from 'react';
import './Pa12_DeterminismPage.css';

const API_BASE = 'http://localhost:8000';

// Display helper: huge values render as "1.234 × 10^N", smaller numbers as-is.
const formatBigNum = (val) => {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return String(val);
    if (val === 0) return '0';
    if (Math.abs(val) > 1e10 || Math.abs(val) < 1e-4) {
      const exp = val.toExponential(4);
      const [mantissa, e] = exp.split('e');
      return `${mantissa} × 10^${parseInt(e, 10)}`;
    }
    return val.toString();
  }
  if (typeof val === 'string' && /^\d+$/.test(val) && val.length > 10) {
    const exp = val.length - 1;
    return `${val[0]}.${val.slice(1, 5)} × 10^${exp}`;
  }
  return String(val);
};

export default function Pa12_DeterminismPage() {
  const [message, setMessage] = useState('yes');
  const [bits, setBits] = useState(512);
  const [demo, setDemo] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/pa12/determinism-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, bits, seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setDemo(data.result || data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="pa12-page">
      <header className="pa12-header">
        <h1>PA#12 — RSA Determinism Attack &amp; PKCS#1 v1.5 Defense</h1>
        <p className="pa12-subtitle">
          Encrypt the same plaintext twice. Textbook RSA gives identical ciphertexts — Eve learns the plaintext is unchanged without ever decrypting. PKCS#1 v1.5 prepends fresh random padding before encryption, so the same plaintext encrypts to a different ciphertext every call.
        </p>
      </header>

      {/* Setup */}
      <section className="pa12-section">
        <div className="control-row">
          <label>
            <span className="ctrl-label">Message</span>
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={loading}
              className="ctrl-input ctrl-input-wide"
              placeholder="yes"
            />
          </label>
          <label>
            <span className="ctrl-label">Bits</span>
            <select
              value={bits}
              onChange={(e) => setBits(Number(e.target.value))}
              disabled={loading}
              className="ctrl-input"
            >
              <option value={256}>256</option>
              <option value={512}>512</option>
              <option value={1024}>1024</option>
            </select>
          </label>
          <button onClick={runDemo} disabled={loading} className="btn btn-primary">
            {loading ? 'Encrypting…' : demo ? 'Run again' : 'Encrypt twice'}
          </button>
        </div>
        <p className="hint">
          PKCS#1 v1.5 needs at least 11 bytes of padding overhead, so use bits ≥ 128 for any non-trivial message. The same plaintext is encrypted twice in each mode; we then compare.
        </p>
        {error && <div className="error-box">Error: {error}</div>}
      </section>

      {!demo && !error && (
        <div className="placeholder-box">
          Click <strong>Encrypt twice</strong> to see the same plaintext encrypted twice in textbook RSA (identical) and PKCS#1 v1.5 (different).
        </div>
      )}

      {demo && (
        <>
          {/* Section 1: Textbook RSA (broken) */}
          <section className="pa12-compare">
            <div className="compare-header">
              <h2>1. Textbook RSA</h2>
              <span className="status-tag tag-broken">BROKEN · DETERMINISTIC</span>
            </div>
            <p className="compare-desc">
              c = m<sup>e</sup> mod N. Same m, same N, same e → identical c. Always.
            </p>

            <div className="cipher-row">
              <div className="card cipher-card">
                <h3>Encryption #1</h3>
                <div className="kv">
                  <span className="key">m</span>
                  <code className="val mono">"{message}"</code>
                </div>
                <div className="kv">
                  <span className="key">c₁ = m<sup>e</sup> mod N</span>
                  <code className="val mono">{formatBigNum(demo.textbook_cipher_1)}</code>
                </div>
              </div>

              <div className={`compare-glyph ${demo.textbook_equal ? 'glyph-equal' : 'glyph-not-equal'}`}>
                {demo.textbook_equal ? '=' : '≠'}
              </div>

              <div className="card cipher-card">
                <h3>Encryption #2</h3>
                <div className="kv">
                  <span className="key">m</span>
                  <code className="val mono">"{message}"</code>
                </div>
                <div className="kv">
                  <span className="key">c₂ = m<sup>e</sup> mod N</span>
                  <code className="val mono">{formatBigNum(demo.textbook_cipher_2)}</code>
                </div>
              </div>
            </div>

            <div className={`verdict-banner ${demo.textbook_equal ? 'verdict-broken' : 'verdict-secure'}`}>
              <h3>{demo.textbook_equal ? '✗ IDENTICAL CIPHERTEXTS — plaintext leaked' : '✓ Ciphertexts differ'}</h3>
              <p>
                {demo.textbook_equal
                  ? `Eve cannot decrypt without the private key, but c₁ = c₂ tells her m₁ = m₂. If "${message}" is Alice's vote, Eve detects every time Alice votes the same way. That's a CPA failure on its own — no decryption needed.`
                  : 'Unexpected — textbook RSA should be deterministic. Investigate.'}
              </p>
            </div>
          </section>

          {/* Section 2: PKCS#1 v1.5 (fixed) */}
          <section className="pa12-compare">
            <div className="compare-header">
              <h2>2. PKCS#1 v1.5</h2>
              <span className="status-tag tag-secure">SECURE · RANDOMIZED</span>
            </div>
            <p className="compare-desc">
              Before encrypting, prepend <code>00 ‖ 02 ‖ PS ‖ 00 ‖ m</code>, where PS is at least 8 bytes of cryptographically random nonzero filler — regenerated per encryption.
            </p>

            <div className="cipher-row">
              <div className="card cipher-card">
                <h3>Encryption #1</h3>
                <div className="kv">
                  <span className="key">EM₁</span>
                  <code className="val mono">00‖02‖PS₁‖00‖"{message}"</code>
                </div>
                <div className="kv">
                  <span className="key">c₁ = EM₁<sup>e</sup> mod N</span>
                  <code className="val mono">{formatBigNum(demo.pkcs15_cipher_1)}</code>
                </div>
              </div>

              <div className={`compare-glyph ${demo.pkcs15_equal ? 'glyph-equal' : 'glyph-not-equal'}`}>
                {demo.pkcs15_equal ? '=' : '≠'}
              </div>

              <div className="card cipher-card">
                <h3>Encryption #2</h3>
                <div className="kv">
                  <span className="key">EM₂</span>
                  <code className="val mono">00‖02‖PS₂‖00‖"{message}"</code>
                </div>
                <div className="kv">
                  <span className="key">c₂ = EM₂<sup>e</sup> mod N</span>
                  <code className="val mono">{formatBigNum(demo.pkcs15_cipher_2)}</code>
                </div>
              </div>
            </div>

            <div className={`verdict-banner ${demo.pkcs15_equal ? 'verdict-broken' : 'verdict-secure'}`}>
              <h3>{!demo.pkcs15_equal ? '✓ DIFFERENT CIPHERTEXTS — semantically secure' : '✗ Ciphertexts equal'}</h3>
              <p>
                {!demo.pkcs15_equal
                  ? `Same plaintext "${message}", but PS₁ ≠ PS₂ (fresh random bytes each call) → completely unrelated ciphertexts. Eve sees two encryptions and cannot tell whether they encode the same message.`
                  : 'Unexpected — PKCS#1 v1.5 should produce different ciphertexts each call. Investigate.'}
              </p>
            </div>
          </section>

          {/* Decrypt check */}
          <section className="pa12-decrypt-check">
            <div className={`decrypt-banner ${demo.decrypt_check ? 'decrypt-ok' : 'decrypt-fail'}`}>
              {demo.decrypt_check
                ? <>✓ Both PKCS#1 v1.5 ciphertexts decrypt back to "<code>{message}</code>". Randomization preserves correctness.</>
                : <>✗ Decryption check failed. The randomization broke correctness — investigate.</>}
            </div>
          </section>
        </>
      )}

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Why determinism breaks CPA security</h4>
          <p>
            CPA (chosen-plaintext attack) security demands that an adversary watching encryptions cannot tell whether two ciphertexts encrypt the same plaintext. Textbook RSA c = m<sup>e</sup> mod N has no randomness — same m always yields the same c. So Eve seeing c₁ = c₂ immediately knows m₁ = m₂. This is a fatal information leak even without recovering the actual plaintext: think of an encrypted vote, an encrypted bid, an encrypted command. Eve doesn't need to know what the message is to know it is the same as last time.
          </p>

          <h4>The PKCS#1 v1.5 padding format</h4>
          <p>
            For modulus N of byte-length k, the padded plaintext EM has total length k bytes:
          </p>
          <pre className="math-block">EM  =  00 ‖ 02 ‖ PS ‖ 00 ‖ m</pre>
          <ul>
            <li><code>00 02</code> — fixed type header (02 = encryption padding; 01 = signature padding).</li>
            <li><code>PS</code> — at least 8 bytes of cryptographically random nonzero filler. Length is k − 3 − |m| bytes.</li>
            <li><code>00</code> — separator marking where m begins on decryption.</li>
            <li><code>m</code> — original message; max length k − 11 bytes.</li>
          </ul>
          <p>
            Randomness in PS makes EM different on every encryption, so RSA's deterministic permutation produces different ciphertexts. Decryption strips the padding and recovers the same m.
          </p>

          <h4>Why PKCS#1 v1.5 is still not enough</h4>
          <p>
            PKCS#1 v1.5 is CPA-secure but not CCA-secure. Bleichenbacher (1998) showed that a service which leaks whether decryption produced a valid PKCS#1 v1.5 padding (a "padding oracle") can be queried adaptively to recover any RSA ciphertext in ≈ 2<sup>20</sup> queries. The modern replacement is OAEP, which is CCA-secure in the random-oracle model. Your PA#17 (Sign-then-Encrypt) is another route to CCA-secure PKC.
          </p>

          <h4>Lineage</h4>
          <p>
            This page calls PA#12's RSA, which uses PA#13 Miller-Rabin for prime generation. The chain: <strong>PA#12 → PA#13</strong>. The fix in PA#17 will compose PA#12 + PA#15 (signatures) + PA#13.
          </p>

          <h4>Note on display precision</h4>
          <p>
            Ciphertexts at 512 bits are ~155 decimal digits — far past JavaScript Number's 15-digit precision. Values shown in scientific notation here are rounded for display. The page does not round-trip these values anywhere, so precision loss is purely cosmetic; the equality and inequality verdicts come from the backend's <code>textbook_equal</code> and <code>pkcs15_equal</code> flags, computed in Python with full bigint precision.
          </p>
        </div>
      </details>
    </div>
  );
}
