import { useState, useEffect } from 'react';
import './Pa5_MacPage.css';

const API_BASE = 'http://localhost:8000';

// Split hex into pairs (1 byte per pair)
const splitBytes = (hex) => (hex ? hex.match(/.{1,2}/g) || [] : []);

// Decode hex to ASCII (printable chars or dot)
const hexToAscii = (hex) =>
  splitBytes(hex)
    .map((byte) => {
      const code = parseInt(byte, 16);
      return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '·';
    })
    .join('');

// String → hex
const stringToHex = (s) =>
  Array.from(new TextEncoder().encode(s))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

export default function Pa5_MacPage() {
  // Section 1: tag + verify
  const [scheme, setScheme] = useState('cbc');
  const [s1Key, setS1Key] = useState('0123456789abcdef');
  const [s1Msg, setS1Msg] = useState('Pay Alice $100');
  const [s1Tag, setS1Tag] = useState(null);
  const [s1Verify, setS1Verify] = useState(null);
  const [s1VerifyMsg, setS1VerifyMsg] = useState('Pay Alice $100');
  const [s1Error, setS1Error] = useState(null);
  const [s1TagLoading, setS1TagLoading] = useState(false);
  const [s1VerifyLoading, setS1VerifyLoading] = useState(false);

  // Section 2: security demos (load on mount)
  const [eufResult, setEufResult] = useState(null);
  const [prfResult, setPrfResult] = useState(null);
  const [s2Error, setS2Error] = useState(null);
  const [s2Loading, setS2Loading] = useState(false);

  // Section 3: length-extension attack
  const [s3Key, setS3Key] = useState('0123456789abcdef');
  const [s3Msg, setS3Msg] = useState('Pay Alice $100');
  const [s3Suffix, setS3Suffix] = useState('; pay Eve $9999');
  const [s3Result, setS3Result] = useState(null);
  const [s3Error, setS3Error] = useState(null);
  const [s3Loading, setS3Loading] = useState(false);

  const isPrfValid = scheme !== 'prf' || s1Msg.length === 16;

  const runTag = async () => {
    if (scheme === 'prf' && s1Msg.length !== 16) {
      setS1Error('PRF-MAC requires the message to be exactly 16 bytes');
      return;
    }
    setS1TagLoading(true);
    setS1Error(null);
    setS1Verify(null);
    try {
      const res = await fetch(`${API_BASE}/pa5/mac`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: { scheme, key: s1Key, message: s1Msg },
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setS1Tag(data.result?.tag_hex || data.result);
      setS1VerifyMsg(s1Msg); // pre-fill verify with same message
    } catch (err) {
      setS1Error(err.message);
    } finally {
      setS1TagLoading(false);
    }
  };

  const runVerify = async () => {
    if (!s1Tag) return;
    if (scheme === 'prf' && s1VerifyMsg.length !== 16) {
      setS1Error('PRF-MAC requires the message to be exactly 16 bytes');
      return;
    }
    setS1VerifyLoading(true);
    setS1Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa5/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: {
            scheme,
            key: s1Key,
            message: s1VerifyMsg,
            tag_hex: s1Tag,
          },
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setS1Verify(data.result);
    } catch (err) {
      setS1Error(err.message);
    } finally {
      setS1VerifyLoading(false);
    }
  };

  const loadSecurityDemos = async () => {
    setS2Loading(true);
    setS2Error(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const [eufRes, prfRes] = await Promise.all([
        fetch(`${API_BASE}/pa5/euf-cma-demo`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload: {} }),
        }),
        fetch(`${API_BASE}/pa5/prf-distinguish-demo`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload: {} }),
        }),
      ]);
      for (const r of [eufRes, prfRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [eufData, prfData] = await Promise.all([eufRes.json(), prfRes.json()]);
      setEufResult(eufData.result);
      setPrfResult(prfData.result);
    } catch (err) {
      setS2Error(err.message);
    } finally {
      setS2Loading(false);
    }
  };

  // Auto-load security demos on mount
  useEffect(() => {
    loadSecurityDemos();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runLengthExtension = async () => {
    setS3Loading(true);
    setS3Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa5/length-extension-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: { key: s3Key, message: s3Msg, suffix: s3Suffix },
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setS3Result(data.result);
    } catch (err) {
      setS3Error(err.message);
    } finally {
      setS3Loading(false);
    }
  };

  // Render the forged message bytes color-coded by region (orig/glue/suffix)
  const renderForgedBytes = (forgedHex, origLen, suffixLen) => {
    const bytes = splitBytes(forgedHex);
    const total = bytes.length;
    const glueEnd = total - suffixLen;
    return bytes.map((byte, i) => {
      let cls = 'fb-glue';
      if (i < origLen) cls = 'fb-orig';
      else if (i >= glueEnd) cls = 'fb-suffix';
      return (
        <span key={i} className={`forged-byte ${cls}`}>
          {byte}
        </span>
      );
    });
  };

  return (
    <div className="pa5-page">
      <header className="pa5-header">
        <h1>PA#5 — Message Authentication Codes</h1>
        <p className="pa5-subtitle">
          A MAC binds a tag t = MAC<sub>k</sub>(m) to a message m using a shared secret key k. The receiver verifies the tag with the same key — if it matches, the message hasn't been tampered with. PA#5 builds two MAC schemes (PRF-MAC for fixed-length messages, CBC-MAC for variable-length), checks their EUF-CMA security empirically, and then exposes the classic length-extension attack against the seemingly-natural <code>H(k ‖ m)</code> construction — the same attack HMAC was designed to prevent.
        </p>
      </header>

      {/* ============ SECTION 1: TAG + VERIFY + TAMPER ============ */}
      <section className="pa5-section">
        <div className="section-head">
          <h2>1. Tag, Verify, Tamper</h2>
          <span className="status-tag tag-info">EUF-CMA AT ONE EXAMPLE</span>
        </div>
        <p className="section-desc">
          Generate a tag for a message, then verify it. Edit a single character of the message and verify again with the same tag — verification fails. This is integrity at a single example: the tag binds to the exact bytes, and any change is detected. Two schemes available: <strong>PRF-MAC</strong> (fixed-length, requires exactly 16-byte messages) and <strong>CBC-MAC</strong> (variable-length, internally pads).
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">scheme</span>
            <select
              value={scheme}
              onChange={(e) => {
                setScheme(e.target.value);
                setS1Tag(null);
                setS1Verify(null);
                setS1Error(null);
              }}
              disabled={s1TagLoading || s1VerifyLoading}
              className="ctrl-input"
            >
              <option value="cbc">CBC-MAC (variable length)</option>
              <option value="prf">PRF-MAC (16 bytes only)</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">key (16 bytes)</span>
            <input
              type="text"
              value={s1Key}
              maxLength={16}
              onChange={(e) => setS1Key(e.target.value)}
              disabled={s1TagLoading || s1VerifyLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">
              message ({s1Msg.length} bytes{scheme === 'prf' ? ' · need 16' : ''})
            </span>
            <input
              type="text"
              value={s1Msg}
              onChange={(e) => setS1Msg(e.target.value)}
              disabled={s1TagLoading || s1VerifyLoading}
              maxLength={scheme === 'prf' ? 16 : 64}
              className={`ctrl-input mono-input ctrl-input-wide ${
                !isPrfValid ? 'ctrl-input-invalid' : ''
              }`}
            />
          </label>
          <button onClick={runTag} disabled={s1TagLoading || !isPrfValid} className="btn btn-primary">
            {s1TagLoading ? 'Tagging…' : 'Generate tag'}
          </button>
        </div>

        {s1Error && <div className="error-box">Error: {s1Error}</div>}

        {s1Tag && (
          <div className="tag-result-card">
            <div className="trc-tag">{scheme.toUpperCase()}-MAC TAG</div>
            <div className="trc-row">
              <span className="trc-key">tag<sub>hex</sub></span>
              <code className="trc-val mono">{s1Tag}</code>
            </div>
            <div className="trc-row">
              <span className="trc-key">message that was tagged</span>
              <code className="trc-val mono">"{s1Msg}"</code>
            </div>

            <div className="verify-block">
              <h3>Verify · with possibly tampered message</h3>
              <p className="verify-blurb">
                The tag above is locked. Now edit the message field below and verify against that tag. Same message → valid. Any change → rejected.
              </p>
              <div className="verify-row">
                <label className="verify-input-label">
                  <span className="ctrl-label">message to verify</span>
                  <input
                    type="text"
                    value={s1VerifyMsg}
                    onChange={(e) => setS1VerifyMsg(e.target.value)}
                    disabled={s1VerifyLoading}
                    maxLength={scheme === 'prf' ? 16 : 64}
                    className="ctrl-input mono-input ctrl-input-wide"
                  />
                </label>
                <button onClick={runVerify} disabled={s1VerifyLoading} className="btn btn-secondary">
                  {s1VerifyLoading ? 'Verifying…' : 'Verify'}
                </button>
              </div>

              {s1Verify !== null && (
                <div
                  className={`verify-banner ${
                    s1Verify.valid ? 'verify-banner-ok' : 'verify-banner-rejected'
                  }`}
                >
                  {s1Verify.valid ? (
                    <>
                      <span className="vb-icon">✓</span>
                      <span className="vb-text">VALID — tag matches "{s1VerifyMsg}"</span>
                    </>
                  ) : (
                    <>
                      <span className="vb-icon">✗</span>
                      <span className="vb-text">REJECTED — tag does not match "{s1VerifyMsg}"</span>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 2: SECURITY CHECKS ============ */}
      <section className="pa5-section">
        <div className="section-head">
          <h2>2. Security Checks</h2>
          <span className="status-tag tag-secure">PRF-MAC IS EUF-CMA SECURE</span>
        </div>
        <p className="section-desc">
          Two empirical checks: (a) the EUF-CMA forgery game — a naive adversary tries 20 random forgery attempts after watching 50 oracle queries, and (b) the PRF-distinguishability of MAC outputs — 100 tags concatenated, count of 1-bits compared to uniform. Both checks should come back green.
        </p>

        <div className="control-row">
          <button onClick={loadSecurityDemos} disabled={s2Loading} className="btn btn-secondary">
            {s2Loading ? 'Running…' : (eufResult ? 'Re-run' : 'Run security demos')}
          </button>
        </div>

        {s2Error && <div className="error-box">Error: {s2Error}</div>}

        {eufResult && prfResult && (
          <div className="security-grid">
            <div className="sec-card sec-card-secure">
              <div className="sec-tag">EUF-CMA · UNFORGEABILITY</div>
              <h3>Naive forgery defeated</h3>
              <div className="sec-stats">
                <div className="sec-stat">
                  <div className="ss-name">trials</div>
                  <div className="ss-num">{eufResult.trials}</div>
                </div>
                <div className="sec-stat sec-stat-highlight-secure">
                  <div className="ss-name">successful forgeries</div>
                  <div className="ss-num">{eufResult.successes}</div>
                  <div className="ss-meta">target: 0</div>
                </div>
                <div className="sec-stat">
                  <div className="ss-name">forgery rate</div>
                  <div className="ss-num">
                    {((eufResult.successes / eufResult.trials) * 100).toFixed(0)}%
                  </div>
                </div>
              </div>
              <div className={`sec-verdict ${eufResult.successes === 0 ? 'sec-verdict-secure' : 'sec-verdict-broken'}`}>
                {eufResult.successes === 0
                  ? '✓ No forgery succeeded — MAC is EUF-CMA at this trial count'
                  : `⚠ ${eufResult.successes} forgery succeeded`}
              </div>
            </div>

            <div className="sec-card sec-card-secure">
              <div className="sec-tag">PRF-DISTINGUISH</div>
              <h3>MAC outputs look pseudorandom</h3>
              <div className="sec-stats">
                <div className="sec-stat">
                  <div className="ss-name">queries</div>
                  <div className="ss-num">{prfResult.queries}</div>
                </div>
                <div className="sec-stat">
                  <div className="ss-name">ones / total bits</div>
                  <div className="ss-num">
                    {prfResult.ones} / {prfResult.total_bits}
                  </div>
                  <div className="ss-meta">target: ~50%</div>
                </div>
                <div className="sec-stat sec-stat-highlight-secure">
                  <div className="ss-name">bias from uniform</div>
                  <div className="ss-num">{prfResult.bias.toFixed(4)}</div>
                  <div className="ss-meta">target: ≈ 0</div>
                </div>
              </div>
              <div className={`sec-verdict ${Math.abs(prfResult.bias) < 0.05 ? 'sec-verdict-secure' : 'sec-verdict-broken'}`}>
                {Math.abs(prfResult.bias) < 0.05
                  ? `✓ Bias ${(prfResult.bias * 100).toFixed(2)}% — within tolerance for uniform output`
                  : `⚠ Bias ${(prfResult.bias * 100).toFixed(2)}% — non-trivial signal`}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 3: LENGTH-EXTENSION ATTACK ============ */}
      <section className="pa5-section">
        <div className="section-head">
          <h2>3. Length-Extension Attack on H(k ‖ m)</h2>
          <span className="status-tag tag-broken">NAIVE MAC · BROKEN</span>
        </div>
        <p className="section-desc">
          The seemingly-natural MAC <code>tag = H(k ‖ m)</code> using a Merkle-Damgård hash is broken. Eve, knowing only (m, tag) and len(k), can compute a valid tag for <code>m ‖ glue ‖ suffix</code> for ANY suffix she chooses — without ever learning k. The construction below uses a toy 16-bit Merkle-Damgård hash; on real hashes (MD5, SHA-1, SHA-256/SHA-512 without truncation) the same attack works.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key (Eve does NOT know)</span>
            <input
              type="text"
              value={s3Key}
              onChange={(e) => setS3Key(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">original message</span>
            <input
              type="text"
              value={s3Msg}
              onChange={(e) => setS3Msg(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <label>
            <span className="ctrl-label">Eve's appended suffix</span>
            <input
              type="text"
              value={s3Suffix}
              onChange={(e) => setS3Suffix(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runLengthExtension} disabled={s3Loading} className="btn btn-primary">
            {s3Loading ? 'Forging…' : 'Run attack'}
          </button>
        </div>

        {s3Error && <div className="error-box">Error: {s3Error}</div>}

        {s3Result && (
          <div className="lext-card">
            {/* Top: original mac */}
            <div className="lext-row">
              <div className="lext-label lext-label-orig">ALICE'S MAC</div>
              <div className="lext-content">
                <div className="lext-kv">
                  <span className="lk-key">message m</span>
                  <code className="mono lk-val">"{s3Msg}"</code>
                </div>
                <div className="lext-kv">
                  <span className="lk-key">tag<sub>hex</sub> = H(k ‖ m)</span>
                  <code className="mono lk-val tag-orig">{s3Result.orig_tag_hex}</code>
                </div>
              </div>
            </div>

            {/* Eve's construction */}
            <div className="lext-divider">
              <span>↓</span>
              <em>Eve constructs a forged message and tag without knowing k</em>
            </div>

            <div className="lext-row">
              <div className="lext-label lext-label-eve">EVE'S FORGERY</div>
              <div className="lext-content">
                <div className="lext-kv lext-kv-stack">
                  <span className="lk-key">forged message = m ‖ glue padding ‖ suffix</span>
                  <div className="forged-bytes-row">
                    {renderForgedBytes(
                      s3Result.forged_message_hex,
                      stringToHex(s3Msg).length / 2,
                      stringToHex(s3Suffix).length / 2
                    )}
                  </div>
                </div>
                <div className="lext-legend">
                  <span className="legend-item">
                    <span className="legend-swatch swatch-orig"></span>original m ({s3Msg.length}B)
                  </span>
                  <span className="legend-item">
                    <span className="legend-swatch swatch-glue"></span>glue padding (Eve constructs)
                  </span>
                  <span className="legend-item">
                    <span className="legend-swatch swatch-suffix"></span>suffix ({s3Suffix.length}B)
                  </span>
                </div>
                <div className="lext-kv">
                  <span className="lk-key">forged tag<sub>hex</sub> (continuing the hash from orig_tag)</span>
                  <code className="mono lk-val tag-forged">{s3Result.forged_tag_hex}</code>
                </div>
              </div>
            </div>

            {/* Verifier */}
            <div className="lext-divider">
              <span>↓</span>
              <em>Verifier (with key) computes the real tag for the forged message</em>
            </div>

            <div className="lext-row">
              <div className="lext-label lext-label-verifier">VERIFIER</div>
              <div className="lext-content">
                <div className="lext-kv">
                  <span className="lk-key">real tag<sub>hex</sub> = H(k ‖ forged_message)</span>
                  <code className="mono lk-val tag-real">{s3Result.real_tag_hex}</code>
                </div>
              </div>
            </div>

            {/* Smoking gun comparison */}
            <div
              className={`smoking-gun ${
                s3Result.attack_success ? 'sg-broken' : 'sg-defeated'
              }`}
            >
              <div className="sg-row">
                <code className="sg-tag">forged_tag = {s3Result.forged_tag_hex}</code>
                <span className="sg-eq">{s3Result.attack_success ? '===' : '≠'}</span>
                <code className="sg-tag">real_tag = {s3Result.real_tag_hex}</code>
              </div>
              <div className="sg-verdict">
                {s3Result.attack_success
                  ? '✗ MATCH — verifier accepts Eve\'s forged message and tag'
                  : '✓ MISMATCH — forgery rejected'}
              </div>
            </div>

            {s3Result.attack_success && (
              <div className="leak-banner leak-banner-broken">
                ⚠ Forgery accepted by verifier. Eve has produced a (message, tag) pair with a tag that's valid under the verifier's key, despite never learning k. The attack works because Merkle-Damgård processes blocks sequentially and the "current state" leaks through the tag — Eve resumes the hash from that state and continues with her chosen suffix.
              </div>
            )}

            <div className="forward-banner">
              <strong>The fix:</strong> HMAC uses two passes — <code>HMAC<sub>k</sub>(m) = H(k ⊕ opad ‖ H(k ⊕ ipad ‖ m))</code>. The outer hash starts from a fresh keyed IV, so the attacker can't continue from the published tag. See PA#10 for the HMAC construction and a side-by-side defeat of this exact attack.
            </div>
          </div>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>MAC security · EUF-CMA</h4>
          <p>
            A MAC scheme (Gen, MAC, Verify) is EUF-CMA secure (Existential Unforgeability under Chosen-Message Attack) if no efficient adversary, given oracle access to MAC<sub>k</sub>(·), can produce a valid (m*, t*) pair where m* was never queried — except with negligible probability. The forgery game in Section 2 simulates this with a naive adversary guessing random tags; that adversary's best strategy is a random guess from a 2<sup>|tag|</sup>-sized space, so success rate ≈ 1/2<sup>|tag|</sup> ≈ 0 for realistic tag sizes.
          </p>

          <h4>PRF-MAC and CBC-MAC</h4>
          <p>
            PRF-MAC (one-block messages): t = F<sub>k</sub>(m). The tag is just a PRF output. Security follows directly from the PRF property: distinguishing valid tags from random outputs is exactly the PRF distinguishing game.
          </p>
          <p>
            CBC-MAC (variable-length): start with chaining state C<sub>0</sub> = 0; for each block m<sub>i</sub>, set C<sub>i</sub> = E<sub>k</sub>(m<sub>i</sub> ⊕ C<sub>i−1</sub>). The final C<sub>L</sub> is the tag. Looks like CBC encryption but only the last block survives. <em>Caveat:</em> raw CBC-MAC is only secure for fixed-length messages; variable-length CBC-MAC needs prefix-free encoding or ECBC-MAC (re-encrypt the final block under a separate key) to be EUF-CMA secure.
          </p>

          <h4>The length-extension attack on H(k ‖ m)</h4>
          <p>
            Merkle-Damgård hashes (MD5, SHA-1, SHA-2) compute H(x) by initializing a state to a fixed IV, then iteratively applying a compression function: state<sub>i</sub> = compress(state<sub>i-1</sub>, block<sub>i</sub>). Critically, the final state IS the output. So if you know H(x), you know the state at the end of processing x — and you can continue hashing FROM that state with whatever you want appended.
          </p>
          <p>
            For tag = H(k ‖ m): Eve knows tag (the final state) and can resume the hash. To make the resumption "valid" she must include the MD padding that the original hash added internally — that's the "glue padding" you see in the visualization. The result is a valid hash output for the message m ‖ glue ‖ suffix. Verifier hashes the same thing and gets the same answer.
          </p>

          <h4>Why HMAC fixes this</h4>
          <p>
            HMAC computes H(k<sub>outer</sub> ‖ H(k<sub>inner</sub> ‖ m)). The outer hash takes a fresh keyed IV and processes only the inner hash output (a short fixed-length value). Eve, given HMAC tag, cannot continue from the outer state because she doesn't know k<sub>outer</sub>. The two-stage structure isolates the attacker's state knowledge from the secret material. PA#10 shows this concretely — same length-extension attack, defeated.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#5 → PA#3 (CPA from PRF, foundation), PA#7 (Merkle-Damgård hash used in length-extension), PA#10 (HMAC defense). PA#11 (Diffie-Hellman key exchange) and PA#15 (signatures) consume MACs as building blocks for higher-level protocols.
          </p>
        </div>
      </details>
    </div>
  );
}
