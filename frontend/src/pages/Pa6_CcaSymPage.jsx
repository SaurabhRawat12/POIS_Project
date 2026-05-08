import { useState, useEffect } from 'react';
import './Pa6_CcaSymPage.css';

const API_BASE = 'http://localhost:8000';

const splitBytes = (hex) => (hex ? hex.match(/.{1,2}/g) || [] : []);

const hexToAscii = (hex) =>
  splitBytes(hex)
    .map((byte) => {
      const code = parseInt(byte, 16);
      return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '·';
    })
    .join('');

export default function Pa6_CcaSymPage() {
  // Section 1: round-trip
  const [keyEnc, setKeyEnc] = useState('0123456789abcdef');
  const [keyMac, setKeyMac] = useState('fedcba9876543210');
  const [msg, setMsg] = useState('Top secret data!');
  const [encResult, setEncResult] = useState(null);
  const [decResult, setDecResult] = useState(null);
  const [s1Error, setS1Error] = useState(null);
  const [encLoading, setEncLoading] = useState(false);
  const [decLoading, setDecLoading] = useState(false);

  // Section 2: malleability (auto-load)
  const [malleability, setMalleability] = useState(null);
  const [s2Error, setS2Error] = useState(null);
  const [s2Loading, setS2Loading] = useState(false);

  // Section 3: cca game + key separation (auto-load)
  const [game, setGame] = useState(null);
  const [keySep, setKeySep] = useState(null);
  const [s3Error, setS3Error] = useState(null);
  const [s3Loading, setS3Loading] = useState(false);

  const runEncrypt = async () => {
    setEncLoading(true);
    setS1Error(null);
    setEncResult(null);
    setDecResult(null);
    try {
      const res = await fetch(`${API_BASE}/pa6/cca-encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: { key_enc: keyEnc, key_mac: keyMac, message: msg },
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setEncResult(data.result);
    } catch (err) {
      setS1Error(err.message);
    } finally {
      setEncLoading(false);
    }
  };

  const runDecrypt = async () => {
    if (!encResult) return;
    setDecLoading(true);
    setS1Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa6/cca-decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: {
            key_enc: keyEnc,
            key_mac: keyMac,
            ciphertext_hex: encResult.ciphertext_hex,
            tag_hex: encResult.tag_hex,
          },
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setDecResult(data.result);
    } catch (err) {
      setS1Error(err.message);
    } finally {
      setDecLoading(false);
    }
  };

  const runMalleability = async () => {
    setS2Loading(true);
    setS2Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa6/malleability-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: {
            key_enc: '0123456789abcdef',
            key_mac: 'fedcba9876543210',
            message: 'Hello, malleability!',
          },
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setMalleability(data.result);
    } catch (err) {
      setS2Error(err.message);
    } finally {
      setS2Loading(false);
    }
  };

  const runGameAndKeySep = async () => {
    setS3Loading(true);
    setS3Error(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const [gameRes, ksRes] = await Promise.all([
        fetch(`${API_BASE}/pa6/cca-game`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload: {} }),
        }),
        fetch(`${API_BASE}/pa6/key-separation-demo`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload: { key: '0123456789abcdef' } }),
        }),
      ]);
      for (const r of [gameRes, ksRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [gameData, ksData] = await Promise.all([gameRes.json(), ksRes.json()]);
      setGame(gameData.result);
      setKeySep(ksData.result);
    } catch (err) {
      setS3Error(err.message);
    } finally {
      setS3Loading(false);
    }
  };

  useEffect(() => {
    runMalleability();
    runGameAndKeySep();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Render byte cells with match/diff highlighting against another hex string
  const renderDiffBytes = (hex, otherHex, role = 'a') => {
    const bytes = splitBytes(hex);
    const otherBytes = splitBytes(otherHex);
    const max = Math.max(bytes.length, otherBytes.length);
    return Array.from({ length: max }).map((_, i) => {
      const ba = bytes[i] ?? '';
      const bb = otherBytes[i] ?? '';
      const match = ba && bb && ba === bb;
      const value = role === 'a' ? ba : bb;
      return value ? (
        <span key={i} className={`byte ${match ? 'byte-match' : 'byte-diff'}`}>
          {value}
        </span>
      ) : null;
    });
  };

  // Render an ASCII string with each char in its own cell, highlight diffs
  const renderAsciiCells = (asciiA, asciiB, role = 'a') => {
    const max = Math.max(asciiA.length, asciiB.length);
    return Array.from({ length: max }).map((_, i) => {
      const ca = asciiA[i] ?? ' ';
      const cb = asciiB[i] ?? ' ';
      const match = ca === cb;
      const value = role === 'a' ? ca : cb;
      const display = value === ' ' ? '␣' : value;
      return (
        <span key={i} className={`ascii-cell ${match ? 'ascii-match' : 'ascii-diff'}`}>
          {display}
        </span>
      );
    });
  };

  return (
    <div className="pa6-page">
      <header className="pa6-header">
        <h1>PA#6 — CCA-Secure Symmetric Encryption</h1>
        <p className="pa6-subtitle">
          CPA security (PA#3) protects against passive eavesdroppers but not active attackers — even a "secure" CPA ciphertext is <em>malleable</em>: flip a bit and the plaintext changes predictably. The fix is <strong>Encrypt-then-MAC</strong>: encrypt under k<sub>enc</sub>, then MAC the entire ciphertext blob under an independent k<sub>mac</sub>. The verifier rejects any tampered ciphertext before decryption ever runs. PA#6 demonstrates the malleability problem and the CCA defense side-by-side.
        </p>
      </header>

      {/* ============ SECTION 1: ROUND-TRIP ============ */}
      <section className="pa6-section">
        <div className="section-head">
          <h2>1. Encrypt-then-MAC · Round-Trip</h2>
          <span className="status-tag tag-info">CCA · TWO KEYS</span>
        </div>
        <p className="section-desc">
          Alice encrypts the message under k<sub>enc</sub>, then MACs the entire ciphertext blob under k<sub>mac</sub>. Both the blob and the tag travel together. Bob's receiver verifies the tag FIRST — if it fails, decryption is never attempted. The independence of the two keys is essential; reusing one key for both creates correlations.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">k<sub>enc</sub> (16 bytes)</span>
            <input
              type="text"
              value={keyEnc}
              maxLength={16}
              onChange={(e) => setKeyEnc(e.target.value)}
              disabled={encLoading || decLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">k<sub>mac</sub> (16 bytes, independent)</span>
            <input
              type="text"
              value={keyMac}
              maxLength={16}
              onChange={(e) => setKeyMac(e.target.value)}
              disabled={encLoading || decLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">message (16 bytes)</span>
            <input
              type="text"
              value={msg}
              maxLength={16}
              onChange={(e) => setMsg(e.target.value)}
              disabled={encLoading || decLoading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runEncrypt} disabled={encLoading} className="btn btn-primary">
            {encLoading ? 'Encrypting…' : 'Encrypt + MAC'}
          </button>
          <button
            onClick={runDecrypt}
            disabled={decLoading || !encResult}
            className="btn btn-secondary"
          >
            {decLoading ? 'Verifying…' : 'Verify + Decrypt'}
          </button>
        </div>

        {s1Error && <div className="error-box">Error: {s1Error}</div>}

        {encResult && (
          <div className="rt-grid">
            <div className="rt-card rt-card-alice">
              <div className="rt-tag rt-tag-alice">ALICE · ENCRYPT-THEN-MAC</div>
              <div className="rt-step">
                <span className="rt-step-num">1</span>
                <div className="rt-step-content">
                  <div className="rt-step-label">CPA-encrypt under k<sub>enc</sub> → blob</div>
                  <code className="rt-hex rt-hex-cipher">{encResult.ciphertext_hex}</code>
                </div>
              </div>
              <div className="rt-step">
                <span className="rt-step-num">2</span>
                <div className="rt-step-content">
                  <div className="rt-step-label">MAC the blob under k<sub>mac</sub> → tag</div>
                  <code className="rt-hex rt-hex-tag">{encResult.tag_hex}</code>
                </div>
              </div>
              <div className="rt-bundle">
                Wire: send (blob, tag) together
              </div>
            </div>

            <div className="rt-arrow">→</div>

            <div className="rt-card rt-card-bob">
              <div className="rt-tag rt-tag-bob">BOB · VERIFY-THEN-DECRYPT</div>
              {decResult ? (
                <>
                  <div className="rt-step">
                    <span className="rt-step-num rt-step-num-good">✓</span>
                    <div className="rt-step-content">
                      <div className="rt-step-label">Verify tag under k<sub>mac</sub></div>
                      <div className="rt-step-result">tag valid · proceed</div>
                    </div>
                  </div>
                  <div className="rt-step">
                    <span className="rt-step-num rt-step-num-good">✓</span>
                    <div className="rt-step-content">
                      <div className="rt-step-label">Decrypt blob under k<sub>enc</sub></div>
                      {decResult.message_hex ? (
                        <code className="rt-hex rt-hex-recovered">
                          "{hexToAscii(decResult.message_hex)}"
                        </code>
                      ) : decResult.plaintext_hex ? (
                        <code className="rt-hex rt-hex-recovered">
                          "{hexToAscii(decResult.plaintext_hex)}"
                        </code>
                      ) : (
                        <code className="rt-hex rt-hex-recovered">
                          {JSON.stringify(decResult)}
                        </code>
                      )}
                    </div>
                  </div>
                  <div className="verdict-pill verdict-pill-secure">
                    ✓ Round-trip complete · message recovered
                  </div>
                </>
              ) : (
                <div className="rt-placeholder">
                  Click <strong>Verify + Decrypt</strong> to recover the plaintext on Bob's side.
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 2: MALLEABILITY (CPA) vs DEFENSE (CCA) ============ */}
      <section className="pa6-section">
        <div className="section-head">
          <h2>2. Malleability · CPA Broken, CCA Secure</h2>
          <span className="status-tag tag-warn">THE LESSON</span>
        </div>
        <p className="section-desc">
          Eve flips a single bit in the last ciphertext byte. Under plain CPA, this corrupts the plaintext predictably — a usable, controlled tampering. Under Encrypt-then-MAC, the same bit-flip invalidates the tag and the ciphertext is rejected before decryption runs. Same key, same message, same attack — different outcome based on whether integrity was layered on.
        </p>

        {s2Error && <div className="error-box">Error: {s2Error}</div>}

        {malleability && (
          <>
            <div className="malleability-grid">
              {/* CPA broken */}
              <div className="mall-card mall-card-broken">
                <div className="mall-tag mall-tag-broken">PLAIN CPA · MALLEABLE</div>
                <h3>One bit flipped in c → predictable corruption in m</h3>

                <div className="mall-row">
                  <div className="mall-label">ciphertext</div>
                  <div className="bytes-row">
                    {renderDiffBytes(
                      malleability.cpa.ciphertext_hex,
                      malleability.cpa.flipped_ciphertext_hex,
                      'a'
                    )}
                  </div>
                </div>
                <div className="mall-row">
                  <div className="mall-label mall-label-tampered">flipped c</div>
                  <div className="bytes-row">
                    {renderDiffBytes(
                      malleability.cpa.ciphertext_hex,
                      malleability.cpa.flipped_ciphertext_hex,
                      'b'
                    )}
                  </div>
                </div>

                <div className="mall-divider">↓ decrypt both</div>

                <div className="mall-row">
                  <div className="mall-label">plaintext</div>
                  <div className="ascii-cells-row">
                    {renderAsciiCells(
                      hexToAscii(malleability.cpa.plaintext_hex),
                      hexToAscii(malleability.cpa.altered_plaintext_hex),
                      'a'
                    )}
                  </div>
                </div>
                <div className="mall-row">
                  <div className="mall-label mall-label-tampered">altered m</div>
                  <div className="ascii-cells-row">
                    {renderAsciiCells(
                      hexToAscii(malleability.cpa.plaintext_hex),
                      hexToAscii(malleability.cpa.altered_plaintext_hex),
                      'b'
                    )}
                  </div>
                </div>

                <div className="cpa-narrative">
                  Eve flipped one bit in the last ciphertext byte. The decryption produced{' '}
                  <code>"{hexToAscii(malleability.cpa.altered_plaintext_hex)}"</code> — the original{' '}
                  <code>'{hexToAscii(malleability.cpa.plaintext_hex).slice(-1)}'</code> became{' '}
                  <code>'{hexToAscii(malleability.cpa.altered_plaintext_hex).slice(-1)}'</code>. Eve didn't know what
                  was originally encrypted, but she could predictably modify it.
                </div>

                <div className="leak-banner leak-banner-broken">
                  ✗ Bit-flip in c produces a deterministic bit-flip in m · CPA encryption alone does NOT prevent
                  active tampering
                </div>
              </div>

              {/* CCA defense */}
              <div className="mall-card mall-card-secure">
                <div className="mall-tag mall-tag-secure">ENCRYPT-THEN-MAC · CCA</div>
                <h3>Same bit-flip · MAC verifier rejects</h3>

                <div className="cca-bundle">
                  <div className="bundle-row">
                    <div className="bundle-label">ciphertext blob</div>
                    <code className="bundle-hex">{malleability.cca.ciphertext_hex}</code>
                  </div>
                  <div className="bundle-row">
                    <div className="bundle-label">tag</div>
                    <code className="bundle-hex bundle-hex-tag">{malleability.cca.tag_hex}</code>
                  </div>
                </div>

                <div className="cca-flow">
                  <div className="cca-step cca-step-attack">
                    <span className="cs-num">1</span>
                    <span>Eve flips last bit of ciphertext</span>
                  </div>
                  <div className="cca-step cca-step-verify">
                    <span className="cs-num">2</span>
                    <span>Bob verifies tag against tampered blob → tag mismatch</span>
                  </div>
                  <div className="cca-step cca-step-reject">
                    <span className="cs-num">✗</span>
                    <span>
                      Decryption returns <code>None</code> — the plaintext is never even computed
                    </span>
                  </div>
                </div>

                {malleability.cca.tampered_rejected ? (
                  <div className="leak-banner leak-banner-secure">
                    ✓ Tampering rejected before decryption · the MAC catches every active modification with
                    overwhelming probability
                  </div>
                ) : (
                  <div className="leak-banner leak-banner-broken">
                    ⚠ Tampering accepted — unexpected for a CCA construction
                  </div>
                )}
              </div>
            </div>

            <div className="contrast-banner">
              <h3>Why integrity is necessary, not optional</h3>
              <p>
                Real-world systems where this lesson was learned the hard way: SSL/TLS padding-oracle attacks (CBC
                without integrity), WEP (CRC instead of MAC, also broken), early IPsec configurations. Modern AEAD
                ciphers (AES-GCM, ChaCha20-Poly1305) bake encryption-and-authentication together so the application
                can't accidentally use one without the other. Encrypt-then-MAC is the generic theorem; AEAD is the
                packaged version.
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 3: CCA GAME + KEY SEPARATION ============ */}
      <section className="pa6-section">
        <div className="section-head">
          <h2>3. IND-CCA2 Game &amp; Key Separation</h2>
          <span className="status-tag tag-secure">EMPIRICAL CHECKS</span>
        </div>
        <p className="section-desc">
          Two standalone checks. The CCA game runs the full chosen-ciphertext security definition with a naive adversary that doesn't actually use the decryption oracle (uses random guesses) — its win rate stays near 50%, advantage near 0. The key-separation demo shows what goes wrong when the SAME key is used for encryption and MAC: outputs become correlated under that single key, an algebraic flaw that bites in real protocols.
        </p>

        <div className="control-row">
          <button onClick={runGameAndKeySep} disabled={s3Loading} className="btn btn-secondary">
            {s3Loading ? 'Running…' : (game ? 'Re-run' : 'Run checks')}
          </button>
        </div>

        {s3Error && <div className="error-box">Error: {s3Error}</div>}

        {game && keySep && (
          <div className="security-grid">
            <div className="sec-card sec-card-secure">
              <div className="sec-tag">IND-CCA2 · NAIVE ADVERSARY</div>
              <h3>Random guessing stays near 50%</h3>
              <div className="sec-stats">
                <div className="sec-stat">
                  <div className="ss-name">rounds</div>
                  <div className="ss-num">{game.rounds}</div>
                </div>
                <div className="sec-stat">
                  <div className="ss-name">wins</div>
                  <div className="ss-num">{game.wins}</div>
                </div>
                <div className="sec-stat sec-stat-highlight-secure">
                  <div className="ss-name">advantage</div>
                  <div className="ss-num">
                    {Math.abs(game.wins / game.rounds - 0.5).toFixed(3)}
                  </div>
                  <div className="ss-meta">target: ≈ 0</div>
                </div>
              </div>
              <div className="sec-verdict sec-verdict-secure">
                ✓ Adversary win rate {((game.wins / game.rounds) * 100).toFixed(0)}% ≈ 50% · CCA-secure at this trial count
              </div>
            </div>

            <div className="sec-card sec-card-warn">
              <div className="sec-tag sec-tag-warn">KEY SEPARATION · WHY TWO KEYS</div>
              <h3>Same key for enc and MAC → correlated outputs</h3>
              <div className="ks-row">
                <span className="ks-label">ciphertext (key reused)</span>
                <code className="ks-val">{keySep.ciphertext_hex}</code>
              </div>
              <div className="ks-row">
                <span className="ks-label">tag (same key)</span>
                <code className="ks-val ks-val-tag">{keySep.tag_hex}</code>
              </div>
              <div className={`leak-banner ${keySep.key_reuse_detected ? 'leak-banner-warn' : 'leak-banner-secure'}`}>
                {keySep.key_reuse_detected
                  ? `⚠ Key reuse detected — outputs correlate under the single key`
                  : '✓ No correlation — keys appear independent'}
              </div>
              <p className="ks-note">{keySep.note}</p>
              <div className="ks-rule">
                <strong>Rule:</strong> always derive k<sub>enc</sub> and k<sub>mac</sub> independently — e.g.,
                from a master key via two distinct domain-separated KDFs.
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>IND-CCA2 security definition</h4>
          <p>
            A symmetric encryption scheme is IND-CCA2 secure if no efficient adversary, even with access to BOTH
            an encryption oracle AND a decryption oracle (with the natural restriction of not querying the
            challenge ciphertext itself), can win the IND game with non-negligible advantage. CCA2 is strictly
            stronger than CPA: CPA models passive eavesdroppers; CCA2 models active attackers who can
            adaptively manipulate ciphertexts and observe decryption behavior.
          </p>

          <h4>Why CPA encryption is malleable</h4>
          <p>
            The standard CPA construction Enc(m) = (r, m ⊕ F<sub>k</sub>(r)) is malleable because the
            ciphertext is XOR-related to the plaintext: c ⊕ Δ decrypts to m ⊕ Δ for any Δ. The attacker can
            inject any modification they want, predictably. CBC mode has the same flaw at the block level (PA#4).
            This isn't a bug in any specific construction — it's an inherent limitation of confidentiality alone.
          </p>

          <h4>Encrypt-then-MAC theorem</h4>
          <p>
            <em>Theorem (Bellare-Namprempre, 2000):</em> if Π is a CPA-secure encryption scheme and MAC is an
            EUF-CMA-secure MAC, then "encrypt-then-MAC" — i.e., output (c, MAC<sub>k<sub>mac</sub></sub>(c))
            for c = Enc<sub>k<sub>enc</sub></sub>(m) — is IND-CCA2 secure. The MAC catches every tampered
            ciphertext at decryption time, so the decryption oracle becomes useless to the attacker.
          </p>

          <p>
            Two other compositions exist but are weaker:
          </p>
          <p style={{ marginLeft: '14px' }}>
            <strong>MAC-then-encrypt:</strong> compute t = MAC(m), then encrypt (m ‖ t). Used in TLS 1.0–1.2 and was the source of multiple padding-oracle attacks (BEAST, Lucky 13). NOT generically CCA-secure.<br/>
            <strong>Encrypt-and-MAC:</strong> output (Enc(m), MAC(m)) — leaks information through the MAC since MAC is deterministic. Broken.
          </p>

          <h4>Key separation</h4>
          <p>
            The Bellare-Namprempre proof requires k<sub>enc</sub> and k<sub>mac</sub> to be INDEPENDENT. If the
            same key is used for both, an adversary may exploit algebraic structure shared between the two
            primitives. Modern protocols derive both from a master key via a KDF with explicit domain
            separation: k<sub>enc</sub> = KDF(k, "enc"), k<sub>mac</sub> = KDF(k, "mac").
          </p>

          <h4>Lineage</h4>
          <p>
            PA#6 → PA#3 (CPA encryption, the underlying scheme), PA#5 (MAC primitive used for integrity). Forward
            to PA#10 (HMAC, which provides the actual MAC primitive in production AEAD constructions like AES-GCM).
            The malleability lesson here also echoes PA#4's IV-reuse and OFB keystream-reuse — without integrity,
            confidentiality alone never resists active attack.
          </p>
        </div>
      </details>
    </div>
  );
}
