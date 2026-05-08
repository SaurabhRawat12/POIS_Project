import { useState } from 'react';
import './Pa4_ModesPage.css';

const API_BASE = 'http://localhost:8000';

// Split a hex string into 16-byte (32-char) blocks
const splitBlocks = (hex, blockSize = 16) => {
  if (!hex) return [];
  const blocks = [];
  for (let i = 0; i < hex.length; i += blockSize * 2) {
    blocks.push(hex.slice(i, i + blockSize * 2));
  }
  return blocks;
};

// Split a hex string into individual bytes (2 chars each)
const splitBytes = (hex) => (hex ? hex.match(/.{1,2}/g) || [] : []);

// Encode a UTF-8 string to hex
const stringToHex = (s) =>
  Array.from(new TextEncoder().encode(s))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

// Hex to ASCII (printable chars only, dot for non-printable)
const hexToAscii = (hex) =>
  splitBytes(hex)
    .map((byte) => {
      const code = parseInt(byte, 16);
      return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '·';
    })
    .join('');

const MODES = ['ECB', 'CBC', 'CTR', 'OFB'];

export default function Pa4_ModesPage() {
  // Section 1: mode comparison
  const [s1Key, setS1Key] = useState('0123456789abcdef');
  const [s1Msg, setS1Msg] = useState('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  const [s1Results, setS1Results] = useState({});
  const [s1Errors, setS1Errors] = useState({});
  const [s1Loading, setS1Loading] = useState(false);

  // Section 2: round-trip
  const [s2Mode, setS2Mode] = useState('CBC');
  const [s2Key, setS2Key] = useState('0123456789abcdef');
  const [s2Msg, setS2Msg] = useState('Hello, encryption modes!');
  const [s2Enc, setS2Enc] = useState(null);
  const [s2Dec, setS2Dec] = useState(null);
  const [s2Error, setS2Error] = useState(null);
  const [s2EncLoading, setS2EncLoading] = useState(false);
  const [s2DecLoading, setS2DecLoading] = useState(false);

  // Section 3: reuse attacks (defaults share 16-byte prefix so attack is visible)
  const [s3Key, setS3Key] = useState('0123456789abcdef');
  const [s3Iv, setS3Iv] = useState('fedcba9876543210');
  const [s3MsgA, setS3MsgA] = useState('0123456789abcdefAlice PIN: 4242 ');
  const [s3MsgB, setS3MsgB] = useState('0123456789abcdefBob   PIN: 9876 ');
  const [s3Cbc, setS3Cbc] = useState(null);
  const [s3Ofb, setS3Ofb] = useState(null);
  const [s3Error, setS3Error] = useState(null);
  const [s3Loading, setS3Loading] = useState(false);

  const runModeComparison = async () => {
    setS1Loading(true);
    setS1Errors({});
    setS1Results({});
    const headers = { 'Content-Type': 'application/json' };

    const tasks = MODES.map((mode) =>
      fetch(`${API_BASE}/pa4/encrypt`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ payload: { mode, key: s1Key, message: s1Msg } }),
      })
        .then(async (res) => {
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.json();
        })
        .then((data) => [mode, data.result, null])
        .catch((err) => [mode, null, err.message])
    );

    const results = await Promise.all(tasks);
    const successResults = {};
    const errorResults = {};
    for (const [mode, result, error] of results) {
      if (result) successResults[mode] = result;
      if (error) errorResults[mode] = error;
    }
    setS1Results(successResults);
    setS1Errors(errorResults);
    setS1Loading(false);
  };

  const runEncrypt = async () => {
    setS2EncLoading(true);
    setS2Error(null);
    setS2Dec(null);
    setS2Enc(null);
    try {
      const res = await fetch(`${API_BASE}/pa4/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: { mode: s2Mode, key: s2Key, message: s2Msg } }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setS2Enc(data.result);
    } catch (err) {
      setS2Error(err.message);
    } finally {
      setS2EncLoading(false);
    }
  };

  const runDecrypt = async () => {
    if (!s2Enc) return;
    setS2DecLoading(true);
    setS2Error(null);
    try {
      const payload = {
        mode: s2Mode,
        key: s2Key,
        ciphertext_hex: s2Enc.ciphertext,
      };
      if (s2Mode === 'CBC' || s2Mode === 'OFB') {
        payload.iv_hex = s2Enc.iv;
      } else if (s2Mode === 'CTR') {
        payload.nonce_hex = s2Enc.nonce;
      }

      const res = await fetch(`${API_BASE}/pa4/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setS2Dec(data.result);
    } catch (err) {
      setS2Error(err.message);
    } finally {
      setS2DecLoading(false);
    }
  };

  const runReuseAttacks = async () => {
    setS3Loading(true);
    setS3Error(null);
    setS3Cbc(null);
    setS3Ofb(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const payload = {
        key: s3Key,
        iv: s3Iv,
        message_a: s3MsgA,
        message_b: s3MsgB,
      };
      const [cbcRes, ofbRes] = await Promise.all([
        fetch(`${API_BASE}/pa4/cbc-iv-reuse-demo`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload }),
        }),
        fetch(`${API_BASE}/pa4/ofb-reuse-demo`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload }),
        }),
      ]);
      for (const r of [cbcRes, ofbRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [cbcData, ofbData] = await Promise.all([cbcRes.json(), ofbRes.json()]);
      setS3Cbc(cbcData.result);
      setS3Ofb(ofbData.result);
    } catch (err) {
      setS3Error(err.message);
    } finally {
      setS3Loading(false);
    }
  };

  // Helpers for rendering ciphertext byte-by-byte with diff coloring
  const renderColoredBytes = (hexA, hexB, role = 'a') => {
    const bytesA = splitBytes(hexA);
    const bytesB = splitBytes(hexB);
    const max = Math.max(bytesA.length, bytesB.length);
    return Array.from({ length: max }).map((_, i) => {
      const ba = bytesA[i] ?? '';
      const bb = bytesB[i] ?? '';
      const match = ba && bb && ba === bb;
      const cls = match ? 'byte-match' : 'byte-diff';
      const value = role === 'a' ? ba : bb;
      return value ? (
        <span key={i} className={`byte ${cls}`}>
          {value}
        </span>
      ) : null;
    });
  };

  // Render XOR row for OFB demo with 0s subtle and non-zeros highlighted
  const renderXorBytes = (hex) =>
    splitBytes(hex).map((byte, i) => (
      <span key={i} className={`byte ${byte === '00' ? 'byte-zero' : 'byte-leak'}`}>
        {byte}
      </span>
    ));

  return (
    <div className="pa4-page">
      <header className="pa4-header">
        <h1>PA#4 — Block Cipher Modes of Operation</h1>
        <p className="pa4-subtitle">
          A block cipher encrypts a single fixed-size block. To encrypt longer messages, you choose a <em>mode of operation</em> that defines how blocks are chained. PA#4 demonstrates four modes (ECB, CBC, CTR, OFB) and the catastrophic security failures that follow from misusing IVs/nonces.
        </p>
      </header>

      {/* ============ SECTION 1: MODE COMPARISON ============ */}
      <section className="pa4-section">
        <div className="section-head">
          <h2>1. Mode Comparison · Same Plaintext, Four Modes</h2>
          <span className="status-tag tag-info">RANDOMIZATION CHECK</span>
        </div>
        <p className="section-desc">
          Encrypt the same plaintext four times — once per mode. Modes that draw a fresh IV/nonce produce different-looking ciphertexts. ECB has no IV: identical plaintext blocks always map to identical ciphertext blocks, leaking the pattern. With the default input (32 bytes of repeating <code>'A'</code>), the two 16-byte plaintext blocks are identical — a deterministic mode would produce two identical ciphertext blocks too.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key (16 bytes)</span>
            <input
              type="text"
              value={s1Key}
              maxLength={16}
              onChange={(e) => setS1Key(e.target.value)}
              disabled={s1Loading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">plaintext message</span>
            <input
              type="text"
              value={s1Msg}
              onChange={(e) => setS1Msg(e.target.value)}
              disabled={s1Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runModeComparison} disabled={s1Loading} className="btn btn-primary">
            {s1Loading ? 'Encrypting…' : 'Encrypt in all 4 modes'}
          </button>
        </div>

        {(Object.keys(s1Results).length > 0 || Object.keys(s1Errors).length > 0) && (
          <>
            <div className="plaintext-strip">
              <span className="strip-label">PLAINTEXT (hex bytes)</span>
              <div className="bytes-row">
                {splitBytes(stringToHex(s1Msg)).map((b, i) => (
                  <span key={i} className="byte byte-plain">{b}</span>
                ))}
              </div>
            </div>

            <div className="modes-grid">
              {MODES.map((mode) => {
                const result = s1Results[mode];
                const error = s1Errors[mode];
                if (error) {
                  return (
                    <div key={mode} className="mode-card mode-card-error">
                      <div className="mode-tag mode-tag-error">{mode} · UNAVAILABLE</div>
                      <p className="mode-error">
                        Backend returned an error: <code>{error}</code>
                      </p>
                      {mode === 'ECB' && (
                        <p className="mode-error-hint">
                          ECB on this build is broken. When fixed, it would visibly show <strong>two identical 16-byte ciphertext blocks</strong> for this input — the canonical "ECB penguin" pattern.
                        </p>
                      )}
                    </div>
                  );
                }
                if (!result) return null;
                const cipherBlocks = splitBlocks(result.ciphertext);
                const ivOrNonce = result.iv || result.nonce;
                const ivLabel = result.iv ? 'IV' : (result.nonce ? 'nonce' : null);
                // Detect if any ciphertext blocks repeat (would indicate ECB-like leak)
                const hasBlockRepeat =
                  cipherBlocks.length > 1 &&
                  new Set(cipherBlocks).size < cipherBlocks.length;
                return (
                  <div key={mode} className={`mode-card ${hasBlockRepeat ? 'mode-card-leak' : ''}`}>
                    <div className="mode-tag">{mode}</div>
                    {ivLabel && (
                      <div className="mode-iv-row">
                        <span className="mode-iv-label">{ivLabel}</span>
                        <code className="mono mode-iv-val">{ivOrNonce}</code>
                      </div>
                    )}
                    <div className="cipher-blocks">
                      {cipherBlocks.map((blk, i) => (
                        <div key={i} className="cipher-block-row">
                          <span className="block-idx">block {i}</span>
                          <code className="mono block-hex">{blk}</code>
                        </div>
                      ))}
                    </div>
                    {hasBlockRepeat && (
                      <div className="leak-pill">⚠ identical blocks detected</div>
                    )}
                    {!hasBlockRepeat && cipherBlocks.length > 1 && (
                      <div className="ok-pill">✓ all blocks distinct</div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 2: ENCRYPT/DECRYPT ROUND-TRIP ============ */}
      <section className="pa4-section">
        <div className="section-head">
          <h2>2. Encrypt / Decrypt Round-Trip</h2>
          <span className="status-tag tag-info">CORRECTNESS</span>
        </div>
        <p className="section-desc">
          Pick a mode, encrypt a message, then decrypt the resulting ciphertext using the same key and IV/nonce. Decryption recovers the original plaintext exactly — this is the basic correctness property all modes share.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">mode</span>
            <select
              value={s2Mode}
              onChange={(e) => setS2Mode(e.target.value)}
              disabled={s2EncLoading || s2DecLoading}
              className="ctrl-input"
            >
              <option value="CBC">CBC</option>
              <option value="CTR">CTR</option>
              <option value="OFB">OFB</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">key (16 bytes)</span>
            <input
              type="text"
              value={s2Key}
              maxLength={16}
              onChange={(e) => setS2Key(e.target.value)}
              disabled={s2EncLoading || s2DecLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">message</span>
            <input
              type="text"
              value={s2Msg}
              onChange={(e) => setS2Msg(e.target.value)}
              disabled={s2EncLoading || s2DecLoading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runEncrypt} disabled={s2EncLoading} className="btn btn-primary">
            {s2EncLoading ? 'Encrypting…' : 'Encrypt'}
          </button>
          <button
            onClick={runDecrypt}
            disabled={s2DecLoading || !s2Enc}
            className="btn btn-secondary"
          >
            {s2DecLoading ? 'Decrypting…' : 'Decrypt'}
          </button>
        </div>

        {s2Error && <div className="error-box">Error: {s2Error}</div>}

        {s2Enc && (
          <div className="rt-grid">
            <div className="rt-card rt-card-enc">
              <div className="rt-tag rt-tag-enc">ENCRYPT · {s2Mode}</div>
              <div className="rt-kv">
                <span className="rt-key">{s2Enc.iv ? 'IV' : 'nonce'}</span>
                <code className="mono rt-val">{s2Enc.iv || s2Enc.nonce}</code>
              </div>
              <div className="rt-kv">
                <span className="rt-key">ciphertext</span>
                <code className="mono rt-val rt-cipher">{s2Enc.ciphertext}</code>
              </div>
            </div>
            <div className="rt-arrow">→</div>
            <div className="rt-card rt-card-dec">
              <div className="rt-tag rt-tag-dec">DECRYPT · {s2Mode}</div>
              {s2Dec ? (
                <>
                  <div className="rt-kv">
                    <span className="rt-key">recovered hex</span>
                    <code className="mono rt-val">{s2Dec.message_hex}</code>
                  </div>
                  <div className="rt-kv">
                    <span className="rt-key">as ASCII</span>
                    <code className="mono rt-val rt-ascii">"{hexToAscii(s2Dec.message_hex)}"</code>
                  </div>
                  {hexToAscii(s2Dec.message_hex) === s2Msg ? (
                    <div className="verdict-pill verdict-pill-secure">✓ m' = m · round-trip</div>
                  ) : (
                    <div className="verdict-pill verdict-pill-broken">✗ m' ≠ m</div>
                  )}
                </>
              ) : (
                <div className="rt-placeholder">
                  Click <strong>Decrypt</strong> to recover the plaintext.
                </div>
              )}
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 3: REUSE ATTACKS ============ */}
      <section className="pa4-section">
        <div className="section-head">
          <h2>3. IV / Keystream Reuse · The Lesson</h2>
          <span className="status-tag tag-warn">CATASTROPHIC FAILURE</span>
        </div>
        <p className="section-desc">
          Encrypt two messages under the <em>same</em> key and <em>same</em> IV. Both modes break, in different ways. CBC: identical leading plaintext blocks produce identical ciphertext blocks, leaking the prefix. OFB: ciphertext_a XOR ciphertext_b = plaintext_a XOR plaintext_b, leaking everywhere the plaintexts agree or disagree. Defaults below share a 16-byte prefix so the CBC attack triggers; if you change the messages, the demo updates.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key (16 bytes)</span>
            <input
              type="text"
              value={s3Key}
              maxLength={16}
              onChange={(e) => setS3Key(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">IV (16 bytes)</span>
            <input
              type="text"
              value={s3Iv}
              maxLength={16}
              onChange={(e) => setS3Iv(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">message A</span>
            <input
              type="text"
              value={s3MsgA}
              onChange={(e) => setS3MsgA(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <label>
            <span className="ctrl-label">message B</span>
            <input
              type="text"
              value={s3MsgB}
              onChange={(e) => setS3MsgB(e.target.value)}
              disabled={s3Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runReuseAttacks} disabled={s3Loading} className="btn btn-primary">
            {s3Loading ? 'Running…' : 'Run both attacks'}
          </button>
        </div>

        {s3Error && <div className="error-box">Error: {s3Error}</div>}

        {(s3Cbc || s3Ofb) && (
          <div className="attacks-grid">
            {/* CBC attack */}
            {s3Cbc && (
              <div className="attack-card attack-card-cbc">
                <div className="attack-tag attack-tag-cbc">CBC IV-REUSE</div>
                <h3>Same first plaintext block ⇒ same first ciphertext block</h3>

                <div className="cipher-row">
                  <span className="cipher-label">A</span>
                  <div className="bytes-row">
                    {splitBlocks(s3Cbc.cipher_a_hex).map((blk, i) => {
                      const matches = s3Cbc.same_block_indices.includes(i);
                      return (
                        <code
                          key={i}
                          className={`block-cell mono ${matches ? 'block-cell-match' : 'block-cell-diff'}`}
                        >
                          {blk}
                        </code>
                      );
                    })}
                  </div>
                </div>
                <div className="cipher-row">
                  <span className="cipher-label">B</span>
                  <div className="bytes-row">
                    {splitBlocks(s3Cbc.cipher_b_hex).map((blk, i) => {
                      const matches = s3Cbc.same_block_indices.includes(i);
                      return (
                        <code
                          key={i}
                          className={`block-cell mono ${matches ? 'block-cell-match' : 'block-cell-diff'}`}
                        >
                          {blk}
                        </code>
                      );
                    })}
                  </div>
                </div>

                <div className="attack-stats">
                  <div className="attack-stat">
                    <span className="as-name">blocks compared</span>
                    <span className="as-num">{s3Cbc.blocks_compared}</span>
                  </div>
                  <div className="attack-stat">
                    <span className="as-name">matching blocks</span>
                    <span className={`as-num ${s3Cbc.same_block_indices.length > 0 ? 'as-num-leak' : ''}`}>
                      {s3Cbc.same_block_indices.length}
                    </span>
                  </div>
                </div>

                {s3Cbc.same_block_indices.length > 0 ? (
                  <div className="leak-banner leak-banner-broken">
                    ⚠ Block{s3Cbc.same_block_indices.length > 1 ? 's' : ''} {s3Cbc.same_block_indices.join(', ')} match · attacker learns the corresponding plaintext block{s3Cbc.same_block_indices.length > 1 ? 's are' : ' is'} identical
                  </div>
                ) : (
                  <div className="leak-banner leak-banner-info">
                    No matching blocks — the messages differ in the first 16 bytes. Try messages with a shared 16-byte prefix to trigger the leak.
                  </div>
                )}
              </div>
            )}

            {/* OFB attack */}
            {s3Ofb && (
              <div className="attack-card attack-card-ofb">
                <div className="attack-tag attack-tag-ofb">OFB KEYSTREAM-REUSE</div>
                <h3>cipher<sub>A</sub> ⊕ cipher<sub>B</sub> = plaintext<sub>A</sub> ⊕ plaintext<sub>B</sub></h3>

                <div className="cipher-row">
                  <span className="cipher-label">cipher A</span>
                  <div className="bytes-row bytes-row-tight">
                    {renderColoredBytes(s3Ofb.cipher_a_hex, s3Ofb.cipher_b_hex, 'a')}
                  </div>
                </div>
                <div className="cipher-row">
                  <span className="cipher-label">cipher B</span>
                  <div className="bytes-row bytes-row-tight">
                    {renderColoredBytes(s3Ofb.cipher_a_hex, s3Ofb.cipher_b_hex, 'b')}
                  </div>
                </div>
                <div className="cipher-row cipher-row-divider">
                  <span className="cipher-label cipher-label-xor">XOR</span>
                  <div className="bytes-row bytes-row-tight">
                    {renderXorBytes(s3Ofb.xor_cipher_hex)}
                  </div>
                </div>

                <div className="xor-identity">
                  <div className="xor-row">
                    <span className="xor-label">xor of ciphertexts</span>
                    <code className="mono xor-val">{s3Ofb.xor_cipher_hex}</code>
                  </div>
                  <div className="xor-equals">
                    {s3Ofb.xor_matches ? '═══' : '✗'}
                  </div>
                  <div className="xor-row">
                    <span className="xor-label">xor of plaintexts</span>
                    <code className="mono xor-val">{s3Ofb.xor_message_hex}</code>
                  </div>
                </div>

                {s3Ofb.xor_matches ? (
                  <div className="leak-banner leak-banner-broken">
                    ⚠ Identity verified · attacker recovers m<sub>A</sub> ⊕ m<sub>B</sub> directly. With ANY known plaintext, both are revealed.
                  </div>
                ) : (
                  <div className="leak-banner leak-banner-info">XOR identity did not hold — unexpected.</div>
                )}
              </div>
            )}
          </div>
        )}

        {s3Cbc && s3Ofb && (
          <div className="contrast-banner">
            <h3>Same key. Same IV. Different mode, different leak — but both broken.</h3>
            <p>
              Both modes are <em>provably</em> CPA-secure when used correctly (fresh IV/nonce per encryption). They both fail when the discipline is dropped. CBC leaks block-equality information; OFB leaks the full XOR of the two plaintexts. The fix in both cases is the same: <strong>never reuse an IV/nonce under the same key</strong>. Modern AEAD modes (AES-GCM, ChaCha20-Poly1305) treat nonce reuse as a critical violation that compromises both confidentiality and integrity.
            </p>
          </div>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Block cipher modes</h4>
          <p>
            A block cipher E<sub>k</sub>: {'{0,1}'}<sup>n</sup> → {'{0,1}'}<sup>n</sup> is a length-preserving keyed permutation. To encrypt a longer message m = m<sub>1</sub>m<sub>2</sub>…m<sub>L</sub> (each m<sub>i</sub> a single block), we use a mode that defines how blocks chain.
          </p>

          <h4>The four modes shown here</h4>
          <p>
            <strong>ECB</strong> (Electronic Codebook): c<sub>i</sub> = E<sub>k</sub>(m<sub>i</sub>). Deterministic, parallelizable, but identical plaintext blocks produce identical ciphertext blocks — pattern leak.<br/>
            <strong>CBC</strong> (Cipher Block Chaining): c<sub>i</sub> = E<sub>k</sub>(m<sub>i</sub> ⊕ c<sub>i−1</sub>) with c<sub>0</sub> = IV. Hides patterns when IV is fresh; sequential.<br/>
            <strong>CTR</strong> (Counter): c<sub>i</sub> = m<sub>i</sub> ⊕ E<sub>k</sub>(nonce ‖ i). Stream-cipher-like, parallelizable, fast.<br/>
            <strong>OFB</strong> (Output Feedback): keystream s<sub>0</sub> = IV, s<sub>i</sub> = E<sub>k</sub>(s<sub>i−1</sub>); c<sub>i</sub> = m<sub>i</sub> ⊕ s<sub>i</sub>. Stream-like, sequential.
          </p>

          <h4>Why ECB leaks patterns</h4>
          <p>
            ECB has no IV/nonce — encryption of a block depends only on the block and the key. So m<sub>i</sub> = m<sub>j</sub> implies c<sub>i</sub> = c<sub>j</sub> deterministically. The famous "ECB penguin" image (Tux encrypted in ECB still recognizable) visualizes this: large solid-colored regions in the original become large solid-colored regions of the same encrypted color in the ciphertext. With our 32-byte all-A input, both 16-byte plaintext blocks would encrypt to the same 16-byte ciphertext block.
          </p>

          <h4>Why CBC IV reuse leaks the prefix</h4>
          <p>
            With IV reused: c<sub>1</sub><sup>A</sup> = E<sub>k</sub>(m<sub>1</sub><sup>A</sup> ⊕ IV), c<sub>1</sub><sup>B</sup> = E<sub>k</sub>(m<sub>1</sub><sup>B</sup> ⊕ IV). If m<sub>1</sub><sup>A</sup> = m<sub>1</sub><sup>B</sup>, the inputs to E<sub>k</sub> are identical, so the outputs are identical. The attacker sees c<sub>1</sub><sup>A</sup> = c<sub>1</sub><sup>B</sup> and learns the plaintexts share the first block. The chain breaks downstream — once any block differs, the cascade randomizes everything after.
          </p>

          <h4>Why OFB keystream reuse is total disaster</h4>
          <p>
            OFB's keystream s<sub>1</sub>s<sub>2</sub>…s<sub>L</sub> depends only on key and IV — NOT on the plaintext. So with the same (key, IV) the keystream is identical. Then c<sup>A</sup> ⊕ c<sup>B</sup> = (m<sup>A</sup> ⊕ s) ⊕ (m<sup>B</sup> ⊕ s) = m<sup>A</sup> ⊕ m<sup>B</sup>. The keystream cancels out completely. The XOR of the two plaintexts leaks in full. With ANY one plaintext known (e.g., a known protocol header), both messages are completely recovered.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#4 uses a toy Feistel block cipher to demonstrate the modes — production systems would plug in AES. The CPA-security argument from PA#3 applies here too: each correctly-used mode is a probabilistic encryption scheme with a PRF underneath. The reuse failures in this section are the same family of bug as PA#3's nonce-reuse demo, lifted to multi-block messages with mode-specific leak shapes.
          </p>
        </div>
      </details>
    </div>
  );
}
