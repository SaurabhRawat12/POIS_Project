import { useState, useEffect } from 'react';
import './Pa7_MdHashPage.css';

const API_BASE = 'http://localhost:8000';

const splitBytes = (hex) => (hex ? hex.match(/.{1,2}/g) || [] : []);

const hexToAscii = (hex) =>
  splitBytes(hex)
    .map((byte) => {
      const code = parseInt(byte, 16);
      return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '·';
    })
    .join('');

export default function Pa7_MdHashPage() {
  // Section 1: hash a message
  const [s1Msg, setS1Msg] = useState('Hello, hash function!');
  const [s1Result, setS1Result] = useState(null);
  const [s1Error, setS1Error] = useState(null);
  const [s1Loading, setS1Loading] = useState(false);

  // Section 2: avalanche comparison
  const [s2MsgA, setS2MsgA] = useState('Pay Alice $100');
  const [s2MsgB, setS2MsgB] = useState('Pay Alice $200');
  const [s2HashA, setS2HashA] = useState(null);
  const [s2HashB, setS2HashB] = useState(null);
  const [s2Trace, setS2Trace] = useState(null);
  const [s2Error, setS2Error] = useState(null);
  const [s2Loading, setS2Loading] = useState(false);

  // Section 3: collision demo (auto-load)
  const [collision, setCollision] = useState(null);
  const [s3Error, setS3Error] = useState(null);
  const [s3Loading, setS3Loading] = useState(false);

  const runHash = async () => {
    setS1Loading(true);
    setS1Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa7/md-hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: { message: s1Msg } }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setS1Result({ ...data.result, ...data.trace });
    } catch (err) {
      setS1Error(err.message);
    } finally {
      setS1Loading(false);
    }
  };

  const runAvalanche = async () => {
    setS2Loading(true);
    setS2Error(null);
    setS2HashA(null);
    setS2HashB(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const [resA, resB] = await Promise.all([
        fetch(`${API_BASE}/pa7/md-hash`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload: { message: s2MsgA } }),
        }),
        fetch(`${API_BASE}/pa7/md-hash`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ payload: { message: s2MsgB } }),
        }),
      ]);
      for (const r of [resA, resB]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [dataA, dataB] = await Promise.all([resA.json(), resB.json()]);
      setS2HashA(dataA.result.hash_hex);
      setS2HashB(dataB.result.hash_hex);
      setS2Trace(dataA.result.contract || dataA.trace);
    } catch (err) {
      setS2Error(err.message);
    } finally {
      setS2Loading(false);
    }
  };

  const runCollision = async () => {
    setS3Loading(true);
    setS3Error(null);
    try {
      const res = await fetch(`${API_BASE}/pa7/collision-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: {} }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setCollision(data.result);
    } catch (err) {
      setS3Error(err.message);
    } finally {
      setS3Loading(false);
    }
  };

  useEffect(() => {
    runCollision();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Render hash bytes as colored cells
  const renderHashBytes = (hex, mode = 'normal') => {
    return splitBytes(hex).map((byte, i) => (
      <span key={i} className={`hash-byte hash-byte-${mode}`}>
        {byte}
      </span>
    ));
  };

  // Compare two hex strings byte-by-byte; return cells colored match/diff
  const renderDiffBytes = (hexA, hexB, role = 'a') => {
    const bytesA = splitBytes(hexA);
    const bytesB = splitBytes(hexB);
    const max = Math.max(bytesA.length, bytesB.length);
    return Array.from({ length: max }).map((_, i) => {
      const ba = bytesA[i] ?? '';
      const bb = bytesB[i] ?? '';
      const match = ba && bb && ba === bb;
      const value = role === 'a' ? ba : bb;
      return value ? (
        <span key={i} className={`hash-byte ${match ? 'hash-byte-match' : 'hash-byte-diff'}`}>
          {value}
        </span>
      ) : null;
    });
  };

  // Count diff bytes between two hex strings
  const countDiff = (hexA, hexB) => {
    const bytesA = splitBytes(hexA);
    const bytesB = splitBytes(hexB);
    let diffs = 0;
    for (let i = 0; i < Math.max(bytesA.length, bytesB.length); i++) {
      if (bytesA[i] !== bytesB[i]) diffs++;
    }
    return diffs;
  };

  return (
    <div className="pa7-page">
      <header className="pa7-header">
        <h1>PA#7 — Merkle-Damgård Hash Construction</h1>
        <p className="pa7-subtitle">
          Most production hash functions (MD5, SHA-1, SHA-2 family) use the Merkle-Damgård construction: take a fixed-input compression function f, initialize a state to a fixed IV, then iteratively absorb message blocks. PA#7 demonstrates the construction on a toy 16-bit hash and shows the structural attack that breaks it: any collision in the compression function propagates to a full-hash collision when extended with any shared suffix.
        </p>
      </header>

      {/* ============ SECTION 1: HASH MECHANICS ============ */}
      <section className="pa7-section">
        <div className="section-head">
          <h2>1. Hash a Message</h2>
          <span className="status-tag tag-info">FORWARD ONLY</span>
        </div>
        <p className="section-desc">
          Compute h = MDHash(m) for a message of any length. The toy hash uses a 16-byte block size and a 2-byte (16-bit) digest. Real hashes (SHA-256) use 64-byte blocks and 256-bit digests; the structure is identical, only the parameter sizes differ.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">message ({s1Msg.length} bytes)</span>
            <input
              type="text"
              value={s1Msg}
              onChange={(e) => setS1Msg(e.target.value)}
              disabled={s1Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runHash} disabled={s1Loading} className="btn btn-primary">
            {s1Loading ? 'Hashing…' : 'Hash'}
          </button>
        </div>

        {s1Error && <div className="error-box">Error: {s1Error}</div>}

        {s1Result && (
          <div className="hash-result-card">
            <div className="hrc-tag">{s1Result.contract?.name || 'TOY-MD'} · HASH</div>

            <div className="hash-display-row">
              <span className="hd-label">h(m) =</span>
              <div className="hash-bytes-row">
                {renderHashBytes(s1Result.hash_hex, 'output')}
              </div>
              <span className="hd-meta">
                {s1Result.hash_hex.length / 2} bytes · {(s1Result.hash_hex.length / 2) * 8} bits
              </span>
            </div>

            {s1Result.contract && (
              <div className="contract-row">
                <div className="contract-tile">
                  <span className="ct-name">scheme</span>
                  <code className="ct-val">{s1Result.contract.name}</code>
                </div>
                <div className="contract-tile">
                  <span className="ct-name">block size</span>
                  <code className="ct-val">{s1Result.contract.block_size} B</code>
                </div>
                <div className="contract-tile">
                  <span className="ct-name">digest size</span>
                  <code className="ct-val">{s1Result.contract.digest_size} B</code>
                </div>
                <div className="contract-tile">
                  <span className="ct-name">message length</span>
                  <code className="ct-val">{s1Result.message_len ?? s1Msg.length} B</code>
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ============ SECTION 2: AVALANCHE ============ */}
      <section className="pa7-section">
        <div className="section-head">
          <h2>2. Avalanche · Sensitivity to Input Changes</h2>
          <span className="status-tag tag-info">DIFFUSION CHECK</span>
        </div>
        <p className="section-desc">
          A cryptographic hash should change unpredictably with any input change — flipping one bit of m should change about half the bits of h(m). Compare two near-identical messages and watch how their hashes diverge. <em>At toy 16-bit size, two random messages have a 1 in 65,536 chance of accidentally colliding — at SHA-256's 256-bit size, the probability is astronomically smaller.</em>
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">message A</span>
            <input
              type="text"
              value={s2MsgA}
              onChange={(e) => setS2MsgA(e.target.value)}
              disabled={s2Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <label>
            <span className="ctrl-label">message B</span>
            <input
              type="text"
              value={s2MsgB}
              onChange={(e) => setS2MsgB(e.target.value)}
              disabled={s2Loading}
              className="ctrl-input mono-input ctrl-input-wide"
            />
          </label>
          <button onClick={runAvalanche} disabled={s2Loading} className="btn btn-primary">
            {s2Loading ? 'Hashing both…' : 'Compare hashes'}
          </button>
        </div>

        {s2Error && <div className="error-box">Error: {s2Error}</div>}

        {s2HashA && s2HashB && (
          <div className="avalanche-card">
            <div className="ava-row">
              <div className="ava-side">
                <div className="ava-tag ava-tag-a">MESSAGE A</div>
                <code className="ava-msg">"{s2MsgA}"</code>
                <div className="ava-arrow">↓ MDHash</div>
                <div className="hash-bytes-row">
                  {renderDiffBytes(s2HashA, s2HashB, 'a')}
                </div>
              </div>
              <div className="ava-vs">vs</div>
              <div className="ava-side">
                <div className="ava-tag ava-tag-b">MESSAGE B</div>
                <code className="ava-msg">"{s2MsgB}"</code>
                <div className="ava-arrow">↓ MDHash</div>
                <div className="hash-bytes-row">
                  {renderDiffBytes(s2HashA, s2HashB, 'b')}
                </div>
              </div>
            </div>

            {s2HashA === s2HashB ? (
              <div className="ava-verdict ava-verdict-collision">
                ⚠ COLLISION! Both messages produce hash <code>{s2HashA}</code>. At 16-bit toy size, random collisions occur about 1 in 65,536 hashes. At SHA-256 scale, this would be a major cryptographic event.
              </div>
            ) : (
              <div className="ava-verdict ava-verdict-diffused">
                ✓ Hashes differ in {countDiff(s2HashA, s2HashB)} of {splitBytes(s2HashA).length} bytes — input change diffused through the entire output. Even a single-character change in m produces a fully different h(m).
              </div>
            )}
          </div>
        )}
      </section>

      {/* ============ SECTION 3: COLLISION PROPAGATION ============ */}
      <section className="pa7-section">
        <div className="section-head">
          <h2>3. Collision Propagation · MD's Achilles' Heel</h2>
          <span className="status-tag tag-broken">STRUCTURAL ATTACK</span>
        </div>
        <p className="section-desc">
          The Merkle-Damgård theorem says: if you find ANY pair of distinct blocks (a, b) such that f(IV, a) = f(IV, b) — a single collision in the compression function — you can extend them with any shared suffix and the resulting messages still collide. The auto-loaded demo below uses brute force (feasible only at toy size) to find such a pair. Once found, the collision is immortal: any suffix you append produces a full-hash collision.
        </p>

        <div className="control-row">
          <button onClick={runCollision} disabled={s3Loading} className="btn btn-secondary">
            {s3Loading ? 'Searching…' : (collision ? 'Find another collision' : 'Find collision')}
          </button>
        </div>

        {s3Error && <div className="error-box">Error: {s3Error}</div>}

        {collision && (
          <div className="collision-flow">
            {/* Top tier: two distinct blocks */}
            <div className="collision-tier-blocks">
              <div className="cb-card cb-card-a">
                <div className="cb-tag cb-tag-a">MESSAGE A · BLOCK 1</div>
                <code className="cb-hex">{collision.block_a_hex}</code>
                <div className="cb-meta">16 bytes · distinct from B</div>
              </div>
              <div className="cb-card cb-card-b">
                <div className="cb-tag cb-tag-b">MESSAGE B · BLOCK 1</div>
                <code className="cb-hex">{collision.block_b_hex}</code>
                <div className="cb-meta">16 bytes · distinct from A</div>
              </div>
            </div>

            {/* Convergence */}
            <div className="collision-converge">
              <div className="converge-arrow converge-arrow-left">↘</div>
              <div className="converge-text">f(IV, ·)</div>
              <div className="converge-arrow converge-arrow-right">↙</div>
            </div>

            {/* Internal state collision */}
            <div className="collision-state">
              <div className="cs-tag">⚠ COLLISION POINT · INTERNAL STATE</div>
              <code className="cs-hex">{collision.internal_state_hex}</code>
              <div className="cs-note">
                f(IV, block_a) = f(IV, block_b) = <code>{collision.internal_state_hex}</code>. The chain has merged. From this point forward both messages are computationally indistinguishable to the hash.
              </div>
            </div>

            <div className="collision-arrow-down">↓</div>

            {/* Shared suffix */}
            <div className="collision-suffix">
              <div className="cf-tag">SHARED SUFFIX (appended to both)</div>
              <code className="cf-hex">{collision.suffix_hex}</code>
              {hexToAscii(collision.suffix_hex) && (
                <div className="cf-decoded">
                  ASCII: "<span>{hexToAscii(collision.suffix_hex)}</span>"
                </div>
              )}
            </div>

            <div className="collision-arrow-down">↓</div>

            {/* Final hashes */}
            <div className="collision-final">
              <div className="cfn-tag">FINAL HASH · IDENTICAL</div>
              <div className="cfn-pair">
                <div className="cfn-side">
                  <span className="cfn-side-label">h(A)</span>
                  <code className="cfn-hex">{collision.hash_a_hex}</code>
                </div>
                <span className="cfn-equals">{collision.hashes_equal ? '===' : '≠'}</span>
                <div className="cfn-side">
                  <span className="cfn-side-label">h(B)</span>
                  <code className="cfn-hex">{collision.hash_b_hex}</code>
                </div>
              </div>
            </div>

            <div className={`collision-verdict ${collision.collision_found ? 'cv-broken' : 'cv-defeated'}`}>
              {collision.collision_found ? (
                <>
                  ✗ <strong>COLLISION FOUND</strong> — two distinct messages, identical hash. The MD construction is only as strong as its compression function: at toy 16-bit output, finding a collision takes ~256 random tries (birthday bound 2<sup>n/2</sup>). At SHA-256's 256-bit output, the same brute-force takes 2<sup>128</sup> tries — far beyond any conceivable adversary.
                </>
              ) : (
                <>✓ No collision found — try again or expand the search space.</>
              )}
            </div>

            <div className="forward-banner">
              <strong>Why this matters:</strong> the MD structure makes <em>finding</em> collisions hard (parameterized by output size), but once found, collisions <em>extend</em> trivially — any shared suffix produces a full collision. This is also why <code>tag = H(k ‖ m)</code> is broken (PA#5's length-extension attack). HMAC's two-pass structure (PA#10) sidesteps both issues.
            </div>
          </div>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Merkle-Damgård construction</h4>
          <p>
            Given a fixed-input compression function f: {'{0,1}'}<sup>n</sup> × {'{0,1}'}<sup>b</sup> → {'{0,1}'}<sup>n</sup>, build a hash function H: {'{0,1}'}<sup>*</sup> → {'{0,1}'}<sup>n</sup>:
          </p>
          <p style={{ marginLeft: '14px' }}>
            <code>state<sub>0</sub> = IV</code><br/>
            for each padded block <code>m<sub>i</sub></code>:<br/>
            <code>state<sub>i</sub> = f(state<sub>i-1</sub>, m<sub>i</sub>)</code><br/>
            <code>H(m) = state<sub>L</sub></code>
          </p>
          <p>
            Padding includes the message length (Merkle's "MD strengthening") so different-length messages can't accidentally produce the same padded block sequence. Production hashes that follow this template: MD5, SHA-1, SHA-2 family.
          </p>

          <h4>The Merkle-Damgård collision theorem</h4>
          <p>
            <em>Theorem:</em> If f is collision-resistant, so is H. Conversely (and more practically): any collision in f can be extended to a collision in H. If you find (a, b) with a ≠ b and f(IV, a) = f(IV, b), then for any suffix s, H(a ‖ s) = H(b ‖ s). Section 3 demonstrates this: two distinct first blocks produce the same internal state, and once states converge, the chain stays converged.
          </p>

          <h4>Birthday bound for collision attacks</h4>
          <p>
            For an n-bit hash, the birthday paradox says you can expect to find a collision after roughly 2<sup>n/2</sup> random hashes. At toy n=16, that's 256 tries — instantly findable. At n=128 (MD5's output): 2<sup>64</sup> ≈ 18 quintillion — feasible with significant resources (broken in practice). At n=256 (SHA-256): 2<sup>128</sup> — infeasible for any conceivable adversary. This is why hash output sizes have grown over time.
          </p>

          <h4>Length-extension and HMAC</h4>
          <p>
            MD's chaining structure has a second weakness independent of collision-resistance: knowing H(m) is enough to compute H(m ‖ pad ‖ s) for any chosen s, without knowing m's prefix. PA#5 demonstrated this attack against the seemingly-natural <code>tag = H(k ‖ m)</code> MAC. PA#10 shows HMAC's two-pass structure that defeats it — the outer hash starts from a fresh keyed IV that the attacker can't continue from.
          </p>

          <h4>What replaced MD</h4>
          <p>
            SHA-3 (Keccak, 2015) abandoned the Merkle-Damgård structure entirely in favor of a sponge construction, partly to avoid both length-extension and the more subtle issues with iterated MD. BLAKE2/BLAKE3 use a tree structure (parallelizable) but include length-extension defenses internally.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#7 → PA#5 (length-extension MAC attack uses MD chaining), PA#10 (HMAC defeats both length-extension and chaining-collision concerns), PA#15 (digital signatures hash messages before signing — collision resistance is critical). Forward to PA#9 (birthday paradox at large scale, why 256-bit hashes are the modern minimum).
          </p>
        </div>
      </details>
    </div>
  );
}
