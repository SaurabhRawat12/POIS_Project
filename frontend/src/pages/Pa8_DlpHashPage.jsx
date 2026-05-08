import { useState, useEffect } from 'react';
import './Pa8_DlpHashPage.css';

const API_BASE = 'http://localhost:8000';

const splitBytes = (hex) => (hex ? hex.replace(/^0x/, '').match(/.{1,2}/g) || [] : []);

export default function Pa8_DlpHashPage() {
  // Section 1: group setup + hash
  const [qBits, setQBits] = useState(32);
  const [group, setGroup] = useState(null);
  const [groupError, setGroupError] = useState(null);
  const [groupLoading, setGroupLoading] = useState(false);

  const [hashMsg, setHashMsg] = useState('Hello, DLP hash!');
  const [hashOutBits, setHashOutBits] = useState(16);
  const [hashResult, setHashResult] = useState(null);
  const [hashError, setHashError] = useState(null);
  const [hashLoading, setHashLoading] = useState(false);

  // Section 2: collisions
  const [collisionQBits, setCollisionQBits] = useState(16);
  const [collCompress, setCollCompress] = useState(null);
  const [collHash, setCollHash] = useState(null);
  const [collError, setCollError] = useState(null);
  const [collLoading, setCollLoading] = useState(false);

  // Section 3: proof
  const [proof, setProof] = useState(null);
  const [proofError, setProofError] = useState(null);

  const runGroupSetup = async () => {
    setGroupLoading(true);
    setGroupError(null);
    try {
      const res = await fetch(`${API_BASE}/pa8/group-setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q_bits: qBits }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setGroup(data.result);
    } catch (err) {
      setGroupError(err.message);
    } finally {
      setGroupLoading(false);
    }
  };

  const runHash = async () => {
    setHashLoading(true);
    setHashError(null);
    try {
      const res = await fetch(`${API_BASE}/pa8/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: hashMsg, q_bits: qBits, out_bits: hashOutBits }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setHashResult(data.result);
    } catch (err) {
      setHashError(err.message);
    } finally {
      setHashLoading(false);
    }
  };

  const runCollisions = async () => {
    setCollLoading(true);
    setCollError(null);
    setCollCompress(null);
    setCollHash(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const [resCompress, resHash] = await Promise.all([
        fetch(`${API_BASE}/pa8/collision-compress`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ q_bits: collisionQBits }),
        }),
        fetch(`${API_BASE}/pa8/collision-hash`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ q_bits: collisionQBits, out_bits: collisionQBits }),
        }),
      ]);
      for (const r of [resCompress, resHash]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [dataCompress, dataHash] = await Promise.all([
        resCompress.json(),
        resHash.json(),
      ]);
      setCollCompress(dataCompress.result);
      setCollHash(dataHash.result);
    } catch (err) {
      setCollError(err.message);
    } finally {
      setCollLoading(false);
    }
  };

  const loadProof = async () => {
    try {
      const res = await fetch(`${API_BASE}/pa8/proof`);
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setProof(data.result);
    } catch (err) {
      setProofError(err.message);
    }
  };

  useEffect(() => {
    runGroupSetup();
    runCollisions();
    loadProof();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const formatBigNum = (n) => {
    if (n === undefined || n === null) return '';
    const s = n.toString();
    if (s.length <= 12) return s;
    const exponent = s.length - 1;
    const mantissa = parseFloat(`${s[0]}.${s.slice(1, 4)}`);
    return `${mantissa} × 10^${exponent}`;
  };

  return (
    <div className="pa8-page">
      <header className="pa8-header">
        <h1>PA#8 — DLP Hash: Collision-Resistant from First Principles</h1>
        <p className="pa8-subtitle">
          The DLP hash builds collision resistance directly from the discrete-log assumption — no heuristics, no Merkle-Damgård tricks. The compression function is just <code>h(x, y) = g<sup>x</sup> · ĥ<sup>y</sup> (mod p)</code> in a prime-order group, where ĥ = g<sup>α</sup> for an α nobody knows. PA#8 demonstrates the construction, finds collisions empirically at toy sizes (confirming the √q birthday bound), and renders the formal reduction proving that any collision-finder is a DLP solver.
        </p>
      </header>

      {/* ============ SECTION 1: GROUP SETUP + HASH ============ */}
      <section className="pa8-section">
        <div className="section-head">
          <h2>1. Group Setup &amp; Hash Mechanics</h2>
          <span className="status-tag tag-info">PRIME-ORDER GROUP</span>
        </div>
        <p className="section-desc">
          Pick a prime q of bit-length q_bits, build the group G = ⟨g⟩ of order q inside Z<sub>p</sub><sup>*</sup> for a prime p ≡ 1 (mod q). Sample ĥ = g<sup>α</sup> for a uniformly random α, then DISCARD α — once thrown away, the discrete log of ĥ is unknown to everyone, including the program that generated it. The compression function <code>h(x, y) = g<sup>x</sup> · ĥ<sup>y</sup> (mod p)</code> takes two q-element inputs to one p-element output.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">q_bits</span>
            <select
              value={qBits}
              onChange={(e) => setQBits(Number(e.target.value))}
              disabled={groupLoading}
              className="ctrl-input"
            >
              <option value={16}>16 (toy)</option>
              <option value={24}>24</option>
              <option value={32}>32 (default)</option>
              <option value={48}>48</option>
              <option value={64}>64</option>
            </select>
          </label>
          <button onClick={runGroupSetup} disabled={groupLoading} className="btn btn-secondary">
            {groupLoading ? 'Generating…' : (group ? 'Re-generate group' : 'Generate group')}
          </button>
        </div>

        {groupError && <div className="error-box">Error: {groupError}</div>}

        {group && (
          <div className="group-card">
            <div className="gc-tag">DLP GROUP · {group.q_bits_requested}-bit</div>
            <div className="group-grid">
              <div className="param-tile">
                <div className="pt-name">p · prime modulus</div>
                <div className="pt-val mono">{formatBigNum(group.p)}</div>
                <div className="pt-hex">{group.p_hex}</div>
              </div>
              <div className="param-tile">
                <div className="pt-name">q · prime order of G</div>
                <div className="pt-val mono">{formatBigNum(group.q)}</div>
                <div className="pt-hex">{group.q_hex}</div>
              </div>
              <div className="param-tile">
                <div className="pt-name">g · generator</div>
                <div className="pt-val mono">{formatBigNum(group.g)}</div>
                <div className="pt-hex">{group.g_hex}</div>
              </div>
              <div className="param-tile param-tile-h">
                <div className="pt-name">ĥ = g<sup>α</sup>, α discarded</div>
                <div className="pt-val mono">{formatBigNum(group.h_gen)}</div>
                <div className="pt-hex">{group.h_hex}</div>
              </div>
            </div>
            <blockquote className="security-quote">{group.security_note}</blockquote>
          </div>
        )}

        <div className="hash-block">
          <h3>Hash a message</h3>
          <p className="hash-blurb">
            DLPHash combines the compression function above with a Merkle-Damgård chain (PA#7's construction): pad the message into q-sized chunks and iteratively absorb them via h. The final state is the digest.
          </p>
          <div className="control-row">
            <label>
              <span className="ctrl-label">message</span>
              <input
                type="text"
                value={hashMsg}
                onChange={(e) => setHashMsg(e.target.value)}
                disabled={hashLoading}
                className="ctrl-input mono-input ctrl-input-wide"
              />
            </label>
            <label>
              <span className="ctrl-label">out_bits</span>
              <select
                value={hashOutBits}
                onChange={(e) => setHashOutBits(Number(e.target.value))}
                disabled={hashLoading}
                className="ctrl-input"
              >
                <option value={8}>8</option>
                <option value={16}>16</option>
                <option value={24}>24</option>
                <option value={32}>32</option>
              </select>
            </label>
            <button onClick={runHash} disabled={hashLoading} className="btn btn-primary">
              {hashLoading ? 'Hashing…' : 'Hash'}
            </button>
          </div>

          {hashError && <div className="error-box">Error: {hashError}</div>}

          {hashResult && (
            <div className="hash-result">
              <div className="hr-row">
                <span className="hr-label">message</span>
                <code className="hr-val">"{hashResult.message}"</code>
              </div>
              <div className="hr-row">
                <span className="hr-label">message hex</span>
                <code className="hr-val mono">{hashResult.message_hex}</code>
              </div>
              <div className="hr-row hr-row-emphasized">
                <span className="hr-label">digest</span>
                <code className="hr-val hr-digest">{hashResult.digest_hex}</code>
                <span className="hr-meta">
                  {hashResult.digest_bytes} bytes · {hashResult.out_bits} bits
                </span>
              </div>
              <div className="hr-group-meta">
                Hashed under p={formatBigNum(hashResult.group.p)}, q={formatBigNum(hashResult.group.q)}, g={formatBigNum(hashResult.group.g)}, ĥ={formatBigNum(hashResult.group.h_gen)}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ============ SECTION 2: COLLISIONS ============ */}
      <section className="pa8-section">
        <div className="section-head">
          <h2>2. Empirical Collisions &amp; the Birthday Bound</h2>
          <span className="status-tag tag-warn">TOY SIZE · BREAKABLE</span>
        </div>
        <p className="section-desc">
          At toy q_bits=16 the group order q ≈ 65k, so √q ≈ 256 — well within brute-force reach. Both panels below run a randomized search until they find a collision; the ratio of <em>actual evaluations</em> to <em>√q</em> should sit near 1, confirming that the cost of finding a collision scales as O(√q) — exactly the birthday bound the formal proof predicts.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">q_bits (search space)</span>
            <select
              value={collisionQBits}
              onChange={(e) => setCollisionQBits(Number(e.target.value))}
              disabled={collLoading}
              className="ctrl-input"
            >
              <option value={12}>12</option>
              <option value={16}>16 (default)</option>
              <option value={20}>20</option>
              <option value={24}>24 (slower)</option>
            </select>
          </label>
          <button onClick={runCollisions} disabled={collLoading} className="btn btn-secondary">
            {collLoading ? 'Searching…' : (collCompress ? 'Re-search' : 'Find collisions')}
          </button>
        </div>

        {collError && <div className="error-box">Error: {collError}</div>}

        {collCompress && collHash && (
          <div className="collisions-grid">
            {/* Compress collision */}
            <div className="coll-card coll-card-compress">
              <div className="coll-tag coll-tag-compress">COMPRESS · h(x, y)</div>
              <h3>Two distinct (x, y) pairs · same h</h3>

              <div className="coll-pair">
                <div className="cp-row">
                  <span className="cp-label cp-label-a">input A</span>
                  <code className="mono cp-val">x = {collCompress.input_a.x}</code>
                  <code className="mono cp-val">y = {collCompress.input_a.y}</code>
                </div>
                <div className="cp-row">
                  <span className="cp-label cp-label-b">input B</span>
                  <code className="mono cp-val">x = {collCompress.input_b.x}</code>
                  <code className="mono cp-val">y = {collCompress.input_b.y}</code>
                </div>
                <div className="cp-divider">↓ both compress to ↓</div>
                <div className="cp-row cp-row-output">
                  <span className="cp-label cp-label-output">h(x, y)</span>
                  <code className="mono cp-val cp-val-collision">
                    {collCompress.hash_value} = {collCompress.hash_hex}
                  </code>
                </div>
              </div>

              <div className="bb-stats">
                <div className="bb-stat">
                  <div className="bbs-name">evaluations</div>
                  <div className="bbs-num">{collCompress.evaluations}</div>
                </div>
                <div className="bb-stat">
                  <div className="bbs-name">√q (expected)</div>
                  <div className="bbs-num">{collCompress.sqrt_q}</div>
                </div>
                <div className="bb-stat bb-stat-highlight">
                  <div className="bbs-name">ratio evals / √q</div>
                  <div className="bbs-num">{collCompress.ratio_evals_over_sqrt_q.toFixed(3)}</div>
                  <div className="bbs-meta">target: ≈ 1</div>
                </div>
              </div>

              <blockquote className="bb-note">{collCompress.security_note}</blockquote>
            </div>

            {/* Hash collision */}
            <div className="coll-card coll-card-hash">
              <div className="coll-tag coll-tag-hash">FULL HASH · DLPHash</div>
              <h3>Two distinct messages · same digest</h3>

              <div className="coll-pair">
                <div className="cp-row cp-row-stack">
                  <span className="cp-label cp-label-a">message A (hex)</span>
                  <code className="mono cp-val cp-val-msg">{collHash.message_a_hex}</code>
                </div>
                <div className="cp-row cp-row-stack">
                  <span className="cp-label cp-label-b">message B (hex)</span>
                  <code className="mono cp-val cp-val-msg">{collHash.message_b_hex}</code>
                </div>
                <div className="cp-divider">↓ both hash to ↓</div>
                <div className="cp-row cp-row-output">
                  <span className="cp-label cp-label-output">digest</span>
                  <code className="mono cp-val cp-val-collision">{collHash.digest_hex}</code>
                </div>
              </div>

              <div className="bb-stats">
                <div className="bb-stat">
                  <div className="bbs-name">evaluations</div>
                  <div className="bbs-num">{collHash.evaluations}</div>
                </div>
                <div className="bb-stat">
                  <div className="bbs-name">expected (≈ 2<sup>n/2</sup>)</div>
                  <div className="bbs-num">{collHash.expected_birthday_bound}</div>
                </div>
                <div className="bb-stat bb-stat-highlight">
                  <div className="bbs-name">ratio</div>
                  <div className="bbs-num">{collHash.ratio.toFixed(3)}</div>
                  <div className="bbs-meta">target: ≈ 1</div>
                </div>
              </div>

              <blockquote className="bb-note">
                Collision found in {collHash.evaluations} evaluations. The expected birthday bound for an {collHash.digest_bits}-bit digest is ~{collHash.expected_birthday_bound}; ratio {collHash.ratio.toFixed(2)} confirms the bound is tight.
              </blockquote>
            </div>
          </div>
        )}

        {collCompress && collHash && (
          <div className="contrast-banner">
            <h3>The birthday bound is tight: real-world implications</h3>
            <p>
              At toy q_bits=16, finding a collision takes ~2<sup>8</sup> = 256 evaluations — milliseconds. To reach 80-bit collision security you need q_bits ≥ 160, giving √q ≈ 2<sup>80</sup> evaluations (about a quintillion, 10<sup>18</sup>). For the 128-bit security level demanded by modern protocols (TLS 1.3, post-quantum standards), q_bits must be at least 256, putting collision search at 2<sup>128</sup> ≈ 3.4 × 10<sup>38</sup> — beyond any conceivable adversary. The proof in Section 3 says this is the BEST any attacker can do.
            </p>
          </div>
        )}
      </section>

      {/* ============ SECTION 3: FORMAL PROOF ============ */}
      <section className="pa8-section">
        <div className="section-head">
          <h2>3. Formal Proof of Collision Resistance</h2>
          <span className="status-tag tag-secure">REDUCTION TO DLP</span>
        </div>
        <p className="section-desc">
          The empirical √q bound from Section 2 isn't accidental — it falls directly out of the formal reduction. The proof shows that ANY algorithm finding a collision in h can be mechanically converted into an algorithm computing α = log<sub>g</sub>(ĥ), which would solve the discrete-log problem. Since DLP is conjectured intractable for sufficiently large q, h is collision-resistant.
        </p>

        {proofError && <div className="error-box">Error loading proof: {proofError}</div>}

        {proof && (
          <div className="proof-card">
            <div className="proof-header">
              <span className="proof-badge">THEOREM</span>
              <h3 className="proof-title">{proof.title}</h3>
            </div>

            <div className="proof-block proof-setup">
              <div className="pb-tag">SETUP</div>
              <p className="pb-text">{proof.setup}</p>
            </div>

            <div className="proof-block proof-claim">
              <div className="pb-tag">CLAIM</div>
              <p className="pb-text">
                <strong>{proof.claim}</strong>
              </p>
            </div>

            <div className="proof-sketch">
              <div className="pb-tag">PROOF SKETCH</div>
              <ol className="proof-steps">
                {proof.proof_sketch.map((step, i) => (
                  <li key={i} className="proof-step">
                    <span className="ps-num">{i + 1}</span>
                    <span className="ps-text mono">{step}</span>
                  </li>
                ))}
              </ol>
            </div>

            <div className="proof-conclusion">
              <span className="pc-symbol">∎</span>
              <p className="pc-text">{proof.conclusion}</p>
            </div>
          </div>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Why DLP-based hashing matters</h4>
          <p>
            Most production hashes (SHA-2, SHA-3, BLAKE) are <em>heuristically</em> collision-resistant: the design follows good principles but no proof connects them to a hard mathematical problem. The DLP hash is <em>provably</em> collision-resistant under the discrete-log assumption — finding a collision IS solving DLP. The trade-off is speed: each compression is a modular exponentiation, dramatically slower than SHA-256's bit-twiddling. Used in zero-knowledge proof systems (Pedersen commitments are essentially this), where the algebraic structure is itself useful.
          </p>

          <h4>The birthday bound · O(√q) is fundamental</h4>
          <p>
            For ANY function with output range of size N, if you try ~√N random inputs you expect to find two that collide (by the birthday paradox). This is INDEPENDENT of the function's design. So 80-bit collision security needs an output of at least 160 bits, 128-bit security needs 256 bits, and so on. The DLP hash matches this bound exactly: collision-finding reduces to DLP-solving, and best-known DLP algorithms (Pohlig-Hellman, Pollard's rho) run in O(√q) time on prime-order groups. The √q from the proof and the √q from the algorithm agree.
          </p>

          <h4>The Pedersen commitment connection</h4>
          <p>
            <code>h(x, y) = g<sup>x</sup> · ĥ<sup>y</sup></code> is also a perfectly hiding, computationally binding <em>commitment</em> if you treat x as the message and y as randomness. <strong>Hiding</strong>: for fixed x and uniform random y, the output is uniform over G — the receiver learns nothing about x. <strong>Binding</strong>: opening the commitment to two different (x, y) pairs is exactly finding a collision in h, which by the proof above implies solving DLP. The same construction does double duty as a hash AND a commitment scheme.
          </p>

          <h4>Why ĥ's discrete log must be unknown</h4>
          <p>
            If anyone knew α = log<sub>g</sub>(ĥ), they could trivially construct collisions: pick any (x, y) and (x', y') with y' ≠ y, and choose x' = x + α(y' − y) (mod q). Then h(x, y) = h(x', y'). The "trusted setup" requirement of the DLP hash is that α is generated and immediately destroyed. Real Pedersen commitments use this same trick — and protocols using them rely on the trusted setup being honest. (Modern systems use Multi-Party Computation or "transparent" alternatives like inner-product arguments to avoid trusted setup entirely.)
          </p>

          <h4>Lineage</h4>
          <p>
            PA#8 → PA#7 (Merkle-Damgård chain wraps the compression), PA#13 (Miller-Rabin generates the prime q), forward to PA#10 (DLP hash used as the CRHF inside HMAC's bidirectional reduction), PA#15 (signatures use this hash for "hash-then-sign"), PA#11 (DH key exchange shares the same group structure), PA#17 (CCA-PKC builds on PA#15 + DLP groups).
          </p>
        </div>
      </details>
    </div>
  );
}
