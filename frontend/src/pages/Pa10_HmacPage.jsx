import { useState } from 'react';
import './Pa10_HmacPage.css';

const API_BASE = 'http://localhost:8000';

export default function Pa10_HmacPage() {
  // Section 1 — Length extension
  const [lengthExt, setLengthExt] = useState(null);
  const [lengthExtError, setLengthExtError] = useState(null);
  const [lengthExtLoading, setLengthExtLoading] = useState(false);

  // Section 2 — Timing
  const [timing, setTiming] = useState(null);
  const [timingError, setTimingError] = useState(null);
  const [timingLoading, setTimingLoading] = useState(false);
  const [tagLength, setTagLength] = useState(32);
  const [trials, setTrials] = useState(5000);

  // Section 3 — Bidirectional reduction
  const [forward, setForward] = useState(null);
  const [backward, setBackward] = useState(null);
  const [bidirError, setBidirError] = useState(null);
  const [bidirLoading, setBidirLoading] = useState(false);

  const runLengthExtension = async () => {
    setLengthExtLoading(true);
    setLengthExtError(null);
    try {
      const res = await fetch(`${API_BASE}/pa10/length-extension-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setLengthExt(data.result || data);
    } catch (err) {
      setLengthExtError(err.message);
    } finally {
      setLengthExtLoading(false);
    }
  };

  const runTiming = async () => {
    setTimingLoading(true);
    setTimingError(null);
    try {
      const res = await fetch(`${API_BASE}/pa10/timing-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tag_length: tagLength, trials }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setTiming(data.result || data);
    } catch (err) {
      setTimingError(err.message);
    } finally {
      setTimingLoading(false);
    }
  };

  const runBidirectional = async () => {
    setBidirLoading(true);
    setBidirError(null);
    setForward(null);
    setBackward(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const body = '{}';
      const [fwdRes, bwdRes] = await Promise.all([
        fetch(`${API_BASE}/pa10/crhf-to-mac-demo`, { method: 'POST', headers, body }),
        fetch(`${API_BASE}/pa10/mac-to-crhf-demo`, { method: 'POST', headers, body }),
      ]);
      for (const r of [fwdRes, bwdRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [fwdData, bwdData] = await Promise.all([fwdRes.json(), bwdRes.json()]);
      setForward(fwdData.result || fwdData);
      setBackward(bwdData.result || bwdData);
    } catch (err) {
      setBidirError(err.message);
    } finally {
      setBidirLoading(false);
    }
  };

  return (
    <div className="pa10-page">
      <header className="pa10-header">
        <h1>PA#10 — HMAC, Length Extension &amp; the CRHF↔MAC Bridge</h1>
        <p className="pa10-subtitle">
          A naive MAC built as <code>H(k‖m)</code> leaks the entire hash state in its tag, letting Eve continue the hash with any suffix and forge tags she never asked for. HMAC's double-hash structure plugs the hole. This page demonstrates the attack, the constant-time comparison fix, and the bidirectional reduction that puts CRHF in the Minicrypt clique.
        </p>
      </header>

      {/* ============ SECTION 1: LENGTH EXTENSION ============ */}
      <section className="pa10-section">
        <div className="section-head">
          <h2>1. Length-Extension Attack</h2>
          <span className="status-tag tag-info">NAIVE vs HMAC</span>
        </div>
        <p className="section-desc">
          Both schemes are given the same secret key, the same message, and the same suffix. Eve sees only the original tag and the public message length. The naive scheme's tag <em>equals what the verifier would compute</em> — Eve forges it without ever seeing the key. HMAC produces a tag Eve can't reproduce.
        </p>

        <div className="control-row">
          <button onClick={runLengthExtension} disabled={lengthExtLoading} className="btn btn-primary">
            {lengthExtLoading ? 'Running attack…' : (lengthExt ? 'Run again' : 'Run the attack')}
          </button>
        </div>

        {lengthExtError && <div className="error-box">Error: {lengthExtError}</div>}

        {lengthExt && (
          <>
            <div className="comparison-grid">
              {/* Naive panel — broken */}
              <div className="card scheme-card scheme-broken">
                <div className="scheme-tag scheme-tag-broken">NAIVE H(k‖m) · BROKEN</div>
                <h3>Forgery succeeded</h3>

                <div className="kv">
                  <span className="key">original message</span>
                  <code className="val mono">"{lengthExt.naive_mac.original_message}"</code>
                </div>
                <div className="kv">
                  <span className="key">Eve's appended suffix</span>
                  <code className="val mono">"{lengthExt.naive_mac.suffix}"</code>
                </div>
                <div className="kv">
                  <span className="key">original tag</span>
                  <code className="val mono">{lengthExt.naive_mac.original_tag}</code>
                </div>

                <div className="cheat-divider" />

                <div className="kv">
                  <span className="key">Eve's forged tag</span>
                  <code className="val mono attack-succeeded">{lengthExt.naive_mac.forged_tag}</code>
                </div>
                <div className="kv">
                  <span className="key">verifier would compute</span>
                  <code className="val mono attack-succeeded">{lengthExt.naive_mac.real_tag}</code>
                </div>

                <div className="match-banner match-equal">
                  forged_tag === real_tag &nbsp; ✗ MATCH
                </div>

                <div className="status-line broken-line">
                  ✗ Forgery accepted by verifier
                </div>

                <blockquote className="explanation-quote">
                  {lengthExt.naive_mac.explanation}
                </blockquote>
              </div>

              <div className="comparison-glyph">vs</div>

              {/* HMAC panel — secure */}
              <div className="card scheme-card scheme-secure">
                <div className="scheme-tag scheme-tag-secure">HMAC · SECURE</div>
                <h3>Forgery rejected</h3>

                <div className="kv">
                  <span className="key">original message</span>
                  <code className="val mono">"{lengthExt.naive_mac.original_message}"</code>
                </div>
                <div className="kv">
                  <span className="key">Eve's appended suffix</span>
                  <code className="val mono">"{lengthExt.naive_mac.suffix}"</code>
                </div>
                <div className="kv">
                  <span className="key">original tag</span>
                  <code className="val mono">{lengthExt.hmac.original_tag}</code>
                </div>

                <div className="cheat-divider" />

                <div className="kv">
                  <span className="key">Eve's attempted forgery</span>
                  <code className="val mono attack-defeated">{lengthExt.hmac.forged_tag}</code>
                </div>
                <div className="kv">
                  <span className="key">verifier output</span>
                  <code className="val mono attack-defeated">⊥ (rejected)</code>
                </div>

                <div className="match-banner match-not-equal">
                  forged_tag ≠ real HMAC &nbsp; ✓ MISMATCH
                </div>

                <div className="status-line secure-line">
                  ✓ Forgery defeated; key required
                </div>

                <blockquote className="explanation-quote">
                  {lengthExt.hmac.explanation}
                </blockquote>
              </div>
            </div>

            <div className={`verdict-banner ${lengthExt.naive_mac.attack_succeeded && !lengthExt.hmac.attack_succeeded ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {lengthExt.naive_mac.attack_succeeded && !lengthExt.hmac.attack_succeeded
                  ? '✓ HMAC defeats the length-extension attack that breaks naive H(k‖m)'
                  : '⚠ Unexpected outcome — investigate'}
              </h3>
              <p>
                Naive Merkle-Damgård tags <strong>are the final hash state</strong>. Knowing it lets Eve restart the hash from that state and feed in any suffix. HMAC's outer hash (keyed with k ⊕ opad) starts from a fresh chaining value Eve cannot enter, so her resume trick has nowhere to begin.
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 2: TIMING ============ */}
      <section className="pa10-section">
        <div className="section-head">
          <h2>2. Constant-Time Tag Comparison</h2>
          <span className="status-tag tag-secure">TIMING-SAFE</span>
        </div>
        <p className="section-desc">
          Naive byte comparison short-circuits on the first mismatch. Late-byte mismatches take longer to detect than early ones — leaking <em>where</em> the tags first differ, byte by byte, over many trials. <code>secure_compare</code> XORs all bytes unconditionally and checks the OR at the end, so timing is independent of where the mismatch is.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Tag length (bytes)</span>
            <select
              value={tagLength}
              onChange={(e) => setTagLength(Number(e.target.value))}
              disabled={timingLoading}
              className="ctrl-input"
            >
              <option value={16}>16</option>
              <option value={32}>32</option>
              <option value={64}>64</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">Trials per case</span>
            <select
              value={trials}
              onChange={(e) => setTrials(Number(e.target.value))}
              disabled={timingLoading}
              className="ctrl-input"
            >
              <option value={1000}>1,000</option>
              <option value={5000}>5,000</option>
              <option value={10000}>10,000</option>
              <option value={50000}>50,000</option>
            </select>
          </label>
          <button onClick={runTiming} disabled={timingLoading} className="btn btn-primary">
            {timingLoading ? 'Measuring…' : (timing ? 'Re-measure' : 'Measure timing')}
          </button>
        </div>

        {timingError && <div className="error-box">Error: {timingError}</div>}

        {timing && (
          <>
            <div className="timing-grid">
              <div className="card timing-card timing-card-broken">
                <div className="scheme-tag scheme-tag-broken">NAIVE COMPARE · LEAKS</div>
                <h3>Mismatch position visible in timing</h3>
                <div className="timing-row">
                  <span className="timing-label">Early-byte mismatch</span>
                  <code className="timing-val">{timing.naive_early_diff_ns.toFixed(1)} ns</code>
                </div>
                <div className="timing-row">
                  <span className="timing-label">Late-byte mismatch</span>
                  <code className="timing-val">{timing.naive_late_diff_ns.toFixed(1)} ns</code>
                </div>
                <div className="timing-divider" />
                <div className="timing-ratio">
                  <span className="ratio-label">Late ÷ Early</span>
                  <span className="ratio-value ratio-bad">{timing.naive_ratio_late_over_early.toFixed(2)}×</span>
                </div>
                <div className="status-line broken-line">
                  ✗ Information leaks — late-byte mismatches take ~{timing.naive_ratio_late_over_early.toFixed(1)}× longer
                </div>
              </div>

              <div className="card timing-card timing-card-secure">
                <div className="scheme-tag scheme-tag-secure">SECURE_COMPARE · CONSTANT-TIME</div>
                <h3>Timing independent of mismatch position</h3>
                <div className="timing-row">
                  <span className="timing-label">Early-byte mismatch</span>
                  <code className="timing-val">{timing.secure_early_diff_ns.toFixed(1)} ns</code>
                </div>
                <div className="timing-row">
                  <span className="timing-label">Late-byte mismatch</span>
                  <code className="timing-val">{timing.secure_late_diff_ns.toFixed(1)} ns</code>
                </div>
                <div className="timing-divider" />
                <div className="timing-ratio">
                  <span className="ratio-label">Late ÷ Early</span>
                  <span className="ratio-value ratio-good">{timing.secure_ratio_late_over_early.toFixed(2)}×</span>
                </div>
                <div className="status-line secure-line">
                  ✓ Ratio ≈ 1.0 — no signal about where the tags differ
                </div>
              </div>
            </div>

            <div className={`verdict-banner ${timing.naive_ratio_late_over_early > 1.5 && Math.abs(timing.secure_ratio_late_over_early - 1) < 0.3 ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {timing.naive_ratio_late_over_early > 1.5 && Math.abs(timing.secure_ratio_late_over_early - 1) < 0.3
                  ? '✓ secure_compare eliminates the timing side-channel'
                  : '⚠ Unexpected timing pattern — investigate'}
              </h3>
              <p>
                {timing.note}
              </p>
              <p className="contrast-note">
                <strong>Why this matters for HMAC.</strong> Tag verification compares the computed tag against the user-supplied tag byte-by-byte. With naive comparison and many trial submissions, an attacker observes the timing distribution and learns the correct tag prefix-by-prefix — eventually forging an entire valid tag <em>without ever knowing the key</em>. Constant-time compare reduces this attack channel to zero.
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 3: BIDIRECTIONAL REDUCTION ============ */}
      <section className="pa10-section">
        <div className="section-head">
          <h2>3. CRHF ↔ MAC Bidirectional Reduction</h2>
          <span className="status-tag tag-info">MINICRYPT BRIDGE</span>
        </div>
        <p className="section-desc">
          PA#10 is the bridge that puts CRHF into the Minicrypt clique. Forward direction: a CRHF (your PA#8 DLP hash) yields a secure MAC via HMAC. Backward direction: a secure MAC used as a Merkle-Damgård compression function gives a CRHF. Both runs are demonstrations on toy parameters.
        </p>

        <div className="control-row">
          <button onClick={runBidirectional} disabled={bidirLoading} className="btn btn-secondary">
            {bidirLoading ? 'Running both demos…' : (forward ? 'Re-run' : 'Run bidirectional reduction')}
          </button>
        </div>

        {bidirError && <div className="error-box">Error: {bidirError}</div>}

        {forward && backward && (
          <>
            <div className="bidir-grid">
              {/* Forward */}
              <div className="card bidir-card">
                <div className="bidir-tag bidir-tag-forward">FORWARD · CRHF → MAC</div>
                <h3>HMAC is EUF-CMA secure</h3>
                <div className="kv">
                  <span className="key">EUF-CMA queries</span>
                  <code className="val mono">{forward.queries}</code>
                </div>
                <div className="kv">
                  <span className="key">Adversary forged a tag?</span>
                  <code className={`val mono ${forward.forgery_succeeded ? 'attack-succeeded' : 'attack-defeated'}`}>
                    {forward.forgery_succeeded ? 'YES — leak' : 'NO — secure'}
                  </code>
                </div>
                <blockquote className="explanation-quote">
                  {forward.note}
                </blockquote>
              </div>

              {/* Backward */}
              <div className="card bidir-card">
                <div className="bidir-tag bidir-tag-backward">BACKWARD · MAC → CRHF</div>
                <h3>MACHash is collision-resistant</h3>
                <div className="kv">
                  <span className="key">messages hashed</span>
                  <code className="val mono">{backward.messages_hashed}</code>
                </div>
                <div className="kv">
                  <span className="key">all distinct?</span>
                  <code className={`val mono ${backward.all_distinct ? 'attack-defeated' : 'attack-succeeded'}`}>
                    {backward.all_distinct ? 'YES ✓' : 'NO — collision found'}
                  </code>
                </div>
                <div className="digest-table">
                  {Object.entries(backward.digests).map(([msg, digest]) => (
                    <div key={msg} className="digest-row">
                      <code className="digest-msg mono">"{msg}"</code>
                      <span className="digest-arrow">→</span>
                      <code className="digest-val mono">{digest}</code>
                    </div>
                  ))}
                </div>
                <blockquote className="explanation-quote">
                  {backward.note}
                </blockquote>
              </div>
            </div>

            <div className={`verdict-banner ${!forward.forgery_succeeded && backward.all_distinct ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {!forward.forgery_succeeded && backward.all_distinct
                  ? '✓ Bidirectional reduction holds — CRHF and MAC are equivalent in Minicrypt'
                  : '⚠ Reduction failed in one direction — investigate'}
              </h3>
              <p>
                Either primitive implies the other. This is what makes the eight-element Minicrypt clique (OWF / PRG / PRF / PRP / MAC / CRHF / HMAC, plus OWP) really a <em>clique</em>: every member is constructible from every other.
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Why naive H(k‖m) is broken</h4>
          <p>
            Merkle-Damgård hashes process input block-by-block, updating an internal chaining value. The final output IS the chaining value after all blocks have been absorbed. So the tag t = H(k‖m) literally <em>is</em> the hash state after consuming k‖m. Anyone who knows t and the length of k‖m can compute the MD-strengthening padding, set the chaining value to t, and continue hashing with any suffix:
          </p>
          <pre className="math-block">{`Eve has:    t = H(k‖m), len(k‖m), suffix m'
She wants:  H(k‖m‖pad‖m')

Eve can:    1. Compute pad from len(k‖m)  [public-knowable]
            2. Initialize MD chaining value to t
            3. Continue hashing m' from there
            4. Output the new state as the forged tag`}</pre>
          <p>
            No knowledge of k required. The naive demo above confirms this: Eve's forged tag matches what the legitimate verifier would compute on the extended message, byte-for-byte.
          </p>

          <h4>HMAC's structural fix</h4>
          <p>
            HMAC sandwiches the inner hash inside a second hash invocation:
          </p>
          <pre className="math-block">HMAC_k(m) = H( (k ⊕ opad) ‖ H( (k ⊕ ipad) ‖ m ) )</pre>
          <p>
            The inner hash output is treated as a fresh fixed-length input to a freshly-keyed outer hash. Eve's resume trick can run on the inner hash, but the inner result is then consumed as a block by the outer hash — and the outer hash starts from a chaining value that depends on (k ⊕ opad), which Eve doesn't know. There's no chaining state for her to extend from.
          </p>

          <h4>Constant-time comparison and tag forgery via timing</h4>
          <p>
            Even with HMAC, naive verify like <code>computed == provided</code> short-circuits on first mismatch. Repeatedly submitting random tags and timing the rejection lets an attacker learn the correct tag prefix one byte at a time — about 256 trials per byte for an n-byte tag, total ~256·n trials. <code>secure_compare</code> XORs all corresponding byte pairs and OR-accumulates, then checks once at the end:
          </p>
          <pre className="math-block">{`def secure_compare(a, b):
    if len(a) != len(b): return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0`}</pre>
          <p>
            Section 2 confirms the difference: naive comparison's late-byte mismatches take measurably longer to detect; secure_compare's timing is constant.
          </p>

          <h4>The CRHF ↔ MAC bridge in detail</h4>
          <p>
            <strong>Forward (CRHF ⇒ MAC).</strong> If H is collision-resistant and its compression function is a PRF (which our PA#8 DLP-based hash satisfies), then HMAC is a secure EUF-CMA MAC. Section 3's forward demo runs the EUF-CMA game on HMAC and confirms unforgeability.
          </p>
          <p>
            <strong>Backward (MAC ⇒ CRHF).</strong> Define a new compression function h'(cv, block) = HMAC<sub>k</sub>(cv ‖ block) for some fixed public key k. Plug h' into the Merkle-Damgård transform. Any collision in the resulting hash would constitute two distinct (cv, block) pairs with the same HMAC output — i.e., a MAC forgery. Section 3's backward demo hashes 5 messages and confirms all-distinct outputs as a sanity check.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#10 → PA#8 (DLP hash, the underlying CRHF) → PA#13 (Miller-Rabin for safe-prime generation). The HMAC construction also depends on PA#7 (Merkle-Damgård transform) for the underlying hash structure.
          </p>
        </div>
      </details>
    </div>
  );
}
