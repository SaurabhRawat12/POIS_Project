import { useState } from 'react';
import './Pa1_OwfPrgPage.css';

const API_BASE = 'http://localhost:8000';

// Format bit string in groups of 8 for readability
const formatBits = (bits) => {
  if (!bits) return '';
  const groups = [];
  for (let i = 0; i < bits.length; i += 8) {
    groups.push(bits.slice(i, i + 8));
  }
  return groups.join(' ');
};

export default function Pa1_OwfPrgPage() {
  // Shared group params
  const [p, setP] = useState(65537);
  const [g, setG] = useState(3);

  // Section 1 — OWF forward
  const [x, setX] = useState(3);
  const [owfResult, setOwfResult] = useState(null);
  const [owfError, setOwfError] = useState(null);
  const [owfLoading, setOwfLoading] = useState(false);

  // Section 1 — OWF hardness
  const [owfTrials, setOwfTrials] = useState(1000);
  const [hardness, setHardness] = useState(null);
  const [hardnessError, setHardnessError] = useState(null);
  const [hardnessLoading, setHardnessLoading] = useState(false);

  // Section 2 — PRG
  const [seed, setSeed] = useState(42);
  const [nBits, setNBits] = useState(64);
  const [prg, setPrg] = useState(null);
  const [prgError, setPrgError] = useState(null);
  const [prgLoading, setPrgLoading] = useState(false);

  // Section 3 — PRG ⇒ OWF reduction
  const [reduxSeed, setReduxSeed] = useState(32415);
  const [reduxTrials, setReduxTrials] = useState(5000);
  const [redux, setRedux] = useState(null);
  const [reduxHardness, setReduxHardness] = useState(null);
  const [reduxError, setReduxError] = useState(null);
  const [reduxLoading, setReduxLoading] = useState(false);

  const evaluateOwf = async () => {
    setOwfLoading(true);
    setOwfError(null);
    try {
      const res = await fetch(`${API_BASE}/pa1/owf-evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x, method: 'dlp', p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setOwfResult(data.result || data);
    } catch (err) {
      setOwfError(err.message);
    } finally {
      setOwfLoading(false);
    }
  };

  const checkHardness = async () => {
    setHardnessLoading(true);
    setHardnessError(null);
    try {
      const res = await fetch(`${API_BASE}/pa1/owf-hardness`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'dlp', trials: owfTrials, p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setHardness(data.result || data);
    } catch (err) {
      setHardnessError(err.message);
    } finally {
      setHardnessLoading(false);
    }
  };

  const generatePrg = async () => {
    setPrgLoading(true);
    setPrgError(null);
    try {
      const res = await fetch(`${API_BASE}/pa1/prg-generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seed, n_bits: nBits, method: 'dlp', p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setPrg(data.result || data);
    } catch (err) {
      setPrgError(err.message);
    } finally {
      setPrgLoading(false);
    }
  };

  const runRedux = async () => {
    setReduxLoading(true);
    setReduxError(null);
    setRedux(null);
    setReduxHardness(null);
    try {
      // Run both demo and hardness in parallel
      const headers = { 'Content-Type': 'application/json' };
      const [demoRes, hardnessRes] = await Promise.all([
        fetch(`${API_BASE}/pa1/prg-to-owf-demo`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ seed_val: reduxSeed, method: 'dlp', p, g }),
        }),
        fetch(`${API_BASE}/pa1/prg-as-owf-hardness`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ seed_val: reduxSeed, trials: reduxTrials, method: 'dlp', p, g }),
        }),
      ]);
      for (const r of [demoRes, hardnessRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [demoData, hardnessData] = await Promise.all([demoRes.json(), hardnessRes.json()]);
      setRedux(demoData.result || demoData);
      setReduxHardness(hardnessData.result || hardnessData);
    } catch (err) {
      setReduxError(err.message);
    } finally {
      setReduxLoading(false);
    }
  };

  return (
    <div className="pa1-page">
      <header className="pa1-header">
        <h1>PA#1 — OWF &amp; PRG: The Foundations of Minicrypt</h1>
        <p className="pa1-subtitle">
          A one-way function f is easy to compute but hard to invert. A pseudorandom generator G stretches a short random seed into a longer string indistinguishable from random. PA#1 demonstrates both primitives concretely (using DLP <code>g^x mod p</code>) and proves their equivalence by reducing PRG to OWF — every PRG yields a one-way function.
        </p>
      </header>

      {/* Shared group params */}
      <section className="pa1-params">
        <span className="params-label">Group parameters · all sections</span>
        <label>
          <span className="ctrl-label">p (prime)</span>
          <input
            type="number"
            value={p}
            onChange={(e) => setP(Number(e.target.value))}
            className="ctrl-input"
          />
        </label>
        <label>
          <span className="ctrl-label">g (generator)</span>
          <input
            type="number"
            value={g}
            onChange={(e) => setG(Number(e.target.value))}
            className="ctrl-input"
          />
        </label>
        <span className="params-note">
          Toy params (p ≈ 2<sup>16</sup>) — too small for real security, ideal for visible cryptanalysis.
        </span>
      </section>

      {/* ============ SECTION 1: OWF ============ */}
      <section className="pa1-section">
        <div className="section-head">
          <h2>1. One-Way Function: <code>f(x) = g^x mod p</code></h2>
          <span className="status-tag tag-info">FORWARD ≪ BACKWARD</span>
        </div>
        <p className="section-desc">
          Modular exponentiation is fast (forward); recovering x from y is the discrete logarithm problem (backward). Both are computable in principle — the OWF claim is that backward is exponentially harder than forward.
        </p>

        <div className="owf-grid">
          {/* Forward */}
          <div className="card direction-card direction-forward">
            <div className="dir-tag dir-tag-forward">FORWARD · EASY</div>
            <h3>Compute f(x)</h3>
            <div className="control-row inline">
              <label>
                <span className="ctrl-label">x</span>
                <input
                  type="number"
                  value={x}
                  onChange={(e) => setX(Number(e.target.value))}
                  disabled={owfLoading}
                  className="ctrl-input"
                />
              </label>
              <button onClick={evaluateOwf} disabled={owfLoading} className="btn btn-primary">
                {owfLoading ? 'Computing…' : 'Evaluate'}
              </button>
            </div>
            {owfError && <div className="error-box">Error: {owfError}</div>}
            {owfResult && (
              <div className="result-block">
                <div className="kv">
                  <span className="key">y = g<sup>x</sup> mod p</span>
                  <code className="val mono">{owfResult.y}</code>
                </div>
                <div className="kv">
                  <span className="key">y in hex</span>
                  <code className="val mono">{owfResult.y_hex}</code>
                </div>
                <div className="formula">{owfResult.formula}</div>
              </div>
            )}
          </div>

          {/* Hardness */}
          <div className="card direction-card direction-backward">
            <div className="dir-tag dir-tag-backward">BACKWARD · HARD</div>
            <h3>Try to invert by random trial</h3>
            <div className="control-row inline">
              <label>
                <span className="ctrl-label">trials</span>
                <select
                  value={owfTrials}
                  onChange={(e) => setOwfTrials(Number(e.target.value))}
                  disabled={hardnessLoading}
                  className="ctrl-input"
                >
                  <option value={1000}>1,000</option>
                  <option value={5000}>5,000</option>
                  <option value={10000}>10,000</option>
                  <option value={50000}>50,000</option>
                  <option value={100000}>100,000</option>
                </select>
              </label>
              <button onClick={checkHardness} disabled={hardnessLoading} className="btn btn-primary">
                {hardnessLoading ? 'Testing…' : 'Test hardness'}
              </button>
            </div>
            {hardnessError && <div className="error-box">Error: {hardnessError}</div>}
            {hardness && (
              <div className="result-block">
                <div className={`verdict-pill ${hardness.verdict === 'SECURE' ? 'verdict-pill-secure' : 'verdict-pill-broken'}`}>
                  {hardness.verdict === 'SECURE' ? '✓ SECURE' : '✗ BROKEN'}
                </div>
                <p className="verdict-message">{hardness.message}</p>
              </div>
            )}
          </div>
        </div>

        <div className="hint-box">
          <strong>Try this:</strong> set trials to 100,000 and re-run. At p ≈ 65,537 the search space is small enough that brute force eventually wins. This is why real crypto uses primes of 2048+ bits — the same algorithm that's "secure" at toy scale becomes infeasible at real scale.
        </div>
      </section>

      {/* ============ SECTION 2: PRG ============ */}
      <section className="pa1-section">
        <div className="section-head">
          <h2>2. Pseudorandom Generator</h2>
          <span className="status-tag tag-info">SHORT SEED → LONG OUTPUT</span>
        </div>
        <p className="section-desc">
          A PRG takes a short random seed and produces many bits indistinguishable from uniform. Construction here uses the OWF's hard-core bit (Goldreich-Levin): each output bit is a hard-core predicate of an iterated DLP computation. A useful sanity check is the 0/1 balance — uniform random bits should be ≈ 50/50.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">seed</span>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value))}
              disabled={prgLoading}
              className="ctrl-input"
            />
          </label>
          <label>
            <span className="ctrl-label">output bits</span>
            <select
              value={nBits}
              onChange={(e) => setNBits(Number(e.target.value))}
              disabled={prgLoading}
              className="ctrl-input"
            >
              <option value={32}>32</option>
              <option value={64}>64</option>
              <option value={128}>128</option>
              <option value={256}>256</option>
              <option value={512}>512</option>
            </select>
          </label>
          <button onClick={generatePrg} disabled={prgLoading} className="btn btn-primary">
            {prgLoading ? 'Generating…' : (prg ? 'Re-generate' : 'Generate')}
          </button>
        </div>

        {prgError && <div className="error-box">Error: {prgError}</div>}

        {prg && (
          <>
            <div className="card prg-output-card">
              <h3>Output bit string ({prg.n_bits} bits)</h3>
              <pre className="bit-string">{formatBits(prg.output_bits)}</pre>
            </div>

            <div className="card prg-stats-card">
              <h3>Distribution check</h3>
              <div className="stats-grid">
                <div className="stat-tile">
                  <div className="stat-name">zeros</div>
                  <div className="stat-num">{prg.stats.zeros}</div>
                </div>
                <div className="stat-tile">
                  <div className="stat-name">ones</div>
                  <div className="stat-num">{prg.stats.ones}</div>
                </div>
                <div className="stat-tile stat-tile-highlight">
                  <div className="stat-name">ratio of 1s</div>
                  <div className="stat-num">{prg.stats.ratio_ones.toFixed(3)}</div>
                </div>
              </div>

              {/* Visual balance bar */}
              <div className="balance-bar-wrap">
                <div className="balance-bar">
                  <div
                    className="balance-zeros"
                    style={{ flex: prg.stats.zeros }}
                  >
                    <span>{prg.stats.zeros} zeros</span>
                  </div>
                  <div
                    className="balance-ones"
                    style={{ flex: prg.stats.ones }}
                  >
                    <span>{prg.stats.ones} ones</span>
                  </div>
                </div>
                <div className="balance-target">target: 50/50 for uniform output</div>
              </div>

              <div className={`verdict-pill ${Math.abs(prg.stats.ratio_ones - 0.5) < 0.1 ? 'verdict-pill-secure' : 'verdict-pill-warn'}`}>
                {Math.abs(prg.stats.ratio_ones - 0.5) < 0.1
                  ? `✓ Balance within 10% of uniform`
                  : `⚠ Balance deviates from uniform`}
              </div>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 3: PRG ⇒ OWF ============ */}
      <section className="pa1-section">
        <div className="section-head">
          <h2>3. Reduction: PRG ⇒ OWF</h2>
          <span className="status-tag tag-info">BACKWARD DIRECTION</span>
        </div>
        <p className="section-desc">
          Define <code>f(s) := G(s)</code>. If an adversary can invert f to recover the seed s from G(s), they break PRG security (they distinguish G's output from random). So any secure PRG yields a OWF — the backward direction of the equivalence. This section runs both halves: the construction itself, and an empirical hardness check that brute-forces the seed at our toy parameters.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">seed</span>
            <input
              type="number"
              value={reduxSeed}
              onChange={(e) => setReduxSeed(Number(e.target.value))}
              disabled={reduxLoading}
              className="ctrl-input"
            />
          </label>
          <label>
            <span className="ctrl-label">inversion trials</span>
            <select
              value={reduxTrials}
              onChange={(e) => setReduxTrials(Number(e.target.value))}
              disabled={reduxLoading}
              className="ctrl-input"
            >
              <option value={1000}>1,000</option>
              <option value={5000}>5,000</option>
              <option value={10000}>10,000</option>
              <option value={50000}>50,000</option>
            </select>
          </label>
          <button onClick={runRedux} disabled={reduxLoading} className="btn btn-primary">
            {reduxLoading ? 'Running…' : (redux ? 'Re-run' : 'Run reduction')}
          </button>
        </div>

        {reduxError && <div className="error-box">Error: {reduxError}</div>}

        {redux && reduxHardness && (
          <>
            <div className="redux-grid">
              <div className="card construction-card">
                <h3>Construction · f(s) = G(s)</h3>
                <div className="kv">
                  <span className="key">original seed s</span>
                  <code className="val mono">{redux.original_seed}</code>
                </div>
                <div className="kv kv-stack">
                  <span className="key">PRG output G(s)</span>
                  <code className="val mono bit-string-inline">{formatBits(redux.prg_output)}</code>
                </div>
                <blockquote className="explanation-quote">{redux.security_claim}</blockquote>
              </div>

              <div className={`card hardness-card ${reduxHardness.verdict === 'SECURE' ? 'hardness-card-secure' : 'hardness-card-broken'}`}>
                <h3>Hardness · invert f at toy scale</h3>
                <div className="kv">
                  <span className="key">trials</span>
                  <code className="val mono">{reduxHardness.trials.toLocaleString()}</code>
                </div>
                <div className="kv">
                  <span className="key">verdict</span>
                  <code className={`val mono ${reduxHardness.verdict === 'SECURE' ? 'attack-defeated' : 'attack-succeeded'}`}>
                    {reduxHardness.verdict}
                  </code>
                </div>
                <p className="verdict-message">{reduxHardness.message}</p>
              </div>
            </div>

            <div className={`verdict-banner ${reduxHardness.verdict === 'SECURE' ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {reduxHardness.verdict === 'SECURE'
                  ? '✓ At these parameters and trial count, the seed survived'
                  : `⚠ Toy parameters: seed brute-forced — but the reduction is sound at real scale`}
              </h3>
              <p>
                {reduxHardness.verdict === 'BROKEN'
                  ? <>The reduction <em>still proves</em> PRG ⇒ OWF — the empirical break here just reflects that p ≈ 2<sup>16</sup> is a 16-bit search space, exhaustively scannable with enough trials. At real cryptographic sizes (p ≈ 2<sup>2048</sup>), brute force takes longer than the age of the universe.</>
                  : <>Increase trials or shrink p to see the brute force succeed. Either way, the reduction is a theorem about asymptotic security, not a guarantee for small parameters.</>}
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>One-way function</h4>
          <p>
            A function f: {'{0,1}'}<sup>n</sup> → {'{0,1}'}<sup>m</sup> is one-way if it's polynomial-time computable but no polynomial-time adversary can invert it with non-negligible probability. The DLP-based construction f(x) = g<sup>x</sup> mod p is conjectured one-way under the discrete-log assumption: nobody knows a polynomial-time algorithm for arbitrary p, but at p ≈ 2<sup>16</sup> brute force trivially works.
          </p>

          <h4>Pseudorandom generator</h4>
          <p>
            A PRG G: {'{0,1}'}<sup>n</sup> → {'{0,1}'}<sup>m</sup> with m {'>'} n is secure if its output on a uniform random seed is computationally indistinguishable from a uniform random m-bit string. The Goldreich-Levin construction extracts a "hard-core bit" from any OWF — the inner product of x and a random r mod 2 is unpredictable given f(x) and r — and stretches that into many bits via iteration. Section 2 outputs the resulting bit stream.
          </p>

          <h4>Why PRG ⇒ OWF (the reduction)</h4>
          <p>
            Suppose G is a secure PRG and define f(s) := G(s). Suppose an efficient adversary A inverts f with non-negligible probability ε. Build a PRG distinguisher D as follows: on input y, run A(y); if A returns s' with G(s') = y, output "real" (i.e., y came from G); else output "random". D wins the PRG game with advantage ε, contradicting G's security. So no such A exists, meaning f is one-way. The empirical break in Section 3 is consistent because at toy p, ε = 1 (brute force always succeeds), and indeed G is also broken at toy p — neither claim holds asymptotically without large parameters.
          </p>

          <h4>What about OWF ⇒ PRG (the forward direction)?</h4>
          <p>
            That's deeper — Håstad-Impagliazzo-Levin-Luby (1999) proved every OWF yields a PRG, but the construction is heavyweight (involves universal hashing, randomness extraction, and exponential blowup factors). The DLP-specific PRG used here is much simpler and exploits structure that general OWFs don't have. PA#2 will pick up the PRF construction and complete the chain OWF → PRG → PRF.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#1 → PA#13 (Miller-Rabin for choosing the prime p, transitively for any non-toy run). The DLP hash in PA#8 also uses the same group structure but adds a second base h chosen so log<sub>g</sub>(h) is unknown.
          </p>
        </div>
      </details>
    </div>
  );
}
