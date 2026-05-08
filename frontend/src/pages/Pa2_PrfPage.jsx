import { useState } from 'react';
import './Pa2_PrfPage.css';

const API_BASE = 'http://localhost:8000';

// Format a 16-bit string in groups of 4 for readability
const formatBits16 = (bits) => {
  if (!bits) return '';
  const groups = [];
  for (let i = 0; i < bits.length; i += 4) {
    groups.push(bits.slice(i, i + 4));
  }
  return groups.join(' ');
};

// Format a longer bit string (e.g. 32 bits) in groups of 8
const formatBits = (bits, group = 8) => {
  if (!bits) return '';
  const groups = [];
  for (let i = 0; i < bits.length; i += group) {
    groups.push(bits.slice(i, i + group));
  }
  return groups.join(' ');
};

const isValidBinary16 = (s) => /^[01]{16}$/.test(s);

export default function Pa2_PrfPage() {
  // Shared params
  const [p, setP] = useState(65537);
  const [g, setG] = useState(3);

  // Section 1: Eval & Trace
  const [k, setK] = useState('1010110011001010');
  const [x, setX] = useState('1011010100110010');
  const [evalResult, setEvalResult] = useState(null);
  const [traceResult, setTraceResult] = useState(null);
  const [evalError, setEvalError] = useState(null);
  const [evalLoading, setEvalLoading] = useState(false);

  // Section 2: PRF -> PRG
  const [s, setS] = useState('1010110011001010');
  const [prgResult, setPrgResult] = useState(null);
  const [prgError, setPrgError] = useState(null);
  const [prgLoading, setPrgLoading] = useState(false);

  // Section 3: Distinguishing Experiment
  const [gameK, setGameK] = useState('1010110011001010');
  const [q, setQ] = useState(100);
  const [rounds, setRounds] = useState(100);
  const [expResult, setExpResult] = useState(null);
  const [expError, setExpError] = useState(null);
  const [expLoading, setExpLoading] = useState(false);

  const runEval = async () => {
    if (!isValidBinary16(k) || !isValidBinary16(x)) {
      setEvalError('k and x must each be exactly 16 bits (only 0s and 1s)');
      return;
    }
    setEvalLoading(true);
    setEvalError(null);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const body = JSON.stringify({ k, x, method: 'dlp', p, g });
      const [evalRes, traceRes] = await Promise.all([
        fetch(`${API_BASE}/pa2/eval`, { method: 'POST', headers, body }),
        fetch(`${API_BASE}/pa2/trace`, { method: 'POST', headers, body }),
      ]);
      for (const r of [evalRes, traceRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }
      const [evalData, traceData] = await Promise.all([evalRes.json(), traceRes.json()]);
      setEvalResult(evalData.result || evalData);
      setTraceResult(traceData.result || traceData);
    } catch (err) {
      setEvalError(err.message);
    } finally {
      setEvalLoading(false);
    }
  };

  const runPrg = async () => {
    if (!isValidBinary16(s)) {
      setPrgError('seed must be exactly 16 bits (only 0s and 1s)');
      return;
    }
    setPrgLoading(true);
    setPrgError(null);
    try {
      const res = await fetch(`${API_BASE}/pa2/prf-to-prg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ s, method: 'dlp', p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setPrgResult(data.result || data);
    } catch (err) {
      setPrgError(err.message);
    } finally {
      setPrgLoading(false);
    }
  };

  const runExperiment = async () => {
    if (!isValidBinary16(gameK)) {
      setExpError('key must be exactly 16 bits (only 0s and 1s)');
      return;
    }
    setExpLoading(true);
    setExpError(null);
    try {
      const res = await fetch(`${API_BASE}/pa2/distinguish-experiment`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ k: gameK, rounds, q, method: 'dlp', p, g }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setExpResult(data.result || data);
    } catch (err) {
      setExpError(err.message);
    } finally {
      setExpLoading(false);
    }
  };

  return (
    <div className="pa2-page">
      <header className="pa2-header">
        <h1>PA#2 — PRF (GGM): Pseudorandom Functions from PRGs</h1>
        <p className="pa2-subtitle">
          The Goldreich-Goldwasser-Micali construction builds a PRF from any length-doubling PRG by treating the input as a binary path through a tree of PRG applications. PA#2 shows the descent in action, derives a PRG back from the PRF (closing the OWF → PRG → PRF chain), and proves indistinguishability empirically through a distinguishing experiment.
        </p>
      </header>

      {/* Shared group params */}
      <section className="pa2-params">
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
          n = 16 bits: keys, inputs, and PRF outputs are all 16-bit binary strings.
        </span>
      </section>

      {/* ============ SECTION 1: GGM EVAL + TRACE ============ */}
      <section className="pa2-section">
        <div className="section-head">
          <h2>1. GGM Evaluation: Path Through the Tree</h2>
          <span className="status-tag tag-info">F<sub>k</sub>: {'{0,1}'}<sup>16</sup> → {'{0,1}'}<sup>16</sup></span>
        </div>
        <p className="section-desc">
          F<sub>k</sub>(x) treats x as a path in a binary tree rooted at k. At each level i, apply the length-doubling PRG to the current state to get two 16-bit children, then descend left if x[i]=0 or right if x[i]=1. After 16 bits of descent, the leaf is the PRF output. The trace below shows both children at every level — only one is on the path, but pedagogically both exist in the conceptual tree.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key k (16 bits)</span>
            <input
              type="text"
              value={k}
              maxLength={16}
              onChange={(e) => setK(e.target.value.replace(/[^01]/g, ''))}
              disabled={evalLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">input x (16 bits)</span>
            <input
              type="text"
              value={x}
              maxLength={16}
              onChange={(e) => setX(e.target.value.replace(/[^01]/g, ''))}
              disabled={evalLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <button onClick={runEval} disabled={evalLoading} className="btn btn-primary">
            {evalLoading ? 'Evaluating…' : (evalResult ? 'Re-evaluate' : 'Evaluate & Trace')}
          </button>
        </div>

        {evalError && <div className="error-box">Error: {evalError}</div>}

        {evalResult && (
          <div className="output-banner">
            <div className="output-line">
              <span className="output-label">F<sub>k</sub>(x) =</span>
              <code className="output-value">{formatBits16(evalResult.output)}</code>
            </div>
            <div className="output-meta">
              16-bit input · 16-bit output · {evalResult.algorithm}
            </div>
          </div>
        )}

        {traceResult && (
          <div className="trace-wrap">
            <h3 className="trace-heading">Tree descent · {traceResult.trace.length - 1} levels</h3>
            <div className="trace-table-scroll">
              <table className="trace-table">
                <thead>
                  <tr>
                    <th className="th-level">level</th>
                    <th className="th-bit">x[i]</th>
                    <th className="th-child">left child = G<sub>0</sub>(parent)</th>
                    <th className="th-child">right child = G<sub>1</sub>(parent)</th>
                  </tr>
                </thead>
                <tbody>
                  {traceResult.trace.map((node) => {
                    if (node.level === 0) {
                      return (
                        <tr key={node.level} className="trace-row trace-row-root">
                          <td className="level-cell">{node.level}</td>
                          <td className="bit-cell bit-cell-none">—</td>
                          <td colSpan={2} className="root-cell">
                            <span className="root-label">ROOT (key k)</span>
                            <code className="root-value">{formatBits16(node.value)}</code>
                          </td>
                        </tr>
                      );
                    }
                    const isLeftChosen = node.chosen_state === node.left_node;
                    const isFinal = node.level === traceResult.trace.length - 1;
                    return (
                      <tr key={node.level} className={`trace-row ${isFinal ? 'trace-row-final' : ''}`}>
                        <td className="level-cell">{node.level}</td>
                        <td className={`bit-cell bit-${node.bit_read}`}>{node.bit_read}</td>
                        <td className={`child-cell ${isLeftChosen ? 'cell-chosen' : 'cell-unchosen'}`}>
                          {isLeftChosen && <span className="chosen-arrow">←</span>}
                          <code className="child-value">{formatBits16(node.left_node)}</code>
                          {isFinal && isLeftChosen && <span className="output-tag">OUTPUT</span>}
                        </td>
                        <td className={`child-cell ${!isLeftChosen ? 'cell-chosen' : 'cell-unchosen'}`}>
                          <code className="child-value">{formatBits16(node.right_node)}</code>
                          {!isLeftChosen && <span className="chosen-arrow">→</span>}
                          {isFinal && !isLeftChosen && <span className="output-tag">OUTPUT</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="trace-legend">
              <span className="legend-item"><span className="legend-swatch swatch-bit-0"></span>bit 0 → descend left</span>
              <span className="legend-item"><span className="legend-swatch swatch-bit-1"></span>bit 1 → descend right</span>
              <span className="legend-item"><span className="legend-swatch swatch-chosen"></span>chosen path</span>
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 2: PRF -> PRG ============ */}
      <section className="pa2-section">
        <div className="section-head">
          <h2>2. Reduction: PRF ⇒ PRG</h2>
          <span className="status-tag tag-info">LENGTH DOUBLING</span>
        </div>
        <p className="section-desc">
          Given a PRF F<sub>s</sub>, define <code>G(s) = F<sub>s</sub>(0<sup>n</sup>) ‖ F<sub>s</sub>(1<sup>n</sup>)</code>. The output is 2n bits — twice the seed length — and is a secure PRG by a hybrid argument (any distinguisher for G yields a distinguisher for F at one of the two query points). This is the backward direction of the PRG ⇄ PRF equivalence; the GGM construction in Section 1 is the forward direction.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">seed s (16 bits)</span>
            <input
              type="text"
              value={s}
              maxLength={16}
              onChange={(e) => setS(e.target.value.replace(/[^01]/g, ''))}
              disabled={prgLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <button onClick={runPrg} disabled={prgLoading} className="btn btn-primary">
            {prgLoading ? 'Generating…' : (prgResult ? 'Re-generate' : 'Generate G(s)')}
          </button>
        </div>

        {prgError && <div className="error-box">Error: {prgError}</div>}

        {prgResult && (
          <div className="prg-output">
            <div className="prg-formula">
              <code>{prgResult.construction}</code>
            </div>

            <div className="prg-stretch">
              <div className="prg-tile">
                <div className="prg-tile-label">seed s · {prgResult.n_bits_in} bits</div>
                <code className="prg-tile-value">{formatBits16(prgResult.seed)}</code>
              </div>
              <div className="prg-arrow">→ G →</div>
              <div className="prg-tile prg-tile-output">
                <div className="prg-tile-label">G(s) · {prgResult.n_bits_out} bits</div>
                <code className="prg-tile-value">{formatBits(prgResult.output, 8)}</code>
              </div>
            </div>

            <div className="prg-stretch-meta">
              {prgResult.n_bits_in}-bit seed → {prgResult.n_bits_out}-bit output · stretch factor {prgResult.n_bits_out / prgResult.n_bits_in}×
            </div>
          </div>
        )}
      </section>

      {/* ============ SECTION 3: DISTINGUISHING EXPERIMENT ============ */}
      <section className="pa2-section">
        <div className="section-head">
          <h2>3. PRF Indistinguishability · Empirical Game</h2>
          <span className="status-tag tag-info">PRF VS RANDOM ORACLE</span>
        </div>
        <p className="section-desc">
          The distinguishing game presents the adversary with q query/response pairs from one of two sources — the GGM PRF (with random hidden key) or a true random oracle — and asks them to guess. A PRF is secure if no efficient adversary's win rate exceeds 1/2 by a non-negligible margin. We average a dummy adversary's success over many independent rounds; their advantage should sit near 0.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">key k (16 bits)</span>
            <input
              type="text"
              value={gameK}
              maxLength={16}
              onChange={(e) => setGameK(e.target.value.replace(/[^01]/g, ''))}
              disabled={expLoading}
              className="ctrl-input mono-input"
            />
          </label>
          <label>
            <span className="ctrl-label">queries / round</span>
            <select
              value={q}
              onChange={(e) => setQ(Number(e.target.value))}
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
          <button onClick={runExperiment} disabled={expLoading} className="btn btn-primary">
            {expLoading ? 'Running…' : (expResult ? 'Re-run experiment' : 'Run experiment')}
          </button>
        </div>

        {expError && <div className="error-box">Error: {expError}</div>}

        {expResult && (
          <>
            <div className="exp-stats">
              <div className="stat-tile">
                <div className="stat-name">rounds</div>
                <div className="stat-num">{expResult.rounds.toLocaleString()}</div>
              </div>
              <div className="stat-tile">
                <div className="stat-name">queries / round</div>
                <div className="stat-num">{expResult.queries_per_round.toLocaleString()}</div>
              </div>
              <div className="stat-tile">
                <div className="stat-name">dummy success rate</div>
                <div className="stat-num">{(expResult.dummy_adversary_success_rate * 100).toFixed(1)}%</div>
                <div className="stat-meta">target: 50%</div>
              </div>
              <div className="stat-tile stat-tile-highlight">
                <div className="stat-name">empirical advantage</div>
                <div className="stat-num">{expResult.empirical_advantage.toFixed(4)}</div>
                <div className="stat-meta">target: ≈ 0</div>
              </div>
            </div>

            {/* Advantage spectrum */}
            <div className="advantage-spectrum">
              <div className="spectrum-label">Advantage spectrum</div>
              <div className="spectrum-bar">
                <div className="spectrum-zone zone-secure">
                  <span>≈ 0 · indistinguishable</span>
                </div>
                <div className="spectrum-zone zone-warn">
                  <span>some signal</span>
                </div>
                <div className="spectrum-zone zone-broken">
                  <span>1 · perfect distinguisher</span>
                </div>
                <div
                  className="spectrum-marker"
                  style={{ left: `${Math.min(100, Math.max(0, expResult.empirical_advantage * 100))}%` }}
                >
                  <div className="marker-pin"></div>
                  <div className="marker-label">{expResult.empirical_advantage.toFixed(4)}</div>
                </div>
              </div>
            </div>

            <div className={`verdict-banner ${Math.abs(expResult.empirical_advantage) < 0.1 ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {Math.abs(expResult.empirical_advantage) < 0.1
                  ? '✓ Advantage near 0 — PRF appears indistinguishable from a random oracle'
                  : '⚠ Adversary has measurable advantage'}
              </h3>
              <p><em>{expResult.security_claim}</em></p>
              <p>
                The dummy adversary makes random guesses; its expected win rate is exactly 50%, so its advantage = (success − 0.5) is concentrated around 0. The narrowness of the concentration depends on the number of rounds — more rounds, tighter band. If a real adversary could push this advantage above some threshold, the PRF would be considered broken.
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Pseudorandom function (PRF)</h4>
          <p>
            A keyed function F: {'{0,1}'}<sup>n</sup> × {'{0,1}'}<sup>n</sup> → {'{0,1}'}<sup>n</sup> is a PRF if no efficient adversary, given oracle access, can distinguish F<sub>k</sub> (with k ←$ {'{0,1}'}<sup>n</sup>) from a uniformly random function with non-negligible advantage. Crucially the oracle hides k — the adversary only sees query/response pairs, never the key.
          </p>

          <h4>Goldreich-Goldwasser-Micali (1986)</h4>
          <p>
            The GGM construction shows that any length-doubling PRG G: {'{0,1}'}<sup>n</sup> → {'{0,1}'}<sup>2n</sup> yields a PRF. Let G<sub>0</sub>(s) and G<sub>1</sub>(s) be the first and second n-bit halves of G(s). Define F<sub>k</sub>(x<sub>1</sub>x<sub>2</sub>…x<sub>n</sub>) = G<sub>x<sub>n</sub></sub>(G<sub>x<sub>n−1</sub></sub>(…G<sub>x<sub>1</sub></sub>(k))). The proof uses a hybrid argument: replacing each level of the tree with a random function one at a time and bounding the distinguishing advantage at each step by the PRG's advantage.
          </p>

          <h4>Why both halves are computed in the trace</h4>
          <p>
            In a real PRF evaluator, only the chosen child is computed — the other half of the tree never materializes. The trace shown here computes both children at each visited node for visualization, so you can see the unchosen sibling. The key property remains: each leaf depends on a unique sequence of G<sub>0</sub>/G<sub>1</sub> applications, and there are 2<sup>n</sup> distinct leaves in the conceptual tree.
          </p>

          <h4>The OWF → PRG → PRF chain</h4>
          <p>
            PA#1 introduced OWFs and showed PRG ⇒ OWF (the easy direction). The hard direction OWF ⇒ PRG was proved by Håstad-Impagliazzo-Levin-Luby (1999). PA#2 then completes the chain: GGM gives PRG ⇒ PRF, and Section 2 here gives PRF ⇒ PRG (almost trivial). So the three primitives are equivalent in terms of existence — any one yields the others. This is why the cryptographic universe with PRG/PRF/OWF is called <em>Minicrypt</em>.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#2 → PA#1 (PRG, used as the length-doubler at each tree level). PA#5 (MAC) and PA#3 (CPA encryption) build directly on PRFs, so PA#2 is a foundational dependency for almost every later construction in the course.
          </p>
        </div>
      </details>
    </div>
  );
}
