import { useState } from 'react';
import './Pa19_SecureGatesPage.css';

const API_BASE = 'http://localhost:8000';

const xorExpected = (a, b) => a ^ b;
const notExpected = (a) => 1 - a;

export default function Pa19_SecureGatesPage() {
  // Section 1 — interactive three-gate evaluator
  const [a, setA] = useState(1);
  const [b, setB] = useState(1);
  const [andResult, setAndResult] = useState(null);
  const [xorResult, setXorResult] = useState(null);
  const [notResult, setNotResult] = useState(null);
  const [gatesError, setGatesError] = useState(null);
  const [gatesLoading, setGatesLoading] = useState(false);

  // Section 2 — truth table
  const [runsPerCombo, setRunsPerCombo] = useState(10);
  const [truthTable, setTruthTable] = useState(null);
  const [ttError, setTtError] = useState(null);
  const [ttLoading, setTtLoading] = useState(false);

  // Section 3 — privacy
  const [privacy, setPrivacy] = useState(null);
  const [privacyError, setPrivacyError] = useState(null);
  const [privacyLoading, setPrivacyLoading] = useState(false);

  const runGates = async () => {
    setGatesLoading(true);
    setGatesError(null);
    setAndResult(null);
    setXorResult(null);
    setNotResult(null);
    try {
      const body = JSON.stringify({ a, b, q_bits: 63, k: 20, seed: 0 });
      const headers = { 'Content-Type': 'application/json' };

      const [andRes, xorRes, notRes] = await Promise.all([
        fetch(`${API_BASE}/pa19/and`, { method: 'POST', headers, body }),
        fetch(`${API_BASE}/pa19/xor`, { method: 'POST', headers, body }),
        fetch(`${API_BASE}/pa19/not`, { method: 'POST', headers, body }),
      ]);

      for (const r of [andRes, xorRes, notRes]) {
        if (!r.ok) {
          const errText = await r.text();
          throw new Error(`HTTP ${r.status}: ${errText}`);
        }
      }

      const [andData, xorData, notData] = await Promise.all([
        andRes.json(), xorRes.json(), notRes.json(),
      ]);

      setAndResult(andData.result || andData);
      setXorResult(xorData.result || xorData);
      setNotResult(notData.result || notData);
    } catch (err) {
      setGatesError(err.message);
    } finally {
      setGatesLoading(false);
    }
  };

  const runTruthTable = async () => {
    setTtLoading(true);
    setTtError(null);
    try {
      const res = await fetch(`${API_BASE}/pa19/truth-table`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ runs_per_combo: runsPerCombo, q_bits: 63, k: 20, seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setTruthTable(data.result || data);
    } catch (err) {
      setTtError(err.message);
    } finally {
      setTtLoading(false);
    }
  };

  const runPrivacy = async () => {
    setPrivacyLoading(true);
    setPrivacyError(null);
    try {
      const res = await fetch(`${API_BASE}/pa19/privacy-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q_bits: 63, k: 20, seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setPrivacy(data.result || data);
    } catch (err) {
      setPrivacyError(err.message);
    } finally {
      setPrivacyLoading(false);
    }
  };

  // Truth table cell renderer
  const renderTtCell = (table, ai, bi) => {
    const key = `${ai},${bi}`;
    const val = table[key];
    return (
      <div className={`tt-cell tt-cell-${val}`}>
        {val}
      </div>
    );
  };

  // Total OT cost across all three gates this run
  const totalOtCost =
    (andResult?.ot_calls ?? 0) +
    (xorResult?.ot_calls ?? 0) +
    (notResult?.ot_calls ?? 0);

  return (
    <div className="pa19-page">
      <header className="pa19-header">
        <h1>PA#19 — Secure Gates: AND, XOR, NOT</h1>
        <p className="pa19-subtitle">
          Three boolean gates evaluated privately by Alice and Bob. AND requires one OT call (interactive); XOR and NOT are free in the GMW shared-wire model. The cost asymmetry is what makes secure circuits practical: minimize ANDs, lavish the XORs.
        </p>
      </header>

      {/* ============ SECTION 1: GATE EVALUATOR ============ */}
      <section className="pa19-section">
        <div className="section-head">
          <h2>1. Run the Three Gates</h2>
          <span className="status-tag tag-info">SAME INPUTS · 3 GATES</span>
        </div>
        <p className="section-desc">
          Pick Alice's bit a and Bob's bit b. All three gates run in parallel against the same inputs. Watch the OT-call count: AND consumes one OT, XOR and NOT consume zero. That's why circuit designers fight for fewer ANDs.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Alice's a</span>
            <select
              value={a}
              onChange={(e) => setA(Number(e.target.value))}
              disabled={gatesLoading}
              className="ctrl-input"
            >
              <option value={0}>0</option>
              <option value={1}>1</option>
            </select>
          </label>
          <label>
            <span className="ctrl-label">Bob's b</span>
            <select
              value={b}
              onChange={(e) => setB(Number(e.target.value))}
              disabled={gatesLoading}
              className="ctrl-input"
            >
              <option value={0}>0</option>
              <option value={1}>1</option>
            </select>
          </label>
          <button onClick={runGates} disabled={gatesLoading} className="btn btn-primary">
            {gatesLoading ? 'Running gates…' : (andResult ? 'Run again' : 'Run all three gates')}
          </button>
        </div>

        {gatesError && <div className="error-box">Error: {gatesError}</div>}

        {andResult && xorResult && notResult && (
          <>
            <div className="gates-grid">
              {/* AND */}
              <div className="card gate-card gate-and">
                <div className="gate-symbol">∧</div>
                <h3>Secure AND</h3>
                <div className="cost-badge cost-paid">
                  <span className="cost-icon">⚙</span>
                  <span className="cost-value">{andResult.ot_calls} OT call{andResult.ot_calls !== 1 ? 's' : ''}</span>
                  <span className="cost-detail">interactive</span>
                </div>
                <div className="gate-io">
                  <div className="io-row">
                    <span className="io-label">a</span>
                    <code className="io-val">{andResult.alice_input}</code>
                  </div>
                  <div className="io-row">
                    <span className="io-label">b</span>
                    <code className="io-val">{andResult.bob_input}</code>
                  </div>
                  <div className="io-divider" />
                  <div className="io-row io-output">
                    <span className="io-label">a ∧ b</span>
                    <code className="io-val io-result">{andResult.output}</code>
                  </div>
                </div>
                <div className={`gate-status ${andResult.correct ? 'status-ok' : 'status-fail'}`}>
                  {andResult.correct ? `✓ matches expected (${andResult.expected})` : '✗ mismatch — investigate'}
                </div>
              </div>

              {/* XOR */}
              <div className="card gate-card gate-xor">
                <div className="gate-symbol">⊕</div>
                <h3>Secure XOR</h3>
                <div className="cost-badge cost-free">
                  <span className="cost-icon">⚡</span>
                  <span className="cost-value">{xorResult.ot_calls} OT calls</span>
                  <span className="cost-detail">FREE · local</span>
                </div>
                <div className="gate-io">
                  <div className="io-row">
                    <span className="io-label">a</span>
                    <code className="io-val">{xorResult.alice_input}</code>
                  </div>
                  <div className="io-row">
                    <span className="io-label">b</span>
                    <code className="io-val">{xorResult.bob_input}</code>
                  </div>
                  <div className="io-divider" />
                  <div className="io-row io-output">
                    <span className="io-label">a ⊕ b</span>
                    <code className="io-val io-result">{xorResult.output}</code>
                  </div>
                </div>
                <div className={`gate-status ${xorResult.output === xorExpected(a, b) ? 'status-ok' : 'status-fail'}`}>
                  {xorResult.output === xorExpected(a, b)
                    ? `✓ matches expected (${xorExpected(a, b)})`
                    : '✗ mismatch — investigate'}
                </div>
              </div>

              {/* NOT */}
              <div className="card gate-card gate-not">
                <div className="gate-symbol">¬</div>
                <h3>Secure NOT(a)</h3>
                <div className="cost-badge cost-free">
                  <span className="cost-icon">⚡</span>
                  <span className="cost-value">{notResult.ot_calls} OT calls</span>
                  <span className="cost-detail">FREE · local flip</span>
                </div>
                <div className="gate-io">
                  <div className="io-row">
                    <span className="io-label">a</span>
                    <code className="io-val">{notResult.input}</code>
                  </div>
                  <div className="io-divider" />
                  <div className="io-row io-output">
                    <span className="io-label">¬a</span>
                    <code className="io-val io-result">{notResult.output}</code>
                  </div>
                </div>
                <div className={`gate-status ${notResult.output === notExpected(notResult.input) ? 'status-ok' : 'status-fail'}`}>
                  {notResult.output === notExpected(notResult.input)
                    ? `✓ matches expected (${notExpected(notResult.input)})`
                    : '✗ mismatch — investigate'}
                </div>
              </div>
            </div>

            <div className="cost-summary">
              <div className="cost-summary-label">Total OT cost for this evaluation:</div>
              <div className="cost-summary-value">{totalOtCost}</div>
              <div className="cost-summary-detail">
                ({andResult.ot_calls} from AND, {xorResult.ot_calls} from XOR, {notResult.ot_calls} from NOT)
                — only AND requires interaction; the other two are local computation.
              </div>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 2: TRUTH TABLE ============ */}
      <section className="pa19-section">
        <div className="section-head">
          <h2>2. Truth Tables — Empirical Verification</h2>
          <span className="status-tag tag-secure">CORRECTNESS</span>
        </div>
        <p className="section-desc">
          Run AND and XOR for each (a, b) combination, multiple trials each. The 2×2 outputs match the textbook truth tables, every time. This is the correctness side of secure computation: privacy is worthless if the circuit returns the wrong answer.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">Runs per combo</span>
            <select
              value={runsPerCombo}
              onChange={(e) => setRunsPerCombo(Number(e.target.value))}
              disabled={ttLoading}
              className="ctrl-input"
            >
              <option value={5}>5 (20 total)</option>
              <option value={10}>10 (40 total)</option>
              <option value={25}>25 (100 total)</option>
              <option value={50}>50 (200 total)</option>
            </select>
          </label>
          <button onClick={runTruthTable} disabled={ttLoading} className="btn btn-secondary">
            {ttLoading ? 'Running…' : (truthTable ? 'Re-run' : 'Run truth table')}
          </button>
        </div>

        {ttError && <div className="error-box">Error: {ttError}</div>}

        {truthTable && (
          <>
            <div className="truth-tables">
              <div className="card tt-card">
                <h3>AND</h3>
                <div className="tt-grid">
                  <div className="tt-corner" />
                  <div className="tt-header">b=0</div>
                  <div className="tt-header">b=1</div>
                  <div className="tt-header">a=0</div>
                  {renderTtCell(truthTable.and_truth_table, 0, 0)}
                  {renderTtCell(truthTable.and_truth_table, 0, 1)}
                  <div className="tt-header">a=1</div>
                  {renderTtCell(truthTable.and_truth_table, 1, 0)}
                  {renderTtCell(truthTable.and_truth_table, 1, 1)}
                </div>
                <div className={`tt-stat ${truthTable.and_perfect ? 'tt-stat-ok' : 'tt-stat-fail'}`}>
                  {truthTable.and_correct_count} / {truthTable.total_runs} correct
                  {truthTable.and_perfect && ' · perfect'}
                </div>
              </div>

              <div className="card tt-card">
                <h3>XOR</h3>
                <div className="tt-grid">
                  <div className="tt-corner" />
                  <div className="tt-header">b=0</div>
                  <div className="tt-header">b=1</div>
                  <div className="tt-header">a=0</div>
                  {renderTtCell(truthTable.xor_truth_table, 0, 0)}
                  {renderTtCell(truthTable.xor_truth_table, 0, 1)}
                  <div className="tt-header">a=1</div>
                  {renderTtCell(truthTable.xor_truth_table, 1, 0)}
                  {renderTtCell(truthTable.xor_truth_table, 1, 1)}
                </div>
                <div className={`tt-stat ${truthTable.xor_perfect ? 'tt-stat-ok' : 'tt-stat-fail'}`}>
                  {truthTable.xor_correct_count} / {truthTable.total_runs} correct
                  {truthTable.xor_perfect && ' · perfect'}
                </div>
              </div>
            </div>

            <div className={`verdict-banner ${truthTable.and_perfect && truthTable.xor_perfect ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {truthTable.and_perfect && truthTable.xor_perfect
                  ? `✓ ${truthTable.total_runs * 2} secure-gate evaluations, ${truthTable.and_correct_count + truthTable.xor_correct_count} correct outputs`
                  : '⚠ Some runs returned incorrect outputs — investigate'}
              </h3>
              <p>
                Each run involves fresh randomness in the OT subprotocol (for AND) and fresh share masks (for XOR). The fact that all runs produce the textbook output means the protocol's correctness doesn't depend on any specific randomness pattern.
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 3: PRIVACY ============ */}
      <section className="pa19-section">
        <div className="section-head">
          <h2>3. Privacy Independence</h2>
          <span className="status-tag tag-secure">NEITHER LEARNS MORE</span>
        </div>
        <p className="section-desc">
          The privacy claim of secure AND: each party's view of the protocol is independent of the other party's input, beyond what the output reveals. Concretely, when Bob's bit b=0, the output is 0 regardless of a — so Bob's view in that case is independent of a.
        </p>

        <div className="control-row">
          <button onClick={runPrivacy} disabled={privacyLoading} className="btn btn-secondary">
            {privacyLoading ? 'Verifying…' : (privacy ? 'Re-verify' : 'Verify privacy')}
          </button>
        </div>

        {privacyError && <div className="error-box">Error: {privacyError}</div>}

        {privacy && (
          <>
            <div className="privacy-checks">
              <div className={`privacy-row ${privacy.bob_view_independent_of_alice ? 'privacy-pass' : 'privacy-fail'}`}>
                <span className="privacy-label">Bob's view ⊥ Alice's input</span>
                <span className="privacy-context">when b=0, output is 0 regardless of a</span>
                <span className="privacy-verdict">{privacy.bob_view_independent_of_alice ? '✓ verified' : '✗ leaked'}</span>
              </div>
              <div className={`privacy-row ${privacy.alice_view_independent_of_bob ? 'privacy-pass' : 'privacy-fail'}`}>
                <span className="privacy-label">Alice's view ⊥ Bob's input</span>
                <span className="privacy-context">when a=0, output is 0 regardless of b</span>
                <span className="privacy-verdict">{privacy.alice_view_independent_of_bob ? '✓ verified' : '✗ leaked'}</span>
              </div>
            </div>

            <div className={`verdict-banner ${privacy.bob_view_independent_of_alice && privacy.alice_view_independent_of_bob ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {privacy.bob_view_independent_of_alice && privacy.alice_view_independent_of_bob
                  ? '✓ Privacy holds — neither party learns more than the AND output'
                  : '⚠ Privacy violated — investigate'}
              </h3>
              <p>{privacy.security_note}</p>
              <p className="contrast-note">
                <strong>Note:</strong> "learns more than the AND output" is the strongest privacy bound possible for this functionality — if a∧b = 1, both parties necessarily learn that the other's input was 1, because that's part of the output. The protocol leaks nothing else.
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>Secure AND from OT</h4>
          <p>
            Alice has bit a, Bob has bit b. Alice plays the OT sender with messages (m₀, m₁) = (0, a). Bob plays the OT receiver with choice bit b. By OT's guarantee, Bob receives m_b: if b=0 he gets 0, if b=1 he gets a. In both cases, Bob's output equals a · b = a ∧ b.
          </p>
          <pre className="math-block">{`Alice (input a)         Bob (input b)
       │                       │
       │  OT sender             │  OT receiver
       │  (m_0=0, m_1=a)        │  choice = b
       └──────── OT ────────────┘
                                       │
                          Bob receives m_b = a·b = a∧b`}</pre>
          <p>
            Privacy: Alice learns nothing about b (OT sender privacy from PA#18). Bob learns m_b, which is a∧b — the intended output, nothing more.
          </p>

          <h4>Free XOR via additive secret sharing</h4>
          <p>
            Each input wire is split into shares: a = a_A ⊕ a_B where Alice holds a_A and Bob holds a_B. To compute c = a ⊕ b on shared wires, each party locally XORs their shares: c_A = a_A ⊕ b_A, c_B = a_B ⊕ b_B. By distributivity: c_A ⊕ c_B = (a_A ⊕ a_B) ⊕ (b_A ⊕ b_B) = a ⊕ b. No communication required. This is the GMW free-XOR property and it's the reason MPC efficiency is dominated by the AND count, not the XOR count.
          </p>

          <h4>NOT is also free</h4>
          <p>
            Alice locally flips her share: a_A' = ¬a_A. The reconstructed value satisfies a_A' ⊕ a_B = ¬a_A ⊕ a_B = ¬(a_A ⊕ a_B) = ¬a. Pure local computation, no transcript exists.
          </p>

          <h4>Why AND is the cost driver</h4>
          <p>
            Any boolean circuit C can be expressed using AND, XOR, and NOT gates (the basis is functionally complete). Secure AND requires one OT per gate; XOR and NOT are free. So the secure-evaluation cost of C is essentially proportional to its <em>multiplicative complexity</em>: the number of AND gates. Optimizing MPC circuits is therefore an exercise in restructuring computation to minimize ANDs while spending XORs liberally.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#19 → PA#18 (OT for the AND gate) → PA#16 (ElGamal inside OT) → PA#11 (group setup) → PA#13 (Miller-Rabin). PA#20 then uses these gate primitives to evaluate arbitrary boolean circuits.
          </p>
        </div>
      </details>
    </div>
  );
}
