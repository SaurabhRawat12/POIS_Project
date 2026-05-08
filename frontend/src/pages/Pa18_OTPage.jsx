import { useState } from 'react';
import './Pa18_OTPage.css';

const API_BASE = 'http://localhost:8000';

const formatBigNum = (val) => {
  if (val === null || val === undefined) return '—';
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return String(val);
    if (Math.abs(val) > 1e10) {
      const exp = val.toExponential(4);
      const [m, e] = exp.split('e');
      return `${m} × 10^${parseInt(e, 10)}`;
    }
    return val.toLocaleString('en-US');
  }
  return String(val);
};

export default function Pa18_OTPage() {
  // Section 1 — protocol run
  const [m0, setM0] = useState(100);
  const [m1, setM1] = useState(200);
  const [b, setB] = useState(0);
  const [runResult, setRunResult] = useState(null);
  const [runError, setRunError] = useState(null);
  const [runLoading, setRunLoading] = useState(false);

  // Section 2 — receiver privacy
  const [recvResult, setRecvResult] = useState(null);
  const [recvError, setRecvError] = useState(null);
  const [recvLoading, setRecvLoading] = useState(false);

  // Section 3 — sender privacy
  const [senderResult, setSenderResult] = useState(null);
  const [senderError, setSenderError] = useState(null);
  const [senderLoading, setSenderLoading] = useState(false);

  const runProtocol = async () => {
    setRunLoading(true);
    setRunError(null);
    try {
      const res = await fetch(`${API_BASE}/pa18/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ b, m_0: m0, m_1: m1, q_bits: 63, k: 20, seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setRunResult(data.result || data);
    } catch (err) {
      setRunError(err.message);
    } finally {
      setRunLoading(false);
    }
  };

  const runReceiverPrivacy = async () => {
    setRecvLoading(true);
    setRecvError(null);
    try {
      const res = await fetch(`${API_BASE}/pa18/receiver-privacy-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q_bits: 63, k: 20, seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setRecvResult(data.result || data);
    } catch (err) {
      setRecvError(err.message);
    } finally {
      setRecvLoading(false);
    }
  };

  const runSenderPrivacy = async () => {
    setSenderLoading(true);
    setSenderError(null);
    try {
      const res = await fetch(`${API_BASE}/pa18/sender-privacy-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q_bits: 63, k: 20, seed: 0 }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }
      const data = await res.json();
      setSenderResult(data.result || data);
    } catch (err) {
      setSenderError(err.message);
    } finally {
      setSenderLoading(false);
    }
  };

  // Slot helpers — highlight the active slot (the one matching b)
  const slot0Class = (active) =>
    `slot-row${active && b === 0 ? ' slot-active' : ''}`;
  const slot1Class = (active) =>
    `slot-row${active && b === 1 ? ' slot-active' : ''}`;

  return (
    <div className="pa18-page">
      <header className="pa18-header">
        <h1>PA#18 — 1-out-of-2 Oblivious Transfer (Bellare-Micali)</h1>
        <p className="pa18-subtitle">
          Alice has two messages m₀, m₁. Bob picks one bit b ∈ {'{0, 1}'}. After the protocol, Bob learns m_b and nothing about m_{'{1-b}'}; Alice learns nothing about b. The atomic building block of all 2-party MPC — your PA#19 Secure AND uses it as a black box.
        </p>
      </header>

      {/* ============ SECTION 1: PROTOCOL RUN ============ */}
      <section className="pa18-section">
        <div className="section-head">
          <h2>1. Run the OT Protocol</h2>
          <span className="status-tag tag-info">YOU PLAY BOB</span>
        </div>
        <p className="section-desc">
          You're the receiver. Alice holds m₀ and m₁ (you set both for the demo, but in deployment only Alice would). Pick a choice bit b. The protocol runs three message exchanges; you'll see Alice's view, Bob's view, and the wire transcript.
        </p>

        <div className="control-row">
          <label>
            <span className="ctrl-label">m₀</span>
            <input
              type="number"
              value={m0}
              onChange={(e) => setM0(Number(e.target.value))}
              disabled={runLoading}
              className="ctrl-input"
              min={1}
            />
          </label>
          <label>
            <span className="ctrl-label">m₁</span>
            <input
              type="number"
              value={m1}
              onChange={(e) => setM1(Number(e.target.value))}
              disabled={runLoading}
              className="ctrl-input"
              min={1}
            />
          </label>
          <label>
            <span className="ctrl-label">choice b</span>
            <select
              value={b}
              onChange={(e) => setB(Number(e.target.value))}
              disabled={runLoading}
              className="ctrl-input"
            >
              <option value={0}>0 (want m₀)</option>
              <option value={1}>1 (want m₁)</option>
            </select>
          </label>
          <button onClick={runProtocol} disabled={runLoading} className="btn btn-primary">
            {runLoading ? 'Running protocol…' : runResult ? 'Run again' : 'Run the protocol'}
          </button>
        </div>

        {runError && <div className="error-box">Error: {runError}</div>}

        {runResult && (
          <>
            {/* Step 0: Public params */}
            <div className="card params-card">
              <div className="step-tag step-tag-meta">PUBLIC SETUP · agreed in advance</div>
              <h3>Group parameters</h3>
              <div className="kv"><span className="key">p</span><code className="val mono">{formatBigNum(runResult.transcript.params.p)}</code></div>
              <div className="kv"><span className="key">g</span><code className="val mono">{formatBigNum(runResult.transcript.params.g)}</code></div>
              <div className="kv"><span className="key">q</span><code className="val mono">{formatBigNum(runResult.transcript.params.q)}</code></div>
              <div className="kv"><span className="key">C = g^α (α discarded)</span><code className="val mono">{formatBigNum(runResult.transcript.params.C)}</code></div>
              <div className="setup-note">
                C is the trapdoor element — nobody knows log<sub>g</sub>(C). This asymmetry is what makes the Bellare-Micali OT secure.
              </div>
            </div>

            <div className="flow-arrow-step">↓</div>

            {/* Step 1: Bob constructs keys */}
            <div className="card bob-card">
              <div className="step-tag step-tag-bob">STEP 1 · BOB</div>
              <h3>Construct two public keys</h3>
              <p className="step-narrative">
                Bob generates sk_b honestly (knows the discrete log). For the other slot, Bob computes pk_<sub>1−b</sub> = C / pk_b — that key is structurally valid but Bob has no trapdoor for it.
              </p>
              <div className={slot0Class(true)}>
                <span className="slot-label">pk₀</span>
                <code className="slot-val mono">{formatBigNum(runResult.transcript.pk_0)}</code>
                <span className="slot-tag">{b === 0 ? 'with trapdoor (sk₀ known)' : 'no trapdoor'}</span>
              </div>
              <div className={slot1Class(true)}>
                <span className="slot-label">pk₁</span>
                <code className="slot-val mono">{formatBigNum(runResult.transcript.pk_1)}</code>
                <span className="slot-tag">{b === 1 ? 'with trapdoor (sk₁ known)' : 'no trapdoor'}</span>
              </div>
              <div className="wire-note">→ sends (pk₀, pk₁) to Alice</div>
            </div>

            <div className="flow-arrow-step">↓ (pk₀, pk₁)</div>

            {/* Step 2: Alice encrypts */}
            <div className="card alice-card">
              <div className="step-tag step-tag-alice">STEP 2 · ALICE</div>
              <h3>Encrypt both messages</h3>
              <p className="step-narrative">
                Alice can't tell which key has the trapdoor — both look uniformly random under the constraint pk₀·pk₁ = C. So she encrypts m₀ under pk₀ and m₁ under pk₁ blindly.
              </p>
              <div className={slot0Class(true)}>
                <span className="slot-label">m₀ → C₀</span>
                <code className="slot-val mono">
                  ({formatBigNum(runResult.transcript.C_0.c1)},&nbsp;{formatBigNum(runResult.transcript.C_0.c2)})
                </code>
              </div>
              <div className={slot1Class(true)}>
                <span className="slot-label">m₁ → C₁</span>
                <code className="slot-val mono">
                  ({formatBigNum(runResult.transcript.C_1.c1)},&nbsp;{formatBigNum(runResult.transcript.C_1.c2)})
                </code>
              </div>
              <div className="wire-note">→ sends (C₀, C₁) to Bob</div>
            </div>

            <div className="flow-arrow-step">↓ (C₀, C₁)</div>

            {/* Step 3: Bob decrypts */}
            <div className="card bob-card">
              <div className="step-tag step-tag-bob">STEP 3 · BOB</div>
              <h3>Decrypt only the chosen ciphertext</h3>
              <p className="step-narrative">
                Bob has sk_b for slot b. He decrypts C_b → m_b. The other slot is structurally locked: no sk means decryption produces a uniformly random group element, not the underlying message.
              </p>
              <div className={`outcome-row outcome-received`}>
                <span className="outcome-label">m_b received</span>
                <code className="outcome-val mono">{formatBigNum(runResult.received)}</code>
                <span className="outcome-check">{runResult.correct ? '✓ matches m_' + b : '✗ mismatch'}</span>
              </div>
              <div className="outcome-row outcome-hidden">
                <span className="outcome-label">m_{1 - b}</span>
                <code className="outcome-val key-hidden">🔒 hidden — no sk for slot {1 - b}</code>
              </div>
            </div>

            <div className={`verdict-banner ${runResult.correct ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>{runResult.correct ? `✓ OT successful — Bob received m_${b} = ${formatBigNum(runResult.received)}` : '✗ Protocol failed — investigate'}</h3>
              <p>
                Bob obtained <strong>only</strong> m<sub>{b}</sub>; the other message remains hidden. Alice never learned which slot Bob chose — both keys looked indistinguishable to her. This is the OT guarantee: receiver privacy + sender privacy in one protocol.
              </p>
              <p className="contrast-note">
                <strong>Tip:</strong> change the choice b and re-run. With seed=0 fixed, you'll see pk₀ and pk₁ swap positions while c₁ in each ciphertext stays identical — the "active slot" follows your choice.
              </p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 2: RECEIVER PRIVACY ============ */}
      <section className="pa18-section">
        <div className="section-head">
          <h2>2. Receiver Privacy</h2>
          <span className="status-tag tag-secure">SENDER LEARNS NOTHING</span>
        </div>
        <p className="section-desc">
          Verifies that the constraint pk₀ · pk₁ ≡ C (mod p) holds for both choices of b, with each individual key uniformly random under that constraint. Alice sees only the pair — she cannot tell whether b=0 or b=1.
        </p>

        <div className="control-row">
          <button onClick={runReceiverPrivacy} disabled={recvLoading} className="btn btn-secondary">
            {recvLoading ? 'Checking…' : recvResult ? 'Re-check' : 'Verify receiver privacy'}
          </button>
        </div>

        {recvError && <div className="error-box">Error: {recvError}</div>}

        {recvResult && (
          <>
            <div className="constraint-grid">
              <div className={`constraint-row ${recvResult.constraint_holds_for_b0 ? 'constraint-pass' : 'constraint-fail'}`}>
                <span className="constraint-label">b = 0:</span>
                <code className="constraint-eq mono">pk₀ · pk₁ ≡ C (mod p)</code>
                <span className="constraint-verdict">{recvResult.constraint_holds_for_b0 ? '✓ holds' : '✗ fails'}</span>
              </div>
              <div className={`constraint-row ${recvResult.constraint_holds_for_b1 ? 'constraint-pass' : 'constraint-fail'}`}>
                <span className="constraint-label">b = 1:</span>
                <code className="constraint-eq mono">pk₀ · pk₁ ≡ C (mod p)</code>
                <span className="constraint-verdict">{recvResult.constraint_holds_for_b1 ? '✓ holds' : '✗ fails'}</span>
              </div>
            </div>

            <div className={`verdict-banner ${recvResult.constraint_holds_for_b0 && recvResult.constraint_holds_for_b1 ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {recvResult.constraint_holds_for_b0 && recvResult.constraint_holds_for_b1
                  ? '✓ Receiver privacy holds — sender cannot distinguish b=0 from b=1'
                  : '⚠ Constraint violated — investigate'}
              </h3>
              <p>{recvResult.security_note}</p>
            </div>
          </>
        )}
      </section>

      {/* ============ SECTION 3: SENDER PRIVACY ============ */}
      <section className="pa18-section">
        <div className="section-head">
          <h2>3. Sender Privacy</h2>
          <span className="status-tag tag-secure">RECEIVER CAN'T CHEAT</span>
        </div>
        <p className="section-desc">
          Verifies that Bob can't recover the message he didn't choose. Bob picks b=0 (gets m₀ legitimately), then tries to use sk₀ against C₁ — the wrong key for that ciphertext. The result is a uniformly random group element, not m₁.
        </p>

        <div className="control-row">
          <button onClick={runSenderPrivacy} disabled={senderLoading} className="btn btn-secondary">
            {senderLoading ? 'Running…' : senderResult ? 'Re-run' : 'Verify sender privacy'}
          </button>
        </div>

        {senderError && <div className="error-box">Error: {senderError}</div>}

        {senderResult && (
          <>
            <div className="card cheat-card">
              <h3>Bob picked b=0; tries to also recover m₁</h3>
              <div className="kv">
                <span className="key">m₀ (Bob legitimately receives)</span>
                <code className="val mono attack-defeated">{formatBigNum(senderResult.legit_received)}</code>
              </div>
              <div className="kv">
                <span className="key">m₁ (Bob shouldn't see)</span>
                <code className="val mono">{formatBigNum(senderResult.m_1)}</code>
                <span className="kv-aside">— shown for comparison only; in real OT Bob never knows this value</span>
              </div>
              <div className="cheat-divider" />
              <div className="kv">
                <span className="key">Bob applies sk₀ to C₁</span>
                <code className="val mono attack-succeeded">{formatBigNum(senderResult.cheat_attempt_on_C_1)}</code>
              </div>
              <div className="kv">
                <span className="key">Equals m₁?</span>
                <code className={`val mono ${senderResult.cheat_recovered_m_1 ? 'attack-succeeded' : 'attack-defeated'}`}>
                  {senderResult.cheat_recovered_m_1 ? '✗ YES — leak!' : '✓ NO — random group element'}
                </code>
              </div>
            </div>

            <div className={`verdict-banner ${!senderResult.cheat_recovered_m_1 ? 'verdict-secure' : 'verdict-broken'}`}>
              <h3>
                {!senderResult.cheat_recovered_m_1
                  ? '✓ Sender privacy holds — wrong key produces garbage, not m₁'
                  : '⚠ Sender privacy violated — investigate'}
              </h3>
              <p>{senderResult.security_note}</p>
              <p className="contrast-note">
                Why it works: pk₁ was computed as C / pk₀, so its discrete log is unknown to Bob (it depends on log<sub>g</sub>(C), which nobody knows). ElGamal decryption with the wrong sk produces a uniformly distributed group element with no relationship to the plaintext.
              </p>
            </div>
          </>
        )}
      </section>

      {/* Pedagogy */}
      <details className="pedagogy">
        <summary>Pedagogy &amp; full math</summary>
        <div className="pedagogy-content">
          <h4>The Bellare-Micali 1-out-of-2 OT</h4>
          <p>
            Setup: cyclic group ⟨g⟩ of prime order q, plus a public element C = g<sup>α</sup> where α is sampled and immediately discarded. After setup, log<sub>g</sub>(C) is known to nobody.
          </p>
          <p>
            <strong>Receiver step 1.</strong> Bob with choice b ∈ {'{0, 1}'}: sample sk<sub>b</sub> ← ℤ_q, set pk<sub>b</sub> = g<sup>sk_b</sup>. Compute pk<sub>1−b</sub> = C · pk<sub>b</sub><sup>−1</sup>. Send (pk₀, pk₁) to Alice.
          </p>
          <p>
            <strong>Sender step.</strong> Alice with messages (m₀, m₁): sample r₀, r₁ ← ℤ_q. Encrypt under each pk: C_i = (g<sup>r_i</sup>, m_i · pk_i<sup>r_i</sup>). Send (C₀, C₁) to Bob.
          </p>
          <p>
            <strong>Receiver step 2.</strong> Bob: m_b = c<sub>b,2</sub> · c<sub>b,1</sub><sup>−sk_b</sup>. He cannot decrypt C<sub>1−b</sub> because he doesn't know sk<sub>1−b</sub> = log<sub>g</sub>(pk<sub>1−b</sub>).
          </p>

          <h4>Receiver privacy (Alice can't learn b)</h4>
          <p>
            Whichever b Bob chose, both pk₀ and pk₁ are uniformly random group elements satisfying pk₀ · pk₁ = C. Section 2 verifies this constraint holds in both cases. The marginal distribution of (pk₀, pk₁) is identical for b=0 and b=1, so Alice's view is statistically independent of b.
          </p>

          <h4>Sender privacy (Bob can't learn m_<sub>1−b</sub>)</h4>
          <p>
            For Bob to recover m<sub>1−b</sub>, he'd need sk<sub>1−b</sub> = log<sub>g</sub>(pk<sub>1−b</sub>) = log<sub>g</sub>(C / pk_b) = log<sub>g</sub>(C) − sk<sub>b</sub>. Since log<sub>g</sub>(C) is unknown (DL assumption), Bob cannot compute it. Section 3 demonstrates this concretely: applying sk_b to the wrong ciphertext yields a uniformly random group element.
          </p>

          <h4>Lineage</h4>
          <p>
            PA#18 → PA#16 (ElGamal encryption for the OT messages) → PA#11 (DH group setup) → PA#13 (Miller-Rabin). Per the no-library rule, every primitive in this chain is your own implementation.
          </p>

          <h4>What's next</h4>
          <p>
            <strong>PA#19 Secure AND</strong> uses this OT as a black box: Alice's messages become (0, a), Bob's choice bit becomes b, and Bob receives a∧b. PA#20 then composes Secure AND with Secure XOR to evaluate any boolean circuit privately — millionaire's problem, equality test, secure addition, etc.
          </p>
        </div>
      </details>
    </div>
  );
}
