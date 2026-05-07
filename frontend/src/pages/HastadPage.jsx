import { useState, useEffect } from 'react'
import './HastadPage.css'

const API_BASE = 'http://localhost:8000'

const BITS_OPTIONS_NONE = [64, 128, 192]
const BITS_OPTIONS_PKCS = [128, 192]

const RECIPIENTS = [
  { name: 'Alice',   color: 'rose' },
  { name: 'Bob',     color: 'blue' },
  { name: 'Charlie', color: 'mint' },
]

export default function HastadPage() {
  const [message, setMessage] = useState(42)
  const [bits, setBits] = useState(64)
  const [padding, setPadding] = useState('none') // 'none' | 'pkcs15'
  const [seed, setSeed] = useState(0)

  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const bitsOptions = padding === 'none' ? BITS_OPTIONS_NONE : BITS_OPTIONS_PKCS

  // PKCS#1 v1.5 needs >= 11 bytes overhead, so bits >= 128 in this demo
  useEffect(() => {
    if (padding === 'pkcs15' && bits === 64) setBits(128)
  }, [padding, bits])

  async function runBroadcast() {
    setError(null)
    setResult(null)
    setRunning(true)
    try {
      const res = await fetch(`${API_BASE}/pa14/hastad-demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message,
          bits,
          e: 3,
          use_pkcs15: padding === 'pkcs15',
          k: 12,
          seed,
        }),
      })
      if (!res.ok) {
        const body = await res.text()
        throw new Error(`HTTP ${res.status}: ${body || res.statusText}`)
      }
      const data = await res.json()
      setResult(data.result)
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="hastad-page">
      <header className="hp-header">
        <h2>PA#14 — Håstad's Broadcast Attack</h2>
        <p className="subtitle">
          When the same message is broadcast to e or more recipients using
          textbook RSA with low public exponent (e=3), an eavesdropper can
          recover the plaintext using only public information: combine the
          ciphertexts with CRT, then take a single integer e-th root. PKCS#1 v1.5
          padding defeats the attack by ensuring each recipient encrypts a
          different padded message — no common cube to extract.
        </p>
      </header>

      <section className="setup-strip">
        <label className="ctrl">
          <span className="ctrl-label">Message m</span>
          <input
            type="number"
            min={1}
            max={1000000}
            value={message}
            onChange={(e) => setMessage(parseInt(e.target.value, 10) || 0)}
            className="num-input"
          />
        </label>

        <label className="ctrl">
          <span className="ctrl-label">RSA modulus bits</span>
          <select value={bits} onChange={(e) => setBits(parseInt(e.target.value, 10))}>
            {bitsOptions.map((b) => (
              <option key={b} value={b}>{b}-bit</option>
            ))}
          </select>
        </label>

        <div className="ctrl ctrl-padding">
          <span className="ctrl-label">Padding</span>
          <div className="seg-control">
            <button
              className={`seg-btn ${padding === 'none' ? 'active' : ''}`}
              onClick={() => setPadding('none')}
            >
              None (textbook RSA)
            </button>
            <button
              className={`seg-btn ${padding === 'pkcs15' ? 'active' : ''}`}
              onClick={() => setPadding('pkcs15')}
            >
              PKCS#1 v1.5
            </button>
          </div>
        </div>

        <button className="run-btn" onClick={runBroadcast} disabled={running}>
          {running ? 'Broadcasting…' : 'Run broadcast & attack'}
        </button>
      </section>

      {error && <div className="error-box"><strong>Error:</strong> {error}</div>}

      {result && <BroadcastView result={result} originalMessage={message} />}

      <PedagogyBox />
    </div>
  )
}

function BroadcastView({ result, originalMessage }) {
  const attack = result.attack
  const recovered = attack.recovered_message
  const attackSucceeded =
    attack.is_exact_root && recovered !== null && Number(recovered) === Number(originalMessage)
  const allCiphertextsEqual = result.ciphertexts.every(
    (c) => Number(c) === Number(result.ciphertexts[0])
  )

  return (
    <>
      <section className="recipients">
        {result.ciphertexts.map((c, i) => (
          <RecipientPanel
            key={i}
            recipient={RECIPIENTS[i]}
            modulus={result.moduli[i]}
            ciphertext={c}
          />
        ))}
      </section>

      {allCiphertextsEqual && (
        <div className="ciphertext-note">
          ⚠ All three ciphertexts are <em>identical</em> — m³ is smaller than
          every modulus, so each c_i equals m³ exactly (no modular reduction).
          Eve doesn't even need CRT here; cube-rooting any single c_i recovers m.
        </div>
      )}

      <EvePanel
        attack={attack}
        attackSucceeded={attackSucceeded}
        originalMessage={originalMessage}
        usePkcs={result.use_pkcs15}
      />
    </>
  )
}

function RecipientPanel({ recipient, modulus, ciphertext }) {
  return (
    <div className={`recipient ${recipient.color}`}>
      <div className="recipient-name">{recipient.name}</div>
      <div className="recipient-row">
        <span className="row-label">public n</span>
        <code className="value-trunc" title={String(modulus)}>{formatBigNum(modulus)}</code>
      </div>
      <div className="recipient-row">
        <span className="row-label">public e</span>
        <code>3</code>
      </div>
      <div className="recipient-row">
        <span className="row-label">received c</span>
        <code className="value-trunc" title={String(ciphertext)}>{formatBigNum(ciphertext)}</code>
      </div>
      <div className="locked-row">🔒 plaintext sealed (private key needed)</div>
    </div>
  )
}

function EvePanel({ attack, attackSucceeded, originalMessage, usePkcs }) {
  return (
    <section className={`eve-panel ${attackSucceeded ? 'leaked' : 'defended'}`}>
      <div className="eve-header">
        <span className="eve-icon">👁️</span>
        <span className="eve-title">Eve intercepts all three ciphertexts</span>
      </div>

      <div className="eve-steps">
        <Step
          num={1}
          title="Combine via Chinese Remainder Theorem"
          formula="M ≡ c_i (mod n_i)  for i = 1, 2, 3"
          resultLabel="M ="
          resultValue={attack.crt_value}
        />
        <Step
          num={2}
          title="Compute integer cube root"
          formula="m_candidate = ⌊M^(1/3)⌋"
          resultLabel="m_candidate ="
          resultValue={attack.recovered_root}
        />
        <div className="step">
          <div className="step-num">3</div>
          <div className="step-body">
            <div className="step-title">Check: is m_candidate³ exactly equal to M?</div>
            <div className="step-detail">
              <span className={`exact-badge ${attack.is_exact_root ? 'yes' : 'no'}`}>
                {attack.is_exact_root ? '✓ exact cube' : '✗ not a cube'}
              </span>
              <span className="exact-explain">
                {attack.is_exact_root
                  ? 'M is a perfect cube — the cube root is the plaintext.'
                  : 'M is not a perfect cube — the candidate is not the plaintext.'}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className={`verdict-bar ${attackSucceeded ? 'leaked' : 'defended'}`}>
        {attackSucceeded ? (
          <>
            <span className="verdict-icon">✗</span>
            <span className="verdict-text">
              Plaintext leaked. Eve recovered m = <strong>{String(attack.recovered_message)}</strong>{' '}
              with no private key. Textbook RSA is broken under broadcast.
            </span>
          </>
        ) : (
          <>
            <span className="verdict-icon">✓</span>
            <span className="verdict-text">
              Attack defeated.{' '}
              {usePkcs
                ? `PKCS#1 v1.5 randomises each recipient's plaintext, so the three ciphertexts have no common cube.`
                : `Cube root was not exact — recovery failed.`}
              {' '}Original m = <strong>{originalMessage}</strong>; attempted recovery ={' '}
              <strong>{attack.recovered_message ?? 'none'}</strong>.
            </span>
          </>
        )}
      </div>
    </section>
  )
}

function Step({ num, title, formula, resultLabel, resultValue }) {
  return (
    <div className="step">
      <div className="step-num">{num}</div>
      <div className="step-body">
        <div className="step-title">{title}</div>
        <div className="step-detail">
          <code className="value-wrap">{formula}</code>
          <div className="step-result">
            <span className="result-label">{resultLabel}</span>
            <code className="value-trunc" title={String(resultValue)}>
              {formatBigNum(resultValue)}
            </code>
          </div>
        </div>
      </div>
    </div>
  )
}

function PedagogyBox() {
  return (
    <section className="pedagogy">
      <details className="pedagogy-details">
        <summary>Why the attack works (and why padding stops it)</summary>
        <div className="pedagogy-body">
          <p>
            Each recipient i has public key (n_i, e=3) and computes c_i = m³ mod n_i.
            Eve collects c_1, c_2, c_3 from the public network.
          </p>
          <p>
            By the Chinese Remainder Theorem, there is a unique M in [0, n_1·n_2·n_3)
            with M ≡ c_i (mod n_i) for all i. Eve computes this M from public
            information alone — no private keys needed.
          </p>
          <p>
            <strong>Key observation:</strong> if m &lt; min(n_i), then m³ &lt; n_1·n_2·n_3,
            so M = m³ <em>exactly</em> (no modular reduction at any stage). Eve takes
            the integer cube root of M and recovers m.
          </p>
          <p>
            <strong>Why padding fixes this:</strong> with PKCS#1 v1.5, each c_i is
            actually <code>(pad_i ‖ m)³ mod n_i</code> for a <em>different</em> random
            pad per recipient. The three plaintexts are no longer the same value, so
            they share no common cube. CRT still combines the ciphertexts, but the
            resulting M is not a perfect cube and the integer cube root is meaningless.
          </p>
        </div>
      </details>
    </section>
  )
}

function formatBigNum(n) {
  if (n === null || n === undefined) return '∅'
  const num = typeof n === 'number' ? n : Number(n)
  if (!Number.isFinite(num)) return String(n)
  if (Math.abs(num) < 1e10) return num.toString()
  return num.toExponential(3)
}