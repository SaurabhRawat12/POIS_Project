import { useState, useEffect } from 'react'
import './MpcPage.css'

const API_BASE = 'http://localhost:8000'

const CIRCUITS = [
  { id: 'millionaire', label: "Millionaire's Problem", op: 'x > y', endpoint: 'millionaire' },
  { id: 'equality',    label: 'Equality test',         op: 'x = y', endpoint: 'equality'    },
  { id: 'addition',    label: 'Secure addition',       op: 'x + y mod 2ⁿ', endpoint: 'addition' },
]

const N_OPTIONS = [4, 6, 8]

export default function MpcPage() {
  const [circuit, setCircuit] = useState('millionaire')
  const [n, setN] = useState(8)
  const [x, setX] = useState(7)
  const [y, setY] = useState(12)

  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [lineage, setLineage] = useState(null)

  // Clamp x, y to [0, 2^n - 1] when n changes
  const maxVal = (1 << n) - 1
  useEffect(() => {
    if (x > maxVal) setX(maxVal)
    if (y > maxVal) setY(maxVal)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [n])

  // Fetch lineage trace once
  useEffect(() => {
    fetch(`${API_BASE}/pa20/lineage`)
      .then(r => r.json())
      .then(d => setLineage(d.result))
      .catch(() => {})
  }, [])

  const currentCircuit = CIRCUITS.find(c => c.id === circuit)

  async function compute() {
    setError(null)
    setResult(null)
    setRunning(true)
    try {
      const res = await fetch(`${API_BASE}/pa20/${currentCircuit.endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x, y, n }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
      const data = await res.json()
      setResult(data.result)
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setRunning(false)
    }
  }

  function pickCircuit(id) {
    setCircuit(id)
    setResult(null)
    setError(null)
  }

  return (
    <div className="mpc-page">
      <header className="mpc-header">
        <h2>PA#20 — 2-Party Secure Computation (GMW)</h2>
        <p className="subtitle">
          Two mutually distrusting parties jointly compute f(x, y) without
          revealing their inputs. Built on Secure AND (PA#19) → Oblivious
          Transfer (PA#18) → ElGamal (PA#16) → Diffie-Hellman (PA#11) →
          Miller-Rabin (PA#13). The protocol transcript is simulatable from
          the output alone — neither party learns anything beyond f(x, y).
        </p>
      </header>

      {/* CIRCUIT PICKER */}
      <section className="circuit-picker">
        <span className="picker-label">Circuit</span>
        {CIRCUITS.map(c => (
          <button
            key={c.id}
            className={`circuit-btn ${circuit === c.id ? 'active' : ''}`}
            onClick={() => pickCircuit(c.id)}
          >
            <span className="circuit-name">{c.label}</span>
            <code className="circuit-op">{c.op}</code>
          </button>
        ))}
      </section>

      {/* TWO-PARTY INPUTS */}
      <section className="parties">
        <PartyPanel
          name="Alice"
          variant="alice"
          symbol="x"
          value={x}
          maxVal={maxVal}
          onChange={setX}
        />
        <PartyPanel
          name="Bob"
          variant="bob"
          symbol="y"
          value={y}
          maxVal={maxVal}
          onChange={setY}
        />
      </section>

      {/* COMPUTE STRIP */}
      <section className="compute-strip">
        <label className="n-picker">
          <span className="n-label">bit width</span>
          <select value={n} onChange={e => setN(parseInt(e.target.value, 10))}>
            {N_OPTIONS.map(opt => (
              <option key={opt} value={opt}>n = {opt} (max value {(1 << opt) - 1})</option>
            ))}
          </select>
        </label>
        <button className="compute-btn" onClick={compute} disabled={running}>
          {running ? 'Evaluating circuit…' : 'Compute securely'}
        </button>
      </section>

      {error && <div className="error-box"><strong>Error:</strong> {error}</div>}

      {result && <ResultPanel result={result} circuit={circuit} />}

      {lineage && <LineagePanel lineage={lineage} />}
    </div>
  )
}

function PartyPanel({ name, variant, symbol, value, maxVal, onChange }) {
  return (
    <div className={`party ${variant}`}>
      <div className="party-name">{name}</div>
      <div className="hidden-badge">🔒 hidden from the other party</div>
      <div className="value-display">
        {symbol} = <code>{value}</code>
      </div>
      <input
        type="range"
        min={0}
        max={maxVal}
        value={value}
        onChange={e => onChange(parseInt(e.target.value, 10))}
        className="value-slider"
      />
      <div className="range-hint">range: 0 — {maxVal}</div>
    </div>
  )
}

function ResultPanel({ result, circuit }) {
  let verdict
  let icon
  let colorClass

  if (circuit === 'millionaire') {
    if (result.result === 1) {
      verdict = `Alice (x = ${result.x}) is richer than Bob`
      icon = '▲'
      colorClass = 'alice-wins'
    } else {
      verdict = `Alice (x = ${result.x}) is NOT richer (Bob wins or they tie)`
      icon = '▽'
      colorClass = 'bob-wins'
    }
  } else if (circuit === 'equality') {
    if (result.result === 1) {
      verdict = `x = y is TRUE  (both values equal ${result.x})`
      icon = '✓'
      colorClass = 'equal'
    } else {
      verdict = `x = y is FALSE  (Alice = ${result.x}, Bob = ${result.y})`
      icon = '✗'
      colorClass = 'not-equal'
    }
  } else {
    verdict = `x + y mod 2^${result.n_bits} = ${result.result}`
    icon = '∑'
    colorClass = 'sum'
  }

  return (
    <section className={`result-panel ${colorClass}`}>
      <div className="verdict-head">
        <span className="verdict-icon">{icon}</span>
        <div className="verdict-text">{verdict}</div>
      </div>

      <div className="stats-grid">
        <Stat label="OT calls" value={result.ot_calls} />
        <Stat label="AND gates" value={result.gate_counts.AND} />
        <Stat label="XOR gates" value={result.gate_counts.XOR} />
        <Stat label="NOT gates" value={result.gate_counts.NOT} />
        <Stat label="elapsed" value={`${(result.wall_clock_seconds * 1000).toFixed(2)} ms`} />
      </div>

      <details className="output-details">
        <summary>
          Raw circuit output ({result.outputs.length} bit{result.outputs.length === 1 ? '' : 's'})
        </summary>
        <pre className="output-bits">[{result.outputs.join(', ')}]</pre>
      </details>

      <p className="security-note">{result.security_note}</p>
    </section>
  )
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  )
}

function LineagePanel({ lineage }) {
  // Extract PAs from the chain in dependency order, not text-appearance order.
  // PA#19 is mentioned last in the source text (as the imported simple-bit
  // interface), but it sits between PA#20 and PA#18 in the actual abstraction
  // stack, so we use a known dependency ordering for the badges.
  const KNOWN_ORDER = ['PA#20', 'PA#19', 'PA#18', 'PA#16', 'PA#11', 'PA#13']
  const present = new Set()
  for (const line of lineage.chain) {
    for (const m of line.matchAll(/PA#(\d+)/g)) {
      present.add(`PA#${m[1]}`)
    }
  }
  const pas = [
    ...KNOWN_ORDER.filter(pa => present.has(pa)),
    ...[...present].filter(pa => !KNOWN_ORDER.includes(pa)),
  ]

  return (
    <section className="lineage-panel">
      <h3>Lineage trace</h3>
      <p className="lineage-sub">
        Every primitive in this stack is implemented from scratch in this project.
        No external crypto libraries — see policy at the bottom.
      </p>

      <div className="lineage-badges">
        {pas.map((pa, i) => (
          <div key={pa} className="badge-item">
            <span className="lineage-badge">{pa}</span>
            {i < pas.length - 1 && <span className="badge-arrow">→</span>}
          </div>
        ))}
      </div>

      <details className="lineage-details">
        <summary>Full call chain</summary>
        <pre className="lineage-chain">{lineage.chain.join('\n')}</pre>
        <p className="policy">{lineage.policy}</p>
      </details>
    </section>
  )
}