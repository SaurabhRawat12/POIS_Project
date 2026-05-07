import { useState } from 'react'
import './PrimalityPage.css'

const PRESETS = [
  { label: '561 (Carmichael)', n: '561', hint: 'Passes Fermat, fails Miller-Rabin' },
  { label: '1729 (Hardy-Ramanujan)', n: '1729', hint: 'Composite, taxicab number' },
  { label: '7919 (1000th prime)', n: '7919', hint: 'Prime' },
  { label: '15485863', n: '15485863', hint: '1,000,000th prime' },
  { label: '25 (composite)', n: '25', hint: 'Trivial composite' },
  { label: '2 (smallest prime)', n: '2', hint: 'Edge case' },
]

const API_BASE = 'http://localhost:8000'

export default function PrimalityPage() {
  const [nInput, setNInput] = useState('561')
  const [rounds, setRounds] = useState(20)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function handleTest() {
    setError(null)
    setResult(null)

    const trimmed = nInput.trim()
    if (!trimmed) {
      setError('Please enter a number to test.')
      return
    }
    let nBig
    try {
      nBig = BigInt(trimmed)
    } catch {
      setError('Input must be a valid integer.')
      return
    }
    if (nBig < 2n) {
      setError('Number must be ≥ 2.')
      return
    }

    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/pa13/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ n: trimmed, k: rounds, trace: true }),
      })
      if (!res.ok) {
        const body = await res.text()
        throw new Error(`HTTP ${res.status}: ${body || res.statusText}`)
      }
      const data = await res.json()
      setResult(data)
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setLoading(false)
    }
  }

  // Backend shape (from /docs):
  //   { pa_id, status: "COMPOSITE"|"PROBABLY_PRIME", elapsed_ms, rounds_executed, trace, details: {...} }
  //   details: { algorithm, n, k, witness, decomposition: {s,d}, reason, trace, ... }
  const status = result?.status
  const details = result?.details
  const isPrime = status === 'PROBABLY_PRIME' || status === 'PRIME'
  const algorithm = details?.algorithm
  const witness = details?.witness
  const reason = details?.reason
  const decomposition = details?.decomposition
  const elapsedMs = result?.elapsed_ms ?? details?.elapsed_ms
  const roundsExecuted = result?.rounds_executed ?? details?.rounds_executed
  const trace =
    (Array.isArray(result?.trace) && result.trace.length ? result.trace : details?.trace) || []

  return (
    <div className="primality-page">
      <header className="primality-header">
        <h2>PA#13 — Miller-Rabin Primality Tester</h2>
        <p className="subtitle">
          Probabilistic primality test. After k rounds, the false-positive probability is
          at most 4<sup>−k</sup>.
        </p>
      </header>

      <section className="presets">
        <span className="presets-label">Try:</span>
        {PRESETS.map((p) => (
          <button
            key={p.n}
            className="preset-chip"
            onClick={() => { setNInput(p.n); setResult(null); setError(null) }}
            title={p.hint}
          >
            {p.label}
          </button>
        ))}
      </section>

      <section className="controls">
        <label className="control control-n">
          <span className="control-label">Number to test (n)</span>
          <input
            type="text"
            className="n-input"
            value={nInput}
            onChange={(e) => setNInput(e.target.value)}
            placeholder="e.g. 561"
            spellCheck={false}
          />
        </label>

        <label className="control control-k">
          <span className="control-label">Rounds (k = {rounds})</span>
          <input
            type="range"
            min={1}
            max={40}
            value={rounds}
            onChange={(e) => setRounds(parseInt(e.target.value, 10))}
            className="rounds-slider"
          />
          <span className="rounds-hint">
            Error ≤ 4<sup>−{rounds}</sup>
          </span>
        </label>

        <button className="test-btn" onClick={handleTest} disabled={loading}>
          {loading ? 'Testing…' : 'Test'}
        </button>
      </section>

      {error && (
        <div className="error-box">
          <strong>Error:</strong> {error}
        </div>
      )}

      {status && (
        <section className={`verdict ${isPrime ? 'prime' : 'composite'}`}>
          <div className="verdict-headline">
            <span className="verdict-icon">{isPrime ? '✓' : '✗'}</span>
            <span className="verdict-text">{status.replace(/_/g, ' ')}</span>
          </div>

          <div className="verdict-meta">
            n = <code>{nInput}</code> · k = {rounds}
            {roundsExecuted !== undefined && roundsExecuted !== rounds && (
              <> ({roundsExecuted} executed)</>
            )}
            {algorithm && <> · {algorithm}</>}
            {elapsedMs !== undefined && <> · {Number(elapsedMs).toFixed(3)} ms</>}
          </div>

          {decomposition && (
            <div className="verdict-detail">
              <span className="detail-label">decomposition</span>
              <code>n − 1 = 2<sup>{decomposition.s}</sup> × {decomposition.d}</code>
            </div>
          )}

          {!isPrime && witness !== undefined && witness !== null && (
            <div className="verdict-detail">
              <span className="detail-label">witness</span>
              <code>{String(witness)}</code>
              {reason && <span className="detail-reason"> — {reason}</span>}
            </div>
          )}

          {Array.isArray(trace) && trace.length > 0 && (
            <details className="trace">
              <summary>Trace ({trace.length} round{trace.length === 1 ? '' : 's'})</summary>
              <pre className="trace-body">{JSON.stringify(trace, null, 2)}</pre>
            </details>
          )}
        </section>
      )}
    </div>
  )
}