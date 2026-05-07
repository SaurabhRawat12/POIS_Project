import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA1Page.css'

const API_BASE = 'http://localhost:8000'

export default function PA1Page() {
  // OWF state
  const [owfX, setOwfX] = useState('42')
  const [owfResult, setOwfResult] = useState(null)
  const [owfLoading, setOwfLoading] = useState(false)
  const [owfError, setOwfError] = useState(null)

  // OWF Hardness state
  const [hardTrials, setHardTrials] = useState(500)
  const [hardResult, setHardResult] = useState(null)
  const [hardLoading, setHardLoading] = useState(false)
  const [hardError, setHardError] = useState(null)

  // PRG state
  const [prgSeed, setPrgSeed] = useState('12345')
  const [prgBits, setPrgBits] = useState(64)
  const [prgResult, setPrgResult] = useState(null)
  const [prgLoading, setPrgLoading] = useState(false)
  const [prgError, setPrgError] = useState(null)

  // PRG→OWF demo
  const [demoResult, setDemoResult] = useState(null)
  const [demoLoading, setDemoLoading] = useState(false)
  const [demoError, setDemoError] = useState(null)

  async function runOwf() {
    setOwfError(null)
    setOwfResult(null)
    setOwfLoading(true)
    try {
      const data = await callEndpoint('/pa1/owf-evaluate', { x: parseInt(owfX, 10) })
      setOwfResult(data)
    } catch (err) {
      setOwfError(err.message)
    } finally {
      setOwfLoading(false)
    }
  }

  async function runHardness() {
    setHardError(null)
    setHardResult(null)
    setHardLoading(true)
    try {
      const data = await callEndpoint('/pa1/owf-hardness', { trials: hardTrials })
      setHardResult(data)
    } catch (err) {
      setHardError(err.message)
    } finally {
      setHardLoading(false)
    }
  }

  async function runPrg() {
    setPrgError(null)
    setPrgResult(null)
    setPrgLoading(true)
    try {
      const data = await callEndpoint('/pa1/prg-generate', {
        seed: parseInt(prgSeed, 10),
        n_bits: prgBits,
      })
      setPrgResult(data)
    } catch (err) {
      setPrgError(err.message)
    } finally {
      setPrgLoading(false)
    }
  }

  async function runDemo() {
    setDemoError(null)
    setDemoResult(null)
    setDemoLoading(true)
    try {
      const data = await callEndpoint('/pa1/prg-to-owf-demo', {})
      setDemoResult(data)
    } catch (err) {
      setDemoError(err.message)
    } finally {
      setDemoLoading(false)
    }
  }

  return (
    <div className="pa1-page">
      <header className="pa1-header">
        <h2>PA#1 — One-Way Functions &amp; Pseudorandom Generators</h2>
        <p className="subtitle">
          OWFs are easy to compute but hard to invert. PRGs stretch short seeds
          into longer pseudorandom strings. PA#1 demonstrates the DLP-based
          construction and the PRG→OWF reduction.
        </p>
      </header>

      {/* OWF Evaluate */}
      <section className="pa1-section">
        <h3>OWF Evaluate</h3>
        <p className="section-sub">
          Compute f(x) = g<sup>x</sup> mod p. Given y = f(x), inverting to
          find x is the Discrete Log Problem.
        </p>

        <div className="pa1-controls">
          <div className="pa1-field">
            <span className="pa1-field-label">Input x</span>
            <input
              type="text"
              value={owfX}
              onChange={(e) => setOwfX(e.target.value)}
              placeholder="e.g. 42"
            />
          </div>
          <button className="pa1-btn" onClick={runOwf} disabled={owfLoading}>
            {owfLoading ? 'Computing…' : 'Evaluate'}
          </button>
        </div>

        {owfError && <div className="pa1-error"><strong>Error:</strong> {owfError}</div>}

        {owfResult && (
          <div className="pa1-result">
            <div className="pa1-result-title">✓ OWF Output</div>
            <div className="pa1-kv">
              <span className="pa1-kv-label">x</span>
              <code>{owfResult.result?.x ?? owfResult.x}</code>
              <span className="pa1-kv-label">f(x)</span>
              <code>{owfResult.result?.fx ?? owfResult.fx}</code>
              {(owfResult.result?.method || owfResult.method) && (
                <>
                  <span className="pa1-kv-label">method</span>
                  <code>{owfResult.result?.method ?? owfResult.method}</code>
                </>
              )}
            </div>
            {owfResult.trace && (
              <details className="pa1-trace">
                <summary>Trace</summary>
                <pre className="pa1-trace-body">{JSON.stringify(owfResult.trace, null, 2)}</pre>
              </details>
            )}
          </div>
        )}
      </section>

      {/* OWF Hardness */}
      <section className="pa1-section">
        <h3>OWF Hardness Test</h3>
        <p className="section-sub">
          Attempt to brute-force invert f(x) over random inputs.
          Success rate should be negligible.
        </p>

        <div className="pa1-controls">
          <div className="pa1-field">
            <span className="pa1-field-label">Trials</span>
            <input
              type="number"
              value={hardTrials}
              onChange={(e) => setHardTrials(parseInt(e.target.value, 10) || 500)}
              min={10}
              max={10000}
            />
          </div>
          <button className="pa1-btn" onClick={runHardness} disabled={hardLoading}>
            {hardLoading ? 'Testing…' : 'Run hardness test'}
          </button>
        </div>

        {hardError && <div className="pa1-error"><strong>Error:</strong> {hardError}</div>}

        {hardResult && (
          <div className={`hardness-verdict ${hardResult.result?.hard || hardResult.hard ? 'pass' : 'fail'}`}>
            <div className="hardness-title">
              {hardResult.result?.hard || hardResult.hard ? '✓ OWF appears hard' : '✗ OWF easily inverted'}
            </div>
            <div className="pa1-kv">
              <span className="pa1-kv-label">trials</span>
              <code>{hardResult.result?.trials ?? hardResult.trials}</code>
              <span className="pa1-kv-label">inversions</span>
              <code>{hardResult.result?.inversions ?? hardResult.inversions}</code>
              <span className="pa1-kv-label">rate</span>
              <code>{((hardResult.result?.inversion_rate ?? hardResult.inversion_rate) * 100).toFixed(2)}%</code>
            </div>
          </div>
        )}
      </section>

      {/* PRG Generate */}
      <section className="pa1-section">
        <h3>PRG — Generate Pseudorandom Bits</h3>
        <p className="section-sub">
          Expand a short seed into n pseudorandom bits using the DLP-based PRG.
        </p>

        <div className="pa1-controls">
          <div className="pa1-field">
            <span className="pa1-field-label">Seed</span>
            <input
              type="text"
              value={prgSeed}
              onChange={(e) => setPrgSeed(e.target.value)}
              placeholder="e.g. 12345"
            />
          </div>
          <div className="pa1-field">
            <span className="pa1-field-label">Output bits</span>
            <input
              type="number"
              value={prgBits}
              onChange={(e) => setPrgBits(parseInt(e.target.value, 10) || 64)}
              min={8}
              max={256}
            />
          </div>
          <button className="pa1-btn" onClick={runPrg} disabled={prgLoading}>
            {prgLoading ? 'Generating…' : 'Generate'}
          </button>
        </div>

        {prgError && <div className="pa1-error"><strong>Error:</strong> {prgError}</div>}

        {prgResult && (
          <div className="pa1-result">
            <div className="pa1-result-title">✓ PRG Output</div>
            <div className="pa1-kv">
              <span className="pa1-kv-label">seed</span>
              <code>{prgResult.result?.seed ?? prgResult.seed}</code>
              <span className="pa1-kv-label">bits</span>
              <code>{prgResult.result?.bits ?? prgResult.bits ?? prgResult.result?.output}</code>
              {(prgResult.result?.expansion ?? prgResult.expansion) && (
                <>
                  <span className="pa1-kv-label">expansion</span>
                  <code>{prgResult.result?.expansion ?? prgResult.expansion}</code>
                </>
              )}
            </div>
          </div>
        )}
      </section>

      {/* PRG → OWF Demo */}
      <section className="pa1-section">
        <h3>PRG → OWF Reduction Demo</h3>
        <p className="section-sub">
          Shows that a secure PRG implies a one-way function. If you can invert
          the OWF built from the PRG, you can also predict the PRG.
        </p>

        <div className="pa1-controls">
          <button className="pa1-btn" onClick={runDemo} disabled={demoLoading}>
            {demoLoading ? 'Running…' : 'Run demo'}
          </button>
        </div>

        {demoError && <div className="pa1-error"><strong>Error:</strong> {demoError}</div>}

        {demoResult && (
          <div className="pa1-result">
            <div className="pa1-result-title">✓ Reduction Result</div>
            <details className="pa1-trace">
              <summary>Full result</summary>
              <pre className="pa1-trace-body">{JSON.stringify(demoResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
