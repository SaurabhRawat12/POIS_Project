import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA2Page.css'

export default function PA2Page() {
  // PRF Eval
  const [prfK, setPrfK] = useState('10110100')
  const [prfX, setPrfX] = useState('01101001')
  const [evalResult, setEvalResult] = useState(null)
  const [evalLoading, setEvalLoading] = useState(false)
  const [evalError, setEvalError] = useState(null)

  // GGM Trace
  const [traceResult, setTraceResult] = useState(null)
  const [traceLoading, setTraceLoading] = useState(false)
  const [traceError, setTraceError] = useState(null)

  // PRF → PRG
  const [prgS, setPrgS] = useState('10110100')
  const [prgResult, setPrgResult] = useState(null)
  const [prgLoading, setPrgLoading] = useState(false)
  const [prgError, setPrgError] = useState(null)

  // Distinguishing Game
  const [distQ, setDistQ] = useState(100)
  const [distResult, setDistResult] = useState(null)
  const [distLoading, setDistLoading] = useState(false)
  const [distError, setDistError] = useState(null)

  async function runEval() {
    setEvalError(null); setEvalResult(null); setEvalLoading(true)
    try {
      const data = await callEndpoint('/pa2/eval', { k: prfK, x: prfX })
      setEvalResult(data)
    } catch (err) { setEvalError(err.message) }
    finally { setEvalLoading(false) }
  }

  async function runTrace() {
    setTraceError(null); setTraceResult(null); setTraceLoading(true)
    try {
      const data = await callEndpoint('/pa2/trace', { k: prfK, x: prfX })
      setTraceResult(data)
    } catch (err) { setTraceError(err.message) }
    finally { setTraceLoading(false) }
  }

  async function runPrg() {
    setPrgError(null); setPrgResult(null); setPrgLoading(true)
    try {
      const data = await callEndpoint('/pa2/prf-to-prg', { s: prgS })
      setPrgResult(data)
    } catch (err) { setPrgError(err.message) }
    finally { setPrgLoading(false) }
  }

  async function runDistinguish() {
    setDistError(null); setDistResult(null); setDistLoading(true)
    try {
      const data = await callEndpoint('/pa2/distinguish-game', { k: prfK, q: distQ })
      setDistResult(data)
    } catch (err) { setDistError(err.message) }
    finally { setDistLoading(false) }
  }

  return (
    <div className="pa2-page">
      <header className="pa2-header">
        <h2>PA#2 — Pseudorandom Functions (GGM Tree)</h2>
        <p className="subtitle">
          A PRF is indistinguishable from a truly random function. The GGM
          construction builds a PRF from a PRG by walking a binary tree keyed
          by the input bits.
        </p>
      </header>

      {/* PRF Eval */}
      <section className="pa2-section">
        <h3>PRF Evaluate</h3>
        <p className="section-sub">
          Compute PRF<sub>k</sub>(x) using the GGM tree construction.
          Key and input are hex strings.
        </p>

        <div className="pa2-controls">
          <div className="pa2-field">
            <span className="pa2-field-label">Key k (binary, e.g. 10110100)</span>
            <input value={prfK} onChange={(e) => setPrfK(e.target.value)} placeholder="binary string, e.g. 10110100" />
          </div>
          <div className="pa2-field">
            <span className="pa2-field-label">Input x (binary, same length as k)</span>
            <input value={prfX} onChange={(e) => setPrfX(e.target.value)} placeholder="binary string, same length as k" />
          </div>
          <button className="pa2-btn" onClick={runEval} disabled={evalLoading}>
            {evalLoading ? 'Computing…' : 'Evaluate'}
          </button>
        </div>

        {evalError && <div className="pa2-error"><strong>Error:</strong> {evalError}</div>}
        {evalResult && (
          <div className="pa2-result">
            <div className="pa2-result-title">✓ PRF Output</div>
            <div className="pa2-kv">
              <span className="pa2-kv-label">key</span>
              <code>{prfK}</code>
              <span className="pa2-kv-label">input</span>
              <code>{prfX}</code>
              <span className="pa2-kv-label">output</span>
              <code>{evalResult.result?.output ?? evalResult.output ?? JSON.stringify(evalResult.result)}</code>
            </div>
          </div>
        )}
      </section>

      {/* GGM Trace */}
      <section className="pa2-section">
        <h3>GGM Tree Trace</h3>
        <p className="section-sub">
          Visualize how each bit of input x selects the left or right child,
          walking the tree from root to leaf.
        </p>

        <div className="pa2-controls">
          <button className="pa2-btn" onClick={runTrace} disabled={traceLoading}>
            {traceLoading ? 'Tracing…' : 'Trace tree path'}
          </button>
        </div>

        {traceError && <div className="pa2-error"><strong>Error:</strong> {traceError}</div>}
        {traceResult && (
          <div className="pa2-result">
            <div className="pa2-result-title">✓ GGM Trace</div>
            {Array.isArray(traceResult.result?.trace || traceResult.trace) ? (
              <div className="ggm-tree">
                {(traceResult.result?.trace || traceResult.trace).map((node, i) => (
                  <div className="ggm-node" key={i}>
                    <span className="ggm-depth">d{i}</span>
                    <span className="ggm-value"><code>{typeof node === 'object' ? JSON.stringify(node) : String(node)}</code></span>
                  </div>
                ))}
              </div>
            ) : (
              <details className="pa2-trace">
                <summary>Full result</summary>
                <pre className="pa2-trace-body">{JSON.stringify(traceResult, null, 2)}</pre>
              </details>
            )}
          </div>
        )}
      </section>

      {/* PRF → PRG */}
      <section className="pa2-section">
        <h3>PRF → PRG Reduction</h3>
        <p className="section-sub">
          Derive a PRG from a PRF by evaluating F<sub>k</sub> on sequential inputs.
        </p>

        <div className="pa2-controls">
          <div className="pa2-field">
            <span className="pa2-field-label">Seed s (binary, e.g. 10110100)</span>
            <input value={prgS} onChange={(e) => setPrgS(e.target.value)} placeholder="binary string, e.g. 10110100" />
          </div>
          <button className="pa2-btn" onClick={runPrg} disabled={prgLoading}>
            {prgLoading ? 'Computing…' : 'Generate'}
          </button>
        </div>

        {prgError && <div className="pa2-error"><strong>Error:</strong> {prgError}</div>}
        {prgResult && (
          <div className="pa2-result">
            <div className="pa2-result-title">✓ PRG from PRF</div>
            <details className="pa2-trace">
              <summary>Full result</summary>
              <pre className="pa2-trace-body">{JSON.stringify(prgResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Distinguishing Game */}
      <section className="pa2-section">
        <h3>PRF Distinguishing Game</h3>
        <p className="section-sub">
          Run a distinguishing experiment: can an adversary tell the PRF apart
          from a truly random function? Advantage should be negligible.
        </p>

        <div className="pa2-controls">
          <div className="pa2-field">
            <span className="pa2-field-label">Queries (q)</span>
            <input
              type="number"
              value={distQ}
              onChange={(e) => setDistQ(parseInt(e.target.value, 10) || 100)}
              min={10}
              max={1000}
            />
          </div>
          <button className="pa2-btn" onClick={runDistinguish} disabled={distLoading}>
            {distLoading ? 'Running…' : 'Run game'}
          </button>
        </div>

        {distError && <div className="pa2-error"><strong>Error:</strong> {distError}</div>}
        {distResult && (
          <div className="pa2-result">
            <div className="pa2-result-title">✓ Distinguishing Game Result</div>
            <details className="pa2-trace">
              <summary>Full result</summary>
              <pre className="pa2-trace-body">{JSON.stringify(distResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
