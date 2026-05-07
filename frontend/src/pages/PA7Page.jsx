import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA7Page.css'

export default function PA7Page() {
  // Hash
  const [hashMsg, setHashMsg] = useState('Hello, World!')
  const [hashResult, setHashResult] = useState(null)
  const [hashLoading, setHashLoading] = useState(false)
  const [hashError, setHashError] = useState(null)

  // Collision Demo
  const [colResult, setColResult] = useState(null)
  const [colLoading, setColLoading] = useState(false)
  const [colError, setColError] = useState(null)

  async function runHash() {
    setHashError(null); setHashResult(null); setHashLoading(true)
    try {
      const data = await callEndpoint('/pa7/md-hash', {
        payload: { message: hashMsg },
      })
      setHashResult(data)
    } catch (err) { setHashError(err.message) }
    finally { setHashLoading(false) }
  }

  async function runCollision() {
    setColError(null); setColResult(null); setColLoading(true)
    try {
      const data = await callEndpoint('/pa7/collision-demo', { payload: {} })
      setColResult(data)
    } catch (err) { setColError(err.message) }
    finally { setColLoading(false) }
  }

  return (
    <div className="pa7-page">
      <header className="pa7-header">
        <h2>PA#7 — Merkle-Damgård Hash Construction</h2>
        <p className="subtitle">
          The Merkle-Damgård transform converts a fixed-input-length
          compression function into a variable-length hash function. The
          message is padded, split into blocks, and processed sequentially
          through the compression function.
        </p>
      </header>

      {/* MD Hash */}
      <section className="pa7-section">
        <h3>Hash a Message</h3>
        <p className="section-sub">
          Compute the Merkle-Damgård hash of a message using the toy
          compression function.
        </p>

        <div className="pa7-controls">
          <div className="pa7-field">
            <span className="pa7-field-label">Message</span>
            <input
              value={hashMsg}
              onChange={(e) => setHashMsg(e.target.value)}
              placeholder="Enter text to hash"
            />
          </div>
          <button className="pa7-btn" onClick={runHash} disabled={hashLoading}>
            {hashLoading ? 'Hashing…' : 'Hash'}
          </button>
        </div>

        {hashError && <div className="pa7-error"><strong>Error:</strong> {hashError}</div>}
        {hashResult && (
          <div className="pa7-result">
            <div className="pa7-result-title">✓ MD Hash Output</div>
            <details className="pa7-trace" open>
              <summary>Result</summary>
              <pre className="pa7-trace-body">{JSON.stringify(hashResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Collision Demo */}
      <section className="pa7-section">
        <h3>Collision Demo</h3>
        <p className="section-sub">
          Demonstrates finding a collision in the toy Merkle-Damgård hash
          via the birthday bound. Two distinct messages producing the same
          hash digest.
        </p>

        <div className="pa7-controls">
          <button className="pa7-btn pa7-btn-warn" onClick={runCollision} disabled={colLoading}>
            {colLoading ? 'Finding collision…' : 'Run collision demo'}
          </button>
        </div>

        {colError && <div className="pa7-error"><strong>Error:</strong> {colError}</div>}
        {colResult && (
          <div className="pa7-result">
            <div className="pa7-result-title">✓ Collision Found</div>
            <details className="pa7-trace" open>
              <summary>Result</summary>
              <pre className="pa7-trace-body">{JSON.stringify(colResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
