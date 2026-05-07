import { useState, useEffect } from 'react'
import { callEndpoint, getEndpoint } from '../api/client'
import './PA8Page.css'

export default function PA8Page() {
  // Group params
  const [group, setGroup] = useState(null)
  const [groupLoading, setGroupLoading] = useState(false)
  const [groupError, setGroupError] = useState(null)

  // Hash
  const [hashMsg, setHashMsg] = useState('Hello, DLP Hash!')
  const [hashResult, setHashResult] = useState(null)
  const [hashLoading, setHashLoading] = useState(false)
  const [hashError, setHashError] = useState(null)

  // Compress
  const [compX, setCompX] = useState('42')
  const [compY, setCompY] = useState('99')
  const [compResult, setCompResult] = useState(null)
  const [compLoading, setCompLoading] = useState(false)
  const [compError, setCompError] = useState(null)

  // Collision on compress
  const [colCompResult, setColCompResult] = useState(null)
  const [colCompLoading, setColCompLoading] = useState(false)
  const [colCompError, setColCompError] = useState(null)

  // Collision on hash
  const [colHashResult, setColHashResult] = useState(null)
  const [colHashLoading, setColHashLoading] = useState(false)
  const [colHashError, setColHashError] = useState(null)

  // Proof
  const [proof, setProof] = useState(null)

  useEffect(() => {
    fetchGroup()
    getEndpoint('/pa8/proof').then(setProof).catch(() => {})
  }, [])

  async function fetchGroup() {
    setGroupError(null); setGroupLoading(true)
    try {
      const data = await callEndpoint('/pa8/group-setup', { q_bits: 32 })
      setGroup(data.result || data)
    } catch (err) { setGroupError(err.message) }
    finally { setGroupLoading(false) }
  }

  async function runHash() {
    setHashError(null); setHashResult(null); setHashLoading(true)
    try {
      const body = { message: hashMsg, q_bits: 32 }
      if (group) body.params = { p: group.p, q: group.q, g: group.g, h: group.h }
      const data = await callEndpoint('/pa8/hash', body)
      setHashResult(data)
    } catch (err) { setHashError(err.message) }
    finally { setHashLoading(false) }
  }

  async function runCompress() {
    setCompError(null); setCompResult(null); setCompLoading(true)
    try {
      if (!group) { setCompError('Generate group first'); setCompLoading(false); return }
      const data = await callEndpoint('/pa8/compress', {
        x: parseInt(compX, 10),
        y: parseInt(compY, 10),
        params: { p: group.p, q: group.q, g: group.g, h: group.h },
      })
      setCompResult(data)
    } catch (err) { setCompError(err.message) }
    finally { setCompLoading(false) }
  }

  async function runColComp() {
    setColCompError(null); setColCompResult(null); setColCompLoading(true)
    try {
      const data = await callEndpoint('/pa8/collision-compress', { q_bits: 16 })
      setColCompResult(data)
    } catch (err) { setColCompError(err.message) }
    finally { setColCompLoading(false) }
  }

  async function runColHash() {
    setColHashError(null); setColHashResult(null); setColHashLoading(true)
    try {
      const data = await callEndpoint('/pa8/collision-hash', { q_bits: 16, out_bits: 16 })
      setColHashResult(data)
    } catch (err) { setColHashError(err.message) }
    finally { setColHashLoading(false) }
  }

  return (
    <div className="pa8-page">
      <header className="pa8-header">
        <h2>PA#8 — DLP-Based Collision-Resistant Hash</h2>
        <p className="subtitle">
          The compression function h(x,y) = g<sup>x</sup>·h<sup>y</sup> mod p
          is collision-resistant under the DLP assumption. Finding (x,y) ≠ (x′,y′)
          with h(x,y) = h(x′,y′) would solve the discrete log.
        </p>
      </header>

      {/* Group Setup */}
      <section className="pa8-section">
        <h3>Group Setup</h3>
        <p className="section-sub">
          Generate a safe-prime group for the DLP hash.
        </p>

        <div className="pa8-controls">
          <button className="pa8-btn" onClick={fetchGroup} disabled={groupLoading}>
            {groupLoading ? 'Generating…' : 'Generate group'}
          </button>
        </div>

        {groupError && <div className="pa8-error"><strong>Error:</strong> {groupError}</div>}

        {group && (
          <div className="group-params-strip">
            <span className="gp-label">Group params</span>
            <div className="gp-values">
              <span>p = <code>{group.p}</code></span>
              <span>q = <code>{group.q}</code></span>
              <span>g = <code>{group.g}</code></span>
              <span>h = <code>{group.h}</code></span>
            </div>
          </div>
        )}
      </section>

      {/* Hash */}
      <section className="pa8-section">
        <h3>Hash a Message</h3>
        <p className="section-sub">
          Compute the full DLP-based hash of a string message.
        </p>

        <div className="pa8-controls">
          <div className="pa8-field">
            <span className="pa8-field-label">Message</span>
            <input value={hashMsg} onChange={(e) => setHashMsg(e.target.value)} />
          </div>
          <button className="pa8-btn" onClick={runHash} disabled={hashLoading}>
            {hashLoading ? 'Hashing…' : 'Hash'}
          </button>
        </div>

        {hashError && <div className="pa8-error"><strong>Error:</strong> {hashError}</div>}
        {hashResult && (
          <div className="pa8-result">
            <div className="pa8-result-title">✓ DLP Hash Output</div>
            <details className="pa8-trace" open>
              <summary>Result</summary>
              <pre className="pa8-trace-body">{JSON.stringify(hashResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Compress */}
      <section className="pa8-section">
        <h3>Compression Function</h3>
        <p className="section-sub">
          Evaluate the compression function C(x, y) = g<sup>x</sup>·h<sup>y</sup> mod p.
        </p>

        <div className="pa8-controls">
          <div className="pa8-field">
            <span className="pa8-field-label">x</span>
            <input value={compX} onChange={(e) => setCompX(e.target.value)} />
          </div>
          <div className="pa8-field">
            <span className="pa8-field-label">y</span>
            <input value={compY} onChange={(e) => setCompY(e.target.value)} />
          </div>
          <button className="pa8-btn" onClick={runCompress} disabled={compLoading}>
            {compLoading ? 'Computing…' : 'Compress'}
          </button>
        </div>

        {compError && <div className="pa8-error"><strong>Error:</strong> {compError}</div>}
        {compResult && (
          <div className="pa8-result">
            <div className="pa8-result-title">✓ Compression Output</div>
            <details className="pa8-trace" open>
              <summary>Result</summary>
              <pre className="pa8-trace-body">{JSON.stringify(compResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Collision Compress */}
      <section className="pa8-section">
        <h3>Collision on Compression Function</h3>
        <p className="section-sub">
          Attempt to find a collision on the compression function (toy
          parameters). This should require solving DLP.
        </p>

        <div className="pa8-controls">
          <button className="pa8-btn pa8-btn-warn" onClick={runColComp} disabled={colCompLoading}>
            {colCompLoading ? 'Searching…' : 'Find collision (compress)'}
          </button>
        </div>

        {colCompError && <div className="pa8-error"><strong>Error:</strong> {colCompError}</div>}
        {colCompResult && (
          <div className="pa8-result">
            <div className="pa8-result-title">✓ Compression Collision</div>
            <details className="pa8-trace" open>
              <summary>Result</summary>
              <pre className="pa8-trace-body">{JSON.stringify(colCompResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Collision Hash */}
      <section className="pa8-section">
        <h3>Collision on Full Hash</h3>
        <p className="section-sub">
          Find two distinct messages with the same DLP hash output (toy size).
        </p>

        <div className="pa8-controls">
          <button className="pa8-btn pa8-btn-warn" onClick={runColHash} disabled={colHashLoading}>
            {colHashLoading ? 'Searching…' : 'Find collision (hash)'}
          </button>
        </div>

        {colHashError && <div className="pa8-error"><strong>Error:</strong> {colHashError}</div>}
        {colHashResult && (
          <div className="pa8-result">
            <div className="pa8-result-title">✓ Hash Collision</div>
            <details className="pa8-trace" open>
              <summary>Result</summary>
              <pre className="pa8-trace-body">{JSON.stringify(colHashResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Proof */}
      {proof && (
        <section className="pa8-section">
          <h3>Security Proof</h3>
          <p className="section-sub">
            Formal argument for collision resistance under the DLP assumption.
          </p>
          <div className="pa8-result">
            <details className="pa8-trace">
              <summary>Proof details</summary>
              <pre className="pa8-trace-body">{JSON.stringify(proof, null, 2)}</pre>
            </details>
          </div>
        </section>
      )}
    </div>
  )
}
