import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA5Page.css'

export default function PA5Page() {
  // MAC Tag
  const [macKey, setMacKey] = useState('mysecretkey12345') // 16 chars = 16 bytes
  const [macMsg, setMacMsg] = useState('Hello, World!')
  const [macScheme, setMacScheme] = useState('cbc')
  const [tagResult, setTagResult] = useState(null)
  const [tagLoading, setTagLoading] = useState(false)
  const [tagError, setTagError] = useState(null)

  // MAC Verify
  const [verTag, setVerTag] = useState('')
  const [verResult, setVerResult] = useState(null)
  const [verLoading, setVerLoading] = useState(false)
  const [verError, setVerError] = useState(null)

  // EUF-CMA demo
  const [cmaResult, setCmaResult] = useState(null)
  const [cmaLoading, setCmaLoading] = useState(false)
  const [cmaError, setCmaError] = useState(null)

  // Length-extension demo
  const [leResult, setLeResult] = useState(null)
  const [leLoading, setLeLoading] = useState(false)
  const [leError, setLeError] = useState(null)

  async function runTag() {
    setTagError(null); setTagResult(null); setTagLoading(true)
    try {
      const data = await callEndpoint('/pa5/mac', {
        payload: { key: macKey, message: macMsg, scheme: macScheme },
      })
      setTagResult(data)
    } catch (err) { setTagError(err.message) }
    finally { setTagLoading(false) }
  }

  async function runVerify() {
    setVerError(null); setVerResult(null); setVerLoading(true)
    try {
      const data = await callEndpoint('/pa5/verify', {
        payload: { key: macKey, message: macMsg, tag: verTag, scheme: macScheme },
      })
      setVerResult(data)
    } catch (err) { setVerError(err.message) }
    finally { setVerLoading(false) }
  }

  async function runCma() {
    setCmaError(null); setCmaResult(null); setCmaLoading(true)
    try {
      const data = await callEndpoint('/pa5/euf-cma-demo', { payload: {} })
      setCmaResult(data)
    } catch (err) { setCmaError(err.message) }
    finally { setCmaLoading(false) }
  }

  async function runLe() {
    setLeError(null); setLeResult(null); setLeLoading(true)
    try {
      const data = await callEndpoint('/pa5/length-extension-demo', { payload: {} })
      setLeResult(data)
    } catch (err) { setLeError(err.message) }
    finally { setLeLoading(false) }
  }

  return (
    <div className="pa5-page">
      <header className="pa5-header">
        <h2>PA#5 — Message Authentication Codes</h2>
        <p className="subtitle">
          MACs guarantee message integrity and authenticity. A valid tag proves
          the sender knew the secret key and the message was not tampered with.
        </p>
      </header>

      {/* MAC Tag */}
      <section className="pa5-section">
        <h3>Compute MAC Tag</h3>
        <p className="section-sub">
          Generate a tag for the given message using the selected MAC scheme.
        </p>

        <div className="pa5-controls">
          <div className="pa5-field">
            <span className="pa5-field-label">Key (16 bytes for PRF-MAC; CBC-MAC accepts any length)</span>
            <input value={macKey} onChange={(e) => setMacKey(e.target.value)} placeholder="16-char key for PRF-MAC" />
          </div>
          <div className="pa5-field">
            <span className="pa5-field-label">Message</span>
            <input value={macMsg} onChange={(e) => setMacMsg(e.target.value)} />
          </div>
          <div className="pa5-field" style={{ maxWidth: 120 }}>
            <span className="pa5-field-label">Scheme</span>
            <select value={macScheme} onChange={(e) => setMacScheme(e.target.value)}>
              <option value="prf">PRF</option>
              <option value="cbc">CBC-MAC</option>
            </select>
          </div>
          <button className="pa5-btn" onClick={runTag} disabled={tagLoading}>
            {tagLoading ? 'Computing…' : 'Tag'}
          </button>
        </div>

        {tagError && <div className="pa5-error"><strong>Error:</strong> {tagError}</div>}
        {tagResult && (
          <div className="pa5-result">
            <div className="pa5-result-title">✓ MAC Tag</div>
            <details className="pa5-trace" open>
              <summary>Result</summary>
              <pre className="pa5-trace-body">{JSON.stringify(tagResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* MAC Verify */}
      <section className="pa5-section">
        <h3>Verify MAC Tag</h3>
        <p className="section-sub">
          Check whether a tag is valid for the given key and message.
        </p>

        <div className="pa5-controls">
          <div className="pa5-field">
            <span className="pa5-field-label">Tag to verify</span>
            <input value={verTag} onChange={(e) => setVerTag(e.target.value)} placeholder="paste tag" />
          </div>
          <button className="pa5-btn" onClick={runVerify} disabled={verLoading}>
            {verLoading ? 'Verifying…' : 'Verify'}
          </button>
        </div>

        {verError && <div className="pa5-error"><strong>Error:</strong> {verError}</div>}
        {verResult && (
          <div className="pa5-result">
            <div className="pa5-result-title">Verification</div>
            <details className="pa5-trace" open>
              <summary>Result</summary>
              <pre className="pa5-trace-body">{JSON.stringify(verResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* EUF-CMA Game */}
      <section className="pa5-section">
        <h3>EUF-CMA Game Demo</h3>
        <p className="section-sub">
          The Existential Unforgeability under Chosen Message Attack game:
          can an adversary forge a valid tag on a new message?
        </p>

        <div className="pa5-controls">
          <button className="pa5-btn pa5-btn-warn" onClick={runCma} disabled={cmaLoading}>
            {cmaLoading ? 'Running…' : 'Run EUF-CMA game'}
          </button>
        </div>

        {cmaError && <div className="pa5-error"><strong>Error:</strong> {cmaError}</div>}
        {cmaResult && (
          <div className="pa5-result">
            <div className="pa5-result-title">✓ EUF-CMA Result</div>
            <details className="pa5-trace" open>
              <summary>Result</summary>
              <pre className="pa5-trace-body">{JSON.stringify(cmaResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Length Extension Demo */}
      <section className="pa5-section">
        <h3>Length-Extension Attack Demo</h3>
        <p className="section-sub">
          Demonstrates the length-extension vulnerability in naive MAC
          constructions (Hash(k ∥ m)). HMAC is immune to this.
        </p>

        <div className="pa5-controls">
          <button className="pa5-btn pa5-btn-warn" onClick={runLe} disabled={leLoading}>
            {leLoading ? 'Running…' : 'Run length-extension demo'}
          </button>
        </div>

        {leError && <div className="pa5-error"><strong>Error:</strong> {leError}</div>}
        {leResult && (
          <div className="pa5-result">
            <div className="pa5-result-title">✓ Length-Extension Result</div>
            <details className="pa5-trace" open>
              <summary>Result</summary>
              <pre className="pa5-trace-body">{JSON.stringify(leResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
