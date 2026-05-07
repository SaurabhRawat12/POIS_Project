import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA4Page.css'

const MODES = ['CBC', 'OFB', 'CTR']

export default function PA4Page() {
  const [mode, setMode] = useState('CBC')
  const [key, setKey] = useState('deadbeefdeadbeef')
  const [message, setMessage] = useState('Hello, World!')

  // Encrypt
  const [encResult, setEncResult] = useState(null)
  const [encLoading, setEncLoading] = useState(false)
  const [encError, setEncError] = useState(null)

  // Decrypt
  const [decIv, setDecIv] = useState('')
  const [decCt, setDecCt] = useState('')
  const [decResult, setDecResult] = useState(null)
  const [decLoading, setDecLoading] = useState(false)
  const [decError, setDecError] = useState(null)

  // CBC IV-reuse demo
  const [cbcResult, setCbcResult] = useState(null)
  const [cbcLoading, setCbcLoading] = useState(false)
  const [cbcError, setCbcError] = useState(null)

  // OFB reuse demo
  const [ofbResult, setOfbResult] = useState(null)
  const [ofbLoading, setOfbLoading] = useState(false)
  const [ofbError, setOfbError] = useState(null)

  async function runEncrypt() {
    setEncError(null); setEncResult(null); setEncLoading(true)
    try {
      const data = await callEndpoint('/pa4/encrypt', {
        payload: { mode, key, message },
      })
      setEncResult(data)
    } catch (err) { setEncError(err.message) }
    finally { setEncLoading(false) }
  }

  async function runDecrypt() {
    setDecError(null); setDecResult(null); setDecLoading(true)
    try {
      const data = await callEndpoint('/pa4/decrypt', {
        payload: { mode, key, iv: decIv, ciphertext: decCt },
      })
      setDecResult(data)
    } catch (err) { setDecError(err.message) }
    finally { setDecLoading(false) }
  }

  async function runCbcDemo() {
    setCbcError(null); setCbcResult(null); setCbcLoading(true)
    try {
      const data = await callEndpoint('/pa4/cbc-iv-reuse-demo', {
        payload: { key, message },
      })
      setCbcResult(data)
    } catch (err) { setCbcError(err.message) }
    finally { setCbcLoading(false) }
  }

  async function runOfbDemo() {
    setOfbError(null); setOfbResult(null); setOfbLoading(true)
    try {
      const data = await callEndpoint('/pa4/ofb-reuse-demo', {
        payload: { key, message },
      })
      setOfbResult(data)
    } catch (err) { setOfbError(err.message) }
    finally { setOfbLoading(false) }
  }

  return (
    <div className="pa4-page">
      <header className="pa4-header">
        <h2>PA#4 — Block Cipher Modes of Operation</h2>
        <p className="subtitle">
          CBC, OFB, and CTR modes turn a block cipher into a stream/full-message
          cipher. Each mode has different security properties — especially around
          IV/nonce reuse.
        </p>
      </header>

      {/* Mode selector */}
      <section className="pa4-section">
        <h3>Encrypt / Decrypt</h3>
        <p className="section-sub">Select a mode, then encrypt or decrypt.</p>

        <div className="mode-chips">
          {MODES.map((m) => (
            <button
              key={m}
              className={`mode-chip ${mode === m ? 'active' : ''}`}
              onClick={() => { setMode(m); setEncResult(null); setDecResult(null) }}
            >
              {m}
            </button>
          ))}
        </div>

        <div className="pa4-controls">
          <div className="pa4-field">
            <span className="pa4-field-label">Key (hex)</span>
            <input value={key} onChange={(e) => setKey(e.target.value)} />
          </div>
          <div className="pa4-field">
            <span className="pa4-field-label">Plaintext</span>
            <input value={message} onChange={(e) => setMessage(e.target.value)} />
          </div>
          <button className="pa4-btn" onClick={runEncrypt} disabled={encLoading}>
            {encLoading ? 'Encrypting…' : `Encrypt (${mode})`}
          </button>
        </div>

        {encError && <div className="pa4-error"><strong>Error:</strong> {encError}</div>}
        {encResult && (
          <div className="pa4-result">
            <div className="pa4-result-title">✓ Encrypted ({mode})</div>
            <details className="pa4-trace" open>
              <summary>Result</summary>
              <pre className="pa4-trace-body">{JSON.stringify(encResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Decrypt */}
      <section className="pa4-section">
        <h3>Decrypt</h3>
        <p className="section-sub">
          Provide IV and ciphertext (hex) from a previous encryption.
        </p>

        <div className="pa4-controls">
          <div className="pa4-field">
            <span className="pa4-field-label">IV (hex)</span>
            <input value={decIv} onChange={(e) => setDecIv(e.target.value)} placeholder="from encrypt" />
          </div>
          <div className="pa4-field">
            <span className="pa4-field-label">Ciphertext (hex)</span>
            <input value={decCt} onChange={(e) => setDecCt(e.target.value)} placeholder="from encrypt" />
          </div>
          <button className="pa4-btn" onClick={runDecrypt} disabled={decLoading}>
            {decLoading ? 'Decrypting…' : `Decrypt (${mode})`}
          </button>
        </div>

        {decError && <div className="pa4-error"><strong>Error:</strong> {decError}</div>}
        {decResult && (
          <div className="pa4-result">
            <div className="pa4-result-title">✓ Decrypted</div>
            <details className="pa4-trace" open>
              <summary>Result</summary>
              <pre className="pa4-trace-body">{JSON.stringify(decResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* CBC IV-Reuse Demo */}
      <section className="pa4-section">
        <h3>CBC IV-Reuse Demo</h3>
        <p className="section-sub">
          Shows how reusing the same IV in CBC mode leaks information about
          identical plaintext blocks.
        </p>

        <div className="pa4-controls">
          <button className="pa4-btn pa4-btn-warn" onClick={runCbcDemo} disabled={cbcLoading}>
            {cbcLoading ? 'Running…' : 'Run CBC IV-reuse demo'}
          </button>
        </div>

        {cbcError && <div className="pa4-error"><strong>Error:</strong> {cbcError}</div>}
        {cbcResult && (
          <div className="pa4-result">
            <div className="pa4-result-title">✓ CBC IV-Reuse Result</div>
            <details className="pa4-trace" open>
              <summary>Result</summary>
              <pre className="pa4-trace-body">{JSON.stringify(cbcResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* OFB Key-Stream Reuse Demo */}
      <section className="pa4-section">
        <h3>OFB Key-Stream Reuse Demo</h3>
        <p className="section-sub">
          In OFB, reusing the IV means the same key stream is XOR'd with
          different plaintexts — trivially broken.
        </p>

        <div className="pa4-controls">
          <button className="pa4-btn pa4-btn-warn" onClick={runOfbDemo} disabled={ofbLoading}>
            {ofbLoading ? 'Running…' : 'Run OFB reuse demo'}
          </button>
        </div>

        {ofbError && <div className="pa4-error"><strong>Error:</strong> {ofbError}</div>}
        {ofbResult && (
          <div className="pa4-result">
            <div className="pa4-result-title">✓ OFB Reuse Result</div>
            <details className="pa4-trace" open>
              <summary>Result</summary>
              <pre className="pa4-trace-body">{JSON.stringify(ofbResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
