import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA6Page.css'

export default function PA6Page() {
  // Encrypt
  const [encKe, setEncKe] = useState('encryptionkey123')
  const [encKm, setEncKm] = useState('mackey1234567890')
  const [encMsg, setEncMsg] = useState('Secret message')
  const [encResult, setEncResult] = useState(null)
  const [encLoading, setEncLoading] = useState(false)
  const [encError, setEncError] = useState(null)

  // Decrypt
  const [decPayload, setDecPayload] = useState('')
  const [decResult, setDecResult] = useState(null)
  const [decLoading, setDecLoading] = useState(false)
  const [decError, setDecError] = useState(null)

  // CCA Game
  const [ccaResult, setCcaResult] = useState(null)
  const [ccaLoading, setCcaLoading] = useState(false)
  const [ccaError, setCcaError] = useState(null)

  // Malleability Demo
  const [malResult, setMalResult] = useState(null)
  const [malLoading, setMalLoading] = useState(false)
  const [malError, setMalError] = useState(null)

  // Key Separation Demo
  const [ksResult, setKsResult] = useState(null)
  const [ksLoading, setKsLoading] = useState(false)
  const [ksError, setKsError] = useState(null)

  async function runEncrypt() {
    setEncError(null); setEncResult(null); setEncLoading(true)
    try {
      const data = await callEndpoint('/pa6/cca-encrypt', {
        payload: { key_enc: encKe, key_mac: encKm, message: encMsg },
      })
      setEncResult(data)
    } catch (err) { setEncError(err.message) }
    finally { setEncLoading(false) }
  }

  async function runDecrypt() {
    setDecError(null); setDecResult(null); setDecLoading(true)
    try {
      let payload
      try { payload = JSON.parse(decPayload) } catch { payload = { ciphertext: decPayload } }
      const data = await callEndpoint('/pa6/cca-decrypt', {
        payload: { key_enc: encKe, key_mac: encKm, ...payload },
      })
      setDecResult(data)
    } catch (err) { setDecError(err.message) }
    finally { setDecLoading(false) }
  }

  async function runCca() {
    setCcaError(null); setCcaResult(null); setCcaLoading(true)
    try {
      const data = await callEndpoint('/pa6/cca-game', { payload: {} })
      setCcaResult(data)
    } catch (err) { setCcaError(err.message) }
    finally { setCcaLoading(false) }
  }

  async function runMalleability() {
    setMalError(null); setMalResult(null); setMalLoading(true)
    try {
      const data = await callEndpoint('/pa6/malleability-demo', { payload: {} })
      setMalResult(data)
    } catch (err) { setMalError(err.message) }
    finally { setMalLoading(false) }
  }

  async function runKeySeparation() {
    setKsError(null); setKsResult(null); setKsLoading(true)
    try {
      const data = await callEndpoint('/pa6/key-separation-demo', { payload: {} })
      setKsResult(data)
    } catch (err) { setKsError(err.message) }
    finally { setKsLoading(false) }
  }

  return (
    <div className="pa6-page">
      <header className="pa6-header">
        <h2>PA#6 — CCA-Secure Symmetric Encryption</h2>
        <p className="subtitle">
          Encrypt-then-MAC achieves CCA security by authenticating the
          ciphertext. Verify-before-decrypt prevents chosen-ciphertext attacks.
          Requires separate encryption and MAC keys (PA#3 + PA#5).
        </p>
      </header>

      {/* Encrypt */}
      <section className="pa6-section">
        <h3>CCA Encrypt</h3>
        <p className="section-sub">
          Encrypt a message using the Encrypt-then-MAC construction.
        </p>

        <div className="pa6-controls">
          <div className="pa6-field">
            <span className="pa6-field-label">Encryption Key</span>
            <input value={encKe} onChange={(e) => setEncKe(e.target.value)} />
          </div>
          <div className="pa6-field">
            <span className="pa6-field-label">MAC Key</span>
            <input value={encKm} onChange={(e) => setEncKm(e.target.value)} />
          </div>
          <div className="pa6-field">
            <span className="pa6-field-label">Message</span>
            <input value={encMsg} onChange={(e) => setEncMsg(e.target.value)} />
          </div>
          <button className="pa6-btn" onClick={runEncrypt} disabled={encLoading}>
            {encLoading ? 'Encrypting…' : 'Encrypt'}
          </button>
        </div>

        {encError && <div className="pa6-error"><strong>Error:</strong> {encError}</div>}
        {encResult && (
          <div className="pa6-result">
            <div className="pa6-result-title">✓ CCA Ciphertext</div>
            <details className="pa6-trace" open>
              <summary>Result</summary>
              <pre className="pa6-trace-body">{JSON.stringify(encResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Decrypt */}
      <section className="pa6-section">
        <h3>CCA Decrypt</h3>
        <p className="section-sub">
          Paste the encrypted payload JSON. Verifies MAC before decrypting.
        </p>

        <div className="pa6-controls">
          <div className="pa6-field">
            <span className="pa6-field-label">Encrypted payload (JSON)</span>
            <input value={decPayload} onChange={(e) => setDecPayload(e.target.value)} placeholder='{"ciphertext":"...", "tag":"...", ...}' />
          </div>
          <button className="pa6-btn" onClick={runDecrypt} disabled={decLoading}>
            {decLoading ? 'Decrypting…' : 'Decrypt'}
          </button>
        </div>

        {decError && <div className="pa6-error"><strong>Error:</strong> {decError}</div>}
        {decResult && (
          <div className="pa6-result">
            <div className="pa6-result-title">✓ Decrypted</div>
            <details className="pa6-trace" open>
              <summary>Result</summary>
              <pre className="pa6-trace-body">{JSON.stringify(decResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* CCA Game */}
      <section className="pa6-section">
        <h3>CCA Security Game</h3>
        <p className="section-sub">
          The IND-CCA2 game with a decryption oracle. Encrypt-then-MAC should
          remain secure even when the adversary can decrypt chosen ciphertexts.
        </p>

        <div className="pa6-controls">
          <button className="pa6-btn" onClick={runCca} disabled={ccaLoading}>
            {ccaLoading ? 'Running…' : 'Run CCA game'}
          </button>
        </div>

        {ccaError && <div className="pa6-error"><strong>Error:</strong> {ccaError}</div>}
        {ccaResult && (
          <div className="pa6-result">
            <div className="pa6-result-title">✓ CCA Game Result</div>
            <details className="pa6-trace" open>
              <summary>Result</summary>
              <pre className="pa6-trace-body">{JSON.stringify(ccaResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Malleability Demo */}
      <section className="pa6-section">
        <h3>Malleability Demo</h3>
        <p className="section-sub">
          Attempt to modify the ciphertext. The MAC check should detect and
          reject all tampered ciphertexts.
        </p>

        <div className="pa6-controls">
          <button className="pa6-btn pa6-btn-warn" onClick={runMalleability} disabled={malLoading}>
            {malLoading ? 'Running…' : 'Run malleability demo'}
          </button>
        </div>

        {malError && <div className="pa6-error"><strong>Error:</strong> {malError}</div>}
        {malResult && (
          <div className="pa6-result">
            <div className="pa6-result-title">✓ Malleability Result</div>
            <details className="pa6-trace" open>
              <summary>Result</summary>
              <pre className="pa6-trace-body">{JSON.stringify(malResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Key Separation Demo */}
      <section className="pa6-section">
        <h3>Key Separation Demo</h3>
        <p className="section-sub">
          Shows why encryption and MAC keys must be independent — reusing the
          same key for both can lead to subtle attacks.
        </p>

        <div className="pa6-controls">
          <button className="pa6-btn pa6-btn-warn" onClick={runKeySeparation} disabled={ksLoading}>
            {ksLoading ? 'Running…' : 'Run key-separation demo'}
          </button>
        </div>

        {ksError && <div className="pa6-error"><strong>Error:</strong> {ksError}</div>}
        {ksResult && (
          <div className="pa6-result">
            <div className="pa6-result-title">✓ Key Separation Result</div>
            <details className="pa6-trace" open>
              <summary>Result</summary>
              <pre className="pa6-trace-body">{JSON.stringify(ksResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
