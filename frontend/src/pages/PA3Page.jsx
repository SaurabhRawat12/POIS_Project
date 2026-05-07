import { useState } from 'react'
import { callEndpoint } from '../api/client'
import './PA3Page.css'

export default function PA3Page() {
  // Encrypt
  const [encK, setEncK] = useState('10110100')
  const [encM, setEncM] = useState('01001101')
  const [encResult, setEncResult] = useState(null)
  const [encLoading, setEncLoading] = useState(false)
  const [encError, setEncError] = useState(null)

  // Decrypt
  const [decK, setDecK] = useState('10110100')
  const [decR, setDecR] = useState('')
  const [decC, setDecC] = useState('')
  const [decResult, setDecResult] = useState(null)
  const [decLoading, setDecLoading] = useState(false)
  const [decError, setDecError] = useState(null)

  // IND-CPA Game
  const [gameK, setGameK] = useState('10110100')
  const [gameM0, setGameM0] = useState('01001101')
  const [gameM1, setGameM1] = useState('11110000')
  const [reuseNonce, setReuseNonce] = useState(false)
  const [gameResult, setGameResult] = useState(null)
  const [gameLoading, setGameLoading] = useState(false)
  const [gameError, setGameError] = useState(null)

  // Nonce-Reuse Attack
  const [attackResult, setAttackResult] = useState(null)
  const [attackLoading, setAttackLoading] = useState(false)
  const [attackError, setAttackError] = useState(null)

  async function runEncrypt() {
    setEncError(null); setEncResult(null); setEncLoading(true)
    try {
      const data = await callEndpoint('/pa3/encrypt', { k: encK, m: encM })
      setEncResult(data)
    } catch (err) { setEncError(err.message) }
    finally { setEncLoading(false) }
  }

  async function runDecrypt() {
    setDecError(null); setDecResult(null); setDecLoading(true)
    try {
      const data = await callEndpoint('/pa3/decrypt', { k: decK, r: decR, c: decC })
      setDecResult(data)
    } catch (err) { setDecError(err.message) }
    finally { setDecLoading(false) }
  }

  async function runGame() {
    setGameError(null); setGameResult(null); setGameLoading(true)
    try {
      const data = await callEndpoint('/pa3/ind-cpa-game', {
        k: gameK, m0: gameM0, m1: gameM1, reuse_nonce: reuseNonce,
      })
      setGameResult(data)
    } catch (err) { setGameError(err.message) }
    finally { setGameLoading(false) }
  }

  async function runAttack() {
    setAttackError(null); setAttackResult(null); setAttackLoading(true)
    try {
      const data = await callEndpoint('/pa3/nonce-reuse-attack', {
        k: gameK, m0: gameM0, m1: gameM1, rounds: 100, reuse_nonce: true,
      })
      setAttackResult(data)
    } catch (err) { setAttackError(err.message) }
    finally { setAttackLoading(false) }
  }

  return (
    <div className="pa3-page">
      <header className="pa3-header">
        <h2>PA#3 — CPA-Secure Encryption</h2>
        <p className="subtitle">
          CPA security means an adversary who can request encryptions of chosen
          messages still cannot distinguish ciphertexts. Nonce reuse breaks this
          guarantee.
        </p>
      </header>

      {/* Encrypt */}
      <section className="pa3-section">
        <h3>Encrypt</h3>
        <p className="section-sub">
          Encrypt a message using the PRF-based CPA scheme.
        </p>

        <div className="pa3-controls">
          <div className="pa3-field">
            <span className="pa3-field-label">Key k (binary, e.g. 10110100)</span>
            <input value={encK} onChange={(e) => setEncK(e.target.value)} placeholder="binary string" />
          </div>
          <div className="pa3-field">
            <span className="pa3-field-label">Message m (binary, same length as key)</span>
            <input value={encM} onChange={(e) => setEncM(e.target.value)} placeholder="binary string" />
          </div>
          <button className="pa3-btn" onClick={runEncrypt} disabled={encLoading}>
            {encLoading ? 'Encrypting…' : 'Encrypt'}
          </button>
        </div>

        {encError && <div className="pa3-error"><strong>Error:</strong> {encError}</div>}
        {encResult && (
          <div className="pa3-result">
            <div className="pa3-result-title">✓ Ciphertext</div>
            <div className="pa3-kv">
              <span className="pa3-kv-label">r (nonce)</span>
              <code>{encResult.result?.r ?? encResult.r}</code>
              <span className="pa3-kv-label">c (ciphertext)</span>
              <code>{encResult.result?.c ?? encResult.c}</code>
            </div>
          </div>
        )}
      </section>

      {/* Decrypt */}
      <section className="pa3-section">
        <h3>Decrypt</h3>
        <p className="section-sub">
          Decrypt a ciphertext (r, c) using the same key.
        </p>

        <div className="pa3-controls">
          <div className="pa3-field">
            <span className="pa3-field-label">Key k (binary)</span>
            <input value={decK} onChange={(e) => setDecK(e.target.value)} placeholder="binary string" />
          </div>
          <div className="pa3-field">
            <span className="pa3-field-label">r (binary, from encrypt output)</span>
            <input value={decR} onChange={(e) => setDecR(e.target.value)} placeholder="from encrypt" />
          </div>
          <div className="pa3-field">
            <span className="pa3-field-label">c (binary, from encrypt output)</span>
            <input value={decC} onChange={(e) => setDecC(e.target.value)} placeholder="from encrypt" />
          </div>
          <button className="pa3-btn" onClick={runDecrypt} disabled={decLoading}>
            {decLoading ? 'Decrypting…' : 'Decrypt'}
          </button>
        </div>

        {decError && <div className="pa3-error"><strong>Error:</strong> {decError}</div>}
        {decResult && (
          <div className="pa3-result">
            <div className="pa3-result-title">✓ Plaintext</div>
            <div className="pa3-kv">
              <span className="pa3-kv-label">plaintext</span>
              <code>{decResult.result?.m ?? decResult.m ?? JSON.stringify(decResult.result)}</code>
            </div>
          </div>
        )}
      </section>

      {/* IND-CPA Game */}
      <section className="pa3-section">
        <h3>IND-CPA Game</h3>
        <p className="section-sub">
          The challenger encrypts either m₀ or m₁ (chosen at random).
          The adversary should not be able to guess which. Toggle nonce reuse to
          see the security break.
        </p>

        <div className="pa3-controls">
          <div className="pa3-field">
            <span className="pa3-field-label">Key k (binary)</span>
            <input value={gameK} onChange={(e) => setGameK(e.target.value)} placeholder="binary string" />
          </div>
          <div className="pa3-field">
            <span className="pa3-field-label">m₀ (binary, same length as m₁)</span>
            <input value={gameM0} onChange={(e) => setGameM0(e.target.value)} placeholder="binary string" />
          </div>
          <div className="pa3-field">
            <span className="pa3-field-label">m₁ (binary, same length as m₀)</span>
            <input value={gameM1} onChange={(e) => setGameM1(e.target.value)} placeholder="binary string" />
          </div>
        </div>

        <div className="pa3-controls">
          <label className="pa3-checkbox-row">
            <input type="checkbox" checked={reuseNonce} onChange={() => setReuseNonce(!reuseNonce)} />
            <span>Reuse nonce (breaks CPA security)</span>
          </label>
          <button className="pa3-btn" onClick={runGame} disabled={gameLoading}>
            {gameLoading ? 'Running…' : 'Run IND-CPA game'}
          </button>
        </div>

        {gameError && <div className="pa3-error"><strong>Error:</strong> {gameError}</div>}
        {gameResult && (
          <div className="pa3-result">
            <div className="pa3-result-title">✓ Game Result</div>
            <details className="pa3-trace">
              <summary>Full result</summary>
              <pre className="pa3-trace-body">{JSON.stringify(gameResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>

      {/* Nonce-Reuse Attack */}
      <section className="pa3-section">
        <h3>Nonce-Reuse Attack Demo</h3>
        <p className="section-sub">
          When the nonce is reused, XOR of two ciphertexts reveals XOR of
          plaintexts — completely breaking CPA security.
        </p>

        <div className="pa3-controls">
          <button className="pa3-btn" onClick={runAttack} disabled={attackLoading}>
            {attackLoading ? 'Attacking…' : 'Run nonce-reuse attack'}
          </button>
        </div>

        {attackError && <div className="pa3-error"><strong>Error:</strong> {attackError}</div>}
        {attackResult && (
          <div className="pa3-result">
            <div className="pa3-result-title">✓ Attack Result</div>
            <details className="pa3-trace">
              <summary>Full result</summary>
              <pre className="pa3-trace-body">{JSON.stringify(attackResult, null, 2)}</pre>
            </details>
          </div>
        )}
      </section>
    </div>
  )
}
