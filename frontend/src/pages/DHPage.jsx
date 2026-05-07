import { useState, useEffect } from 'react'
import './DHPage.css'

const API_BASE = 'http://localhost:8000'

export default function DHPage() {
  const [group, setGroup] = useState(null)
  const [groupLoading, setGroupLoading] = useState(false)
  const [mitm, setMitm] = useState(false)
  const [result, setResult] = useState(null)
  const [resultMode, setResultMode] = useState(null) // 'normal' | 'mitm'
  const [exchanging, setExchanging] = useState(false)
  const [error, setError] = useState(null)

  async function fetchGroup() {
    setError(null)
    setGroupLoading(true)
    setResult(null)
    try {
      const res = await fetch(`${API_BASE}/pa11/group`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q_bits: 24, k: 20 }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      const r = data.result
      setGroup({ p: r.p, q: r.q, g: r.g, source: r.source })
    } catch (err) {
      setError(`Group generation failed: ${err.message}`)
    } finally {
      setGroupLoading(false)
    }
  }

  useEffect(() => {
    fetchGroup()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function runExchange() {
    if (!group) return
    setError(null)
    setExchanging(true)
    setResult(null)
    try {
      const endpoint = mitm ? '/pa11/mitm-demo' : '/pa11/exchange'
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ params: { p: group.p, q: group.q, g: group.g } }),
      })
      if (!res.ok) {
        const body = await res.text()
        throw new Error(`HTTP ${res.status}: ${body || res.statusText}`)
      }
      const data = await res.json()
      setResult(data.result)
      setResultMode(mitm ? 'mitm' : 'normal')
    } catch (err) {
      setError(`Exchange failed: ${err.message}`)
    } finally {
      setExchanging(false)
    }
  }

  function toggleMitm() {
    setMitm(!mitm)
    setResult(null)
  }

  return (
    <div className="dh-page">
      <header className="dh-header">
        <h2>PA#11 — Diffie-Hellman Key Exchange</h2>
        <p className="subtitle">
          Two parties establish a shared secret over an open channel using only modular
          exponentiation. Without authentication, the protocol is broken by any active
          attacker in the middle.
        </p>
      </header>

      <section className="group-strip">
        <div className="group-label">Group params · toy 24-bit safe prime</div>
        {group ? (
          <div className="group-values">
            <span>p = <code>{group.p}</code></span>
            <span>q = <code>{group.q}</code></span>
            <span>g = <code>{group.g}</code></span>
          </div>
        ) : (
          <div className="group-values muted">
            {groupLoading ? 'Generating…' : 'No group yet'}
          </div>
        )}
        <button className="regen-btn" onClick={fetchGroup} disabled={groupLoading}>
          {groupLoading ? '…' : 'Regenerate'}
        </button>
      </section>

      <section className="controls-strip">
        <label className="mitm-toggle">
          <input type="checkbox" checked={mitm} onChange={toggleMitm} />
          <span className="toggle-label">Enable Eve (MITM attack)</span>
        </label>
        <button
          className="run-btn"
          onClick={runExchange}
          disabled={!group || exchanging}
        >
          {exchanging ? 'Running…' : 'Run exchange'}
        </button>
      </section>

      {error && (
        <div className="error-box"><strong>Error:</strong> {error}</div>
      )}

      {result && resultMode === 'normal' && <NormalView result={result} />}
      {result && resultMode === 'mitm' && <MitmView result={result} />}
    </div>
  )
}

function NormalView({ result }) {
  const match = result.shared_secret_match
  return (
    <section className="exchange-view">
      <div className="parties two-cols">
        <Party
          name="Alice"
          publicLabel="A = gᵃ mod p"
          publicValue={result.alice_public}
          secretValue={result.alice_secret}
          ok={match}
        />
        <Party
          name="Bob"
          publicLabel="B = gᵇ mod p"
          publicValue={result.bob_public}
          secretValue={result.bob_secret}
          ok={match}
        />
      </div>
      <div className={`verdict-bar ${match ? 'ok' : 'fail'}`}>
        {match ? '✓' : '✗'}{' '}
        {match
          ? 'Shared secrets match — channel established successfully.'
          : 'Shared secrets diverge unexpectedly.'}
      </div>
    </section>
  )
}

function MitmView({ result }) {
  const success = result.mitm_success
  return (
    <section className="exchange-view">
      <div className="parties three-cols">
        <Party
          name="Alice"
          publicLabel="A = gᵃ mod p"
          publicValue={result.alice_public}
          secretValue={result.alice_secret_with_eve}
          secretLabel='K with "Bob"'
          warn
        />
        <Eve
          injected={result.eve_injected_public}
          secretA={result.eve_secret_with_alice}
          secretB={result.eve_secret_with_bob}
        />
        <Party
          name="Bob"
          publicLabel="B = gᵇ mod p"
          publicValue={result.bob_public}
          secretValue={result.bob_secret_with_eve}
          secretLabel='K with "Alice"'
          warn
        />
      </div>
      <div className={`verdict-bar ${success ? 'fail' : 'ok'}`}>
        {success ? '✗' : '✓'}{' '}
        {success
          ? 'Alice and Bob each share a different secret — both with Eve. Eve transparently relays and reads everything; neither party detects the attack.'
          : 'MITM unexpectedly failed.'}
      </div>
    </section>
  )
}

function Party({
  name, publicLabel, publicValue, secretValue,
  secretLabel = 'Shared secret K', warn = false, ok = false,
}) {
  return (
    <div className={`party ${warn ? 'warn' : ok ? 'ok' : ''}`}>
      <h3>{name}</h3>
      <div className="party-row">
        <span className="row-label">{publicLabel}</span>
        <code>{publicValue}</code>
      </div>
      <div className="party-row secret">
        <span className="row-label">{secretLabel}</span>
        <code>{secretValue}</code>
      </div>
    </div>
  )
}

function Eve({ injected, secretA, secretB }) {
  return (
    <div className="party eve">
      <h3>Eve <span className="eve-badge">MITM</span></h3>
      <div className="party-row">
        <span className="row-label">E = gᵉ (injected)</span>
        <code>{injected}</code>
      </div>
      <div className="party-row secret">
        <span className="row-label">K with Alice</span>
        <code>{secretA}</code>
      </div>
      <div className="party-row secret">
        <span className="row-label">K with Bob</span>
        <code>{secretB}</code>
      </div>
    </div>
  )
}