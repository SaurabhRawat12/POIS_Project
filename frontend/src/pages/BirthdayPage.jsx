import { useState, useEffect } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
} from 'recharts'
import './BirthdayPage.css'

const API_BASE = 'http://localhost:8000'
const N_VALUES = [8, 10, 12, 14, 16]
const N_COLORS = {
  8: '#5e9eff',
  10: '#5fdc7a',
  12: '#ffd66e',
  14: '#ff9f7a',
  16: '#ff7a8a',
}

export default function BirthdayPage() {
  // Section 1 state
  const [n, setN] = useState(12)
  const [attacking, setAttacking] = useState(false)
  const [attackResult, setAttackResult] = useState(null)
  const [attackError, setAttackError] = useState(null)

  // Section 2 state
  const [trials, setTrials] = useState(30)
  const [running, setRunning] = useState(false)
  const [curveData, setCurveData] = useState(null)
  const [curveError, setCurveError] = useState(null)

  // Section 3 state
  const [context, setContext] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE}/pa9/md5-sha1-context`)
      .then((r) => r.json())
      .then((d) => setContext(d.result))
      .catch(() => {})
  }, [])

  async function runAttack() {
    setAttackError(null)
    setAttackResult(null)
    setAttacking(true)
    try {
      const res = await fetch(`${API_BASE}/pa9/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ n }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
      const data = await res.json()
      setAttackResult(data.result)
    } catch (err) {
      setAttackError(err.message || String(err))
    } finally {
      setAttacking(false)
    }
  }

  async function runCurve() {
    setCurveError(null)
    setCurveData(null)
    setRunning(true)
    try {
      const res = await fetch(`${API_BASE}/pa9/curve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ n_values: N_VALUES, trials }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
      const data = await res.json()
      setCurveData(data.result)
    } catch (err) {
      setCurveError(err.message || String(err))
    } finally {
      setRunning(false)
    }
  }

  const chartData = curveData ? mergeCurves(curveData.theoretical_curves) : null

  return (
    <div className="birthday-page">
      <header className="bd-header">
        <h2>PA#9 — Birthday Attack</h2>
        <p className="subtitle">
          Finding collisions in any n-bit hash takes O(2<sup>n/2</sup>) evaluations.
          This is a hard floor — no engineering can do better. Below: empirical
          confirmation on toy hashes.
        </p>
      </header>

      {/* SECTION 1 */}
      <section className="bd-section">
        <h3>Single attack</h3>
        <p className="section-sub">
          Pick an output size, run the naive (dict-based) birthday attack on a
          toy hash. Expect a collision near 2<sup>n/2</sup> evaluations.
        </p>

        <div className="controls-row">
          <label className="ctrl">
            <span className="ctrl-label">Output bits (n = {n})</span>
            <input
              type="range"
              min={8}
              max={16}
              step={2}
              value={n}
              onChange={(e) => setN(parseInt(e.target.value, 10))}
            />
            <span className="ctrl-hint">
              Expected: 2<sup>{n / 2}</sup> = {Math.pow(2, n / 2)} evaluations
            </span>
          </label>
          <button className="run-btn" onClick={runAttack} disabled={attacking}>
            {attacking ? 'Attacking…' : 'Run attack'}
          </button>
        </div>

        {attackError && (
          <div className="error-box"><strong>Error:</strong> {attackError}</div>
        )}

        {attackResult && <AttackResultCard result={attackResult} />}
      </section>

      {/* SECTION 2 */}
      <section className="bd-section">
        <h3>Empirical curve vs theoretical</h3>
        <p className="section-sub">
          Run the attack many times across all output sizes. Empirical means
          should fall close to the theoretical 2<sup>n/2</sup> markers, and
          collision probability should match the curve P(collision) = 1 −
          e<sup>−k(k−1)/2<sup>n+1</sup></sup>.
        </p>

        <div className="controls-row">
          <label className="ctrl">
            <span className="ctrl-label">Trials per n ({trials})</span>
            <input
              type="range"
              min={10}
              max={100}
              step={10}
              value={trials}
              onChange={(e) => setTrials(parseInt(e.target.value, 10))}
            />
            <span className="ctrl-hint">Higher = smoother but slower</span>
          </label>
          <button className="run-btn" onClick={runCurve} disabled={running}>
            {running ? 'Running…' : 'Run curve experiment'}
          </button>
        </div>

        {curveError && (
          <div className="error-box"><strong>Error:</strong> {curveError}</div>
        )}

        {curveData && (
          <>
            <CurveChart data={chartData} curveData={curveData} />
            <CurveTable curveData={curveData} />
          </>
        )}
      </section>

      {/* SECTION 3 */}
      {context && (
        <section className="bd-section">
          <h3>Real-world context</h3>
          <p className="section-sub">
            How long does the birthday attack take on production hashes?
            Assuming {context.cpu_speed_assumption}, single-threaded.
          </p>

          <div className="ctx-grid">
            {context.analyses.map((a) => (
              <div className={`ctx-card ${a.status.toLowerCase()}`} key={a.hash}>
                <div className="ctx-headline">
                  <span className="ctx-name">{a.hash}</span>
                  <span className={`ctx-status ${a.status.toLowerCase()}`}>
                    {a.status}
                  </span>
                </div>
                <div className="ctx-row">
                  <span className="ctx-label">output</span>
                  <span>{a.output_bits} bits</span>
                </div>
                <div className="ctx-row">
                  <span className="ctx-label">birthday bound</span>
                  <code>{a.birthday_bound_2_n_half}</code>
                </div>
                <div className="ctx-row">
                  <span className="ctx-label">at 10⁹/sec</span>
                  <span>{a.at_1e9_hashes_per_sec.years} years</span>
                </div>
              </div>
            ))}
          </div>

          <p className="ctx-takeaway">{context.takeaway}</p>
        </section>
      )}
    </div>
  )
}

function AttackResultCard({ result }) {
  if (!result.collision_found) {
    return (
      <div className="result-card bad">
        <div className="result-headline">✗ No collision found</div>
        <div className="section-sub">
          Reached max_trials = {result.evaluations} without a collision.
        </div>
      </div>
    )
  }

  const ratio = result.ratio
  let band = 'good'
  if (ratio > 2.5) band = 'mid'
  if (ratio > 5) band = 'bad'

  return (
    <div className={`result-card ${band}`}>
      <div className="result-headline">
        ✓ Collision found in {result.evaluations} evaluations
      </div>
      <div className="result-grid">
        <span className="result-label">expected</span>
        <code>2^({result.n_bits}/2) = {result.expected_2_n_half}</code>

        <span className="result-label">ratio</span>
        <code>{ratio.toFixed(2)}× expected</code>

        <span className="result-label">elapsed</span>
        <code>{result.elapsed_ms.toFixed(2)} ms</code>

        <span className="result-label">collision pair</span>
        <code className="hex-trunc">{result.x_hex}</code>

        <span className="result-label"></span>
        <code className="hex-trunc">{result.x_prime_hex}</code>

        <span className="result-label">shared hash</span>
        <code>{result.hash_hex}</code>
      </div>
    </div>
  )
}

function CurveChart({ data, curveData }) {
  const empiricalMeans = curveData.results.map((r) => ({
    n: r.n_bits,
    mean: r.mean_evaluations,
  }))

  return (
    <div className="chart-wrap">
      <ResponsiveContainer width="100%" height={420}>
        <LineChart data={data} margin={{ top: 16, right: 24, bottom: 24, left: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2a2d31" />
          <XAxis
            dataKey="k"
            type="number"
            scale="log"
            domain={['auto', 'auto']}
            allowDataOverflow
            stroke="#9aa0a6"
            label={{
              value: 'k (number of hashes computed, log scale)',
              position: 'insideBottom',
              offset: -8,
              fill: '#9aa0a6',
              fontSize: 12,
            }}
          />
          <YAxis
            domain={[0, 1]}
            stroke="#9aa0a6"
            label={{
              value: 'P(collision)',
              angle: -90,
              position: 'insideLeft',
              fill: '#9aa0a6',
              fontSize: 12,
            }}
          />
          <Tooltip
            contentStyle={{
              background: '#0f1115',
              border: '1px solid #2a2d31',
              borderRadius: 6,
            }}
            labelStyle={{ color: '#d6d6d6' }}
            formatter={(value) => (typeof value === 'number' ? value.toFixed(3) : value)}
            labelFormatter={(k) => `k = ${k}`}
          />
          <Legend wrapperStyle={{ paddingTop: 8 }} />
          {N_VALUES.map((nv) => (
            <Line
              key={nv}
              type="monotone"
              dataKey={`n${nv}`}
              name={`n=${nv}`}
              stroke={N_COLORS[nv]}
              dot={false}
              strokeWidth={2}
              connectNulls
            />
          ))}
          {empiricalMeans.map((m) => (
            <ReferenceLine
              key={m.n}
              x={m.mean}
              stroke={N_COLORS[m.n]}
              strokeDasharray="3 3"
              label={{
                value: `n=${m.n}`,
                position: 'top',
                fill: N_COLORS[m.n],
                fontSize: 10,
              }}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      <p className="chart-caption">
        Solid lines = theoretical P(collision). Dashed verticals = empirical
        mean evaluations to first collision.
      </p>
    </div>
  )
}

function CurveTable({ curveData }) {
  return (
    <div className="curve-table-wrap">
      <table className="curve-table">
        <thead>
          <tr>
            <th>n</th>
            <th>trials</th>
            <th>empirical mean</th>
            <th>theoretical 2^(n/2)</th>
            <th>ratio</th>
            <th>min / max</th>
          </tr>
        </thead>
        <tbody>
          {curveData.results.map((r) => (
            <tr key={r.n_bits}>
              <td><code>{r.n_bits}</code></td>
              <td>{r.trials}</td>
              <td><code>{r.mean_evaluations.toFixed(1)}</code></td>
              <td><code>{r.expected_sqrt_2n.toFixed(1)}</code></td>
              <td className={ratioClass(r.ratio_mean_over_expected)}>
                <code>{r.ratio_mean_over_expected.toFixed(2)}×</code>
              </td>
              <td className="muted">
                <code>{r.min_evaluations} / {r.max_evaluations}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ratioClass(r) {
  if (r >= 0.7 && r <= 1.5) return 'ratio-good'
  if (r >= 0.5 && r <= 2.5) return 'ratio-mid'
  return 'ratio-bad'
}

function mergeCurves(theoretical) {
  // theoretical: { "8": [{k, probability}, ...], "10": [...], ... }
  const merged = new Map()
  for (const [n, points] of Object.entries(theoretical)) {
    for (const p of points) {
      if (!merged.has(p.k)) merged.set(p.k, { k: p.k })
      merged.get(p.k)[`n${n}`] = p.probability
    }
  }
  return Array.from(merged.values()).sort((a, b) => a.k - b.k)
}