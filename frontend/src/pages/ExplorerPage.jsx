import { useState, useEffect } from "react";
import { checkHealth } from "../api/client";
import "../App.css";

// ---- Static metadata ------------------------------------------------------

const FOUNDATIONS = [
  { id: "AES", label: "AES-128 (PRP)" },
  { id: "DLP", label: "DLP (g^x mod p)" },
];

const PRIMITIVES = [
  { id: "OWF", label: "OWF — One-Way Function" },
  { id: "PRG", label: "PRG — Pseudorandom Generator" },
  { id: "PRF", label: "PRF — Pseudorandom Function" },
  { id: "PRP", label: "PRP — Pseudorandom Permutation" },
  { id: "MAC", label: "MAC — Message Auth. Code" },
  { id: "CRHF", label: "CRHF — Collision-Resistant Hash" },
  { id: "HMAC", label: "HMAC — Hash-based MAC" },
];

// Reduction routing: each pair maps to a chain of theorem names.
// Empty chain means "not implemented in this direction".
const REDUCTIONS = {
  "OWF→PRG": ["HILL hard-core-bit construction"],
  "PRG→PRF": ["GGM tree (binary)"],
  "PRF→PRP": ["Luby-Rackoff Feistel (3 rounds)"],
  "PRF→MAC": ["Mac_k(m) = F_k(m)"],
  "PRP→MAC": ["PRP/PRF switching lemma", "F_k as MAC"],
  "CRHF→HMAC": ["HMAC double-hash construction"],
  "HMAC→MAC": ["HMAC is a secure MAC"],
};

// ---- Component ------------------------------------------------------------

export default function App() {
  const [foundation, setFoundation] = useState("AES");
  const [sourcePrim, setSourcePrim] = useState("PRG");
  const [targetPrim, setTargetPrim] = useState("PRF");
  const [seed, setSeed] = useState("a3f29b1c8e74d502");
  const [query, setQuery] = useState("1011");
  const [showProof, setShowProof] = useState(true);
  const [backendStatus, setBackendStatus] = useState("checking…");

  // Probe the backend on mount so the user knows the API is reachable.
  useEffect(() => {
    checkHealth()
      .then((data) =>
        setBackendStatus(`✓ ${data.service} v${data.version}`)
      )
      .catch((err) =>
        setBackendStatus(`✗ Backend offline (${err.message})`)
      );
  }, []);

  const reductionKey = `${sourcePrim}→${targetPrim}`;
  const reductionChain = REDUCTIONS[reductionKey];
  const reductionImplemented = !!reductionChain;

  return (
    <div className="app">
      {/* ---- Top bar ---------------------------------------------------- */}
      <header className="topbar">
        <h1>POIS Cryptography Lab</h1>

        <div className="foundation-toggle" role="radiogroup" aria-label="Foundation">
          <span className="label">Foundation:</span>
          {FOUNDATIONS.map((f) => (
            <button
              key={f.id}
              className={foundation === f.id ? "active" : ""}
              onClick={() => setFoundation(f.id)}
              aria-pressed={foundation === f.id}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div
          className={
            "backend-status " +
            (backendStatus.startsWith("✓") ? "ok" : "fail")
          }
          title="FastAPI server status"
        >
          {backendStatus}
        </div>
      </header>

      {/* ---- Two columns ----------------------------------------------- */}
      <main className="columns">
        <section className="column">
          <h2>Column 1 — Build</h2>
          <p className="column-subtitle">
            Foundation → Source primitive A
          </p>

          <label>
            Source primitive A
            <select
              value={sourcePrim}
              onChange={(e) => setSourcePrim(e.target.value)}
            >
              {PRIMITIVES.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            Input seed (hex)
            <input
              type="text"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              placeholder="a3f2…"
            />
          </label>

          <div className="chain-display">
            <h3>Construction chain</h3>
            <div className="chain-step">
              <span className="step-num">1.</span>
              <span className="step-text">
                {foundation === "AES"
                  ? "AES_k(0) = …"
                  : "g^x mod p = …"}
              </span>
            </div>
            <div className="chain-step">
              <span className="step-num">2.</span>
              <span className="step-text">{sourcePrim}(s) = …</span>
            </div>
            <p className="placeholder-note">
              ⚠ Live data wiring lands in the next step.
            </p>
          </div>
        </section>

        <section className="column">
          <h2>Column 2 — Reduce</h2>
          <p className="column-subtitle">
            Source A → Target primitive B
          </p>

          <label>
            Target primitive B
            <select
              value={targetPrim}
              onChange={(e) => setTargetPrim(e.target.value)}
            >
              {PRIMITIVES.filter((p) => p.id !== sourcePrim).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            Query x
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="1011"
            />
          </label>

          <div className="chain-display">
            <h3>Reduction chain</h3>
            {reductionImplemented ? (
              reductionChain.map((step, i) => (
                <div key={i} className="chain-step">
                  <span className="step-num">{i + 1}.</span>
                  <span className="step-text">{step}</span>
                </div>
              ))
            ) : (
              <div className="stub-warning">
                No direct reduction <code>{sourcePrim} → {targetPrim}</code> in
                the routing table yet. Try toggling primitives or wait for
                the bidirectional mode (coming in a later step).
              </div>
            )}
          </div>
        </section>
      </main>

      {/* ---- Proof summary --------------------------------------------- */}
      <footer className="proof-panel">
        <button
          className="proof-toggle"
          onClick={() => setShowProof(!showProof)}
          aria-expanded={showProof}
        >
          {showProof ? "▼" : "▶"} Reduction Chain Summary
        </button>
        {showProof && (
          <div className="proof-content">
            <p>
              <strong>Path:</strong> {foundation} →{" "}
              <em>{sourcePrim}</em> → <em>{targetPrim}</em>
            </p>
            <p>
              <strong>Theorems used:</strong>{" "}
              {reductionImplemented
                ? reductionChain.join("  ·  ")
                : "(no path defined yet)"}
            </p>
            <p className="security-note">
              Security claim: all values in the columns above will be live
              outputs from your PA implementations once the API client is
              wired up next.
            </p>
          </div>
        )}
      </footer>
    </div>
  );
}
