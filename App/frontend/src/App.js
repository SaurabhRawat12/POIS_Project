import React, { useCallback, useEffect, useState } from "react";
import FoundationToggle from "./components/FoundationToggle";
import DirectionToggle from "./components/DirectionToggle";
import BuildColumn from "./components/BuildColumn";
import ReduceColumn from "./components/ReduceColumn";
import ProofPanel from "./components/ProofPanel";
import { api } from "./lib/api";

const DEFAULT_SEED = "a3f24e87b21c49df8e06f14c3a9b2c7d";
const DEFAULT_QUERY = "1011";

export default function App() {
  // Core selection state
  const [foundation, setFoundation] = useState("AES");
  const [source, setSource] = useState("PRG");
  const [target, setTarget] = useState("PRF");
  const [direction, setDirection] = useState("forward");

  // Input state
  const [seed, setSeed] = useState(DEFAULT_SEED);
  const [query, setQuery] = useState(DEFAULT_QUERY);

  // Computed chain state
  const [buildChain, setBuildChain] = useState([]);
  const [buildFinal, setBuildFinal] = useState("");
  const [reduceChain, setReduceChain] = useState([]);
  const [reduceFinal, setReduceFinal] = useState("");

  // UX state
  const [loadingBuild, setLoadingBuild] = useState(false);
  const [loadingReduce, setLoadingReduce] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [backendOk, setBackendOk] = useState(null); // null = unknown, true/false

  // --- Health check once on mount ------------------------------------------
  useEffect(() => {
    api
      .health()
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));
  }, []);

  // --- If target matches source, pick a different target -------------------
  useEffect(() => {
    if (target === source) {
      // pick next primitive that isn't equal to source
      const fallback = ["PRF", "PRG", "MAC", "HMAC", "CRHF", "PRP", "OWP", "OWF"].find(
        (p) => p !== source
      );
      setTarget(fallback);
    }
  }, [source, target]);

  // --- Build chain (Leg 1) -------------------------------------------------
  const fetchBuild = useCallback(async () => {
    setLoadingBuild(true);
    try {
      const res = await api.build({ foundation, source, seed });
      setBuildChain(res.chain || []);
      setBuildFinal(res.final_output || "");
      setApiError(null);
    } catch (e) {
      setApiError(String(e));
    } finally {
      setLoadingBuild(false);
    }
  }, [foundation, source, seed]);

  // --- Reduce chain (Leg 2) ------------------------------------------------
  const fetchReduce = useCallback(async () => {
    setLoadingReduce(true);
    try {
      const res = await api.reduce({
        source,
        target,
        direction,
        query,
        a_instance: buildFinal,
      });
      setReduceChain(res.chain || []);
      setReduceFinal(res.final_output || "");
      setApiError(null);
    } catch (e) {
      setApiError(String(e));
    } finally {
      setLoadingReduce(false);
    }
  }, [source, target, direction, query, buildFinal]);

  // --- Live re-fetch on any input change -----------------------------------
  useEffect(() => {
    if (backendOk) fetchBuild();
  }, [fetchBuild, backendOk]);

  useEffect(() => {
    if (backendOk) fetchReduce();
  }, [fetchReduce, backendOk]);

  return (
    <div className="min-h-screen bg-lab-bg text-lab-text flex flex-col">
      {/* ---------------------- Top bar ---------------------- */}
      <header className="border-b border-lab-border bg-lab-panel/60 backdrop-blur-sm">
        <div className="px-5 py-3 flex flex-wrap items-center gap-4 justify-between">
          {/* Left: title */}
          <div className="flex items-baseline gap-3">
            <div className="text-lab-accent text-xl font-bold select-none">∴</div>
            <div>
              <div className="text-[10px] tracking-[0.25em] text-lab-dim font-mono uppercase">
                CS8.401 · PA#0
              </div>
              <h1 className="display text-xl text-lab-text leading-none mt-0.5">
                Minicrypt Clique Explorer
              </h1>
            </div>
          </div>

          {/* Right: foundation + direction + health */}
          <div className="flex items-center gap-5 flex-wrap">
            <FoundationToggle value={foundation} onChange={setFoundation} />
            <DirectionToggle value={direction} onChange={setDirection} />
            <HealthDot ok={backendOk} />
          </div>
        </div>
      </header>

      {/* API error banner */}
      {apiError && (
        <div className="bg-lab-warn/10 border-b border-lab-warnDim text-lab-warn text-xs px-5 py-2 font-mono">
          API error: {apiError}
        </div>
      )}

      {backendOk === false && (
        <div className="bg-lab-warn/10 border-b border-lab-warnDim text-lab-warn text-xs px-5 py-2 font-mono">
          Backend not reachable at /api/health. Start the Flask server:{" "}
          <span className="text-lab-warn/80">cd backend && python app.py</span>
        </div>
      )}

      {/* ---------------------- Two columns ---------------------- */}
      <main className="flex-1 p-5 grid grid-cols-1 lg:grid-cols-2 gap-5 min-h-0">
        <BuildColumn
          foundation={foundation}
          source={source}
          onSourceChange={setSource}
          seed={seed}
          onSeedChange={setSeed}
          chain={buildChain}
          finalOutput={buildFinal}
          loading={loadingBuild}
        />
        <ReduceColumn
          source={source}
          target={target}
          onTargetChange={setTarget}
          query={query}
          onQueryChange={setQuery}
          aInstance={buildFinal}
          chain={reduceChain}
          finalOutput={reduceFinal}
          direction={direction}
          loading={loadingReduce}
        />
      </main>

      {/* ---------------------- Proof panel ---------------------- */}
      <div className="px-5 pb-5">
        <ProofPanel
          foundation={foundation}
          source={source}
          target={target}
          direction={direction}
          buildChain={buildChain}
          reduceChain={reduceChain}
        />
      </div>

      {/* ---------------------- Footer caption ---------------------- */}
      <footer className="border-t border-lab-border px-5 py-3 text-[10px] text-lab-dim font-mono tracking-wider uppercase flex justify-between">
        <span>
          No external cryptographic libraries. Every primitive is our own.
        </span>
        <span>
          Stage: <span className="text-lab-accent">PA#0 · scaffold</span>
        </span>
      </footer>
    </div>
  );
}

function HealthDot({ ok }) {
  const color =
    ok === true
      ? "bg-lab-accent text-lab-accent"
      : ok === false
      ? "bg-lab-warn text-lab-warn"
      : "bg-lab-dim text-lab-dim";
  const label = ok === true ? "backend live" : ok === false ? "backend down" : "checking…";
  return (
    <div className="flex items-center gap-2" title={label}>
      <span className={`live-dot w-1.5 h-1.5 rounded-full ${color}`} />
      <span className="text-[10px] font-mono text-lab-dim tracking-wider uppercase">
        {label}
      </span>
    </div>
  );
}
