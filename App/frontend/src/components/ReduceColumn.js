import React from "react";
import { PRIMITIVES } from "../lib/primitives";
import StepDisplay from "./StepDisplay";

export default function ReduceColumn({
  source,
  target,
  onTargetChange,
  query,
  onQueryChange,
  aInstance,
  chain,
  finalOutput,
  direction,
  loading,
}) {
  // Target must differ from source
  const options = PRIMITIVES.filter((p) => p.name !== source);
  const directionLabel =
    direction === "backward" ? `${target} → ${source}` : `${source} → ${target}`;

  return (
    <section className="flex flex-col h-full border border-lab-border bg-lab-panel/40">
      {/* Header */}
      <header className="border-b border-lab-border px-4 py-3 bg-lab-panel/80">
        <div className="flex items-baseline justify-between gap-2">
          <div>
            <div className="text-[10px] tracking-widest text-lab-gold font-mono uppercase">
              Column 2 · Leg 2
            </div>
            <h2 className="display text-lg text-lab-text mt-0.5">
              Abstract reduction {directionLabel}
            </h2>
          </div>
          <div className="text-[10px] text-lab-dim font-mono text-right">
            <div>A (from col. 1)</div>
            <div className="hex text-lab-accent text-xs mt-0.5 max-w-[10ch] truncate">
              {aInstance || "—"}
            </div>
          </div>
        </div>
      </header>

      {/* Controls */}
      <div className="border-b border-lab-border px-4 py-3 grid grid-cols-1 md:grid-cols-[auto_1fr] gap-3 items-center">
        <label className="text-[11px] uppercase tracking-widest text-lab-dim">
          Target primitive B
        </label>
        <select
          value={target}
          onChange={(e) => onTargetChange(e.target.value)}
          className="bg-lab-bg border border-lab-border text-lab-text text-sm px-2 py-1.5 font-mono focus:outline-none focus:border-lab-gold"
        >
          {options.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name} — {p.full} (PA#{p.pa})
            </option>
          ))}
        </select>

        <label className="text-[11px] uppercase tracking-widest text-lab-dim">
          Query input (hex)
        </label>
        <input
          type="text"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="1011 — bit string or hex"
          spellCheck={false}
          className="bg-lab-bg border border-lab-border text-lab-text text-sm px-2 py-1.5 font-mono hex focus:outline-none focus:border-lab-gold"
        />
      </div>

      {/* Chain */}
      <div className="flex-1 overflow-y-auto px-4 py-3 lab-grid">
        {loading ? (
          <div className="text-lab-dim text-xs animate-blink">reducing…</div>
        ) : chain && chain.length ? (
          chain.map((step, i) => (
            <StepDisplay key={i} index={i + 1} {...step} />
          ))
        ) : (
          <div className="text-lab-dim text-xs">no reduction</div>
        )}
      </div>

      {/* Final output */}
      <footer className="border-t border-lab-border px-4 py-3 bg-lab-panel/80">
        <div className="text-[10px] uppercase tracking-widest text-lab-dim mb-1">
          B output = {direction === "backward" ? source : target}(query)
        </div>
        <div className="hex text-sm text-lab-gold">
          {finalOutput || "—"}
        </div>
      </footer>
    </section>
  );
}
