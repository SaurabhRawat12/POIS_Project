import React from "react";
import { PRIMITIVES } from "../lib/primitives";
import StepDisplay from "./StepDisplay";

export default function BuildColumn({
  foundation,
  source,
  onSourceChange,
  seed,
  onSeedChange,
  chain,
  finalOutput,
  loading,
}) {
  return (
    <section className="flex flex-col h-full border border-lab-border bg-lab-panel/40">
      {/* Header */}
      <header className="border-b border-lab-border px-4 py-3 bg-lab-panel/80">
        <div className="flex items-baseline justify-between gap-2">
          <div>
            <div className="text-[10px] tracking-widest text-lab-accent font-mono uppercase">
              Column 1 · Leg 1
            </div>
            <h2 className="display text-lg text-lab-text mt-0.5">
              Build source primitive from foundation
            </h2>
          </div>
          <div className="text-[10px] text-lab-dim font-mono text-right">
            <div>foundation</div>
            <div className="text-lab-text text-sm mt-0.5">{foundation}</div>
          </div>
        </div>
      </header>

      {/* Controls */}
      <div className="border-b border-lab-border px-4 py-3 grid grid-cols-1 md:grid-cols-[auto_1fr] gap-3 items-center">
        <label className="text-[11px] uppercase tracking-widest text-lab-dim">
          Source primitive A
        </label>
        <select
          value={source}
          onChange={(e) => onSourceChange(e.target.value)}
          className="bg-lab-bg border border-lab-border text-lab-text text-sm px-2 py-1.5 font-mono focus:outline-none focus:border-lab-accent"
        >
          {PRIMITIVES.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name} — {p.full} (PA#{p.pa})
            </option>
          ))}
        </select>

        <label className="text-[11px] uppercase tracking-widest text-lab-dim">
          Input seed (hex)
        </label>
        <input
          type="text"
          value={seed}
          onChange={(e) => onSeedChange(e.target.value)}
          placeholder="a3f24e87b21c49df8e06f14c3a9b2c7d"
          spellCheck={false}
          className="bg-lab-bg border border-lab-border text-lab-text text-sm px-2 py-1.5 font-mono hex focus:outline-none focus:border-lab-accent"
        />
      </div>

      {/* Chain */}
      <div className="flex-1 overflow-y-auto px-4 py-3 lab-grid">
        {loading ? (
          <div className="text-lab-dim text-xs animate-blink">computing…</div>
        ) : chain && chain.length ? (
          chain.map((step, i) => (
            <StepDisplay key={i} index={i + 1} {...step} />
          ))
        ) : (
          <div className="text-lab-dim text-xs">no chain</div>
        )}
      </div>

      {/* Final output */}
      <footer className="border-t border-lab-border px-4 py-3 bg-lab-panel/80">
        <div className="text-[10px] uppercase tracking-widest text-lab-dim mb-1">
          A = {source} (piped to Column 2)
        </div>
        <div className="hex text-sm text-lab-accent">
          {finalOutput || "—"}
        </div>
      </footer>
    </section>
  );
}
