import React from "react";
import { FOUNDATIONS } from "../lib/primitives";

export default function FoundationToggle({ value, onChange }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[11px] uppercase tracking-widest text-lab-dim">
        Foundation
      </span>
      <div
        role="tablist"
        aria-label="Cryptographic foundation"
        className="flex border border-lab-border"
      >
        {FOUNDATIONS.map((f) => {
          const active = value === f.name;
          return (
            <button
              key={f.name}
              role="tab"
              aria-selected={active}
              onClick={() => onChange(f.name)}
              className={`px-3 py-1.5 text-xs font-mono tracking-wider transition-colors ${
                active
                  ? "bg-lab-accent text-lab-bg"
                  : "bg-transparent text-lab-ink hover:bg-lab-panel hover:text-lab-text"
              }`}
              title={f.full}
            >
              {f.name}
            </button>
          );
        })}
      </div>
    </div>
  );
}
