import React from "react";

export default function DirectionToggle({ value, onChange }) {
  const options = [
    { value: "forward", label: "Forward", desc: "A → B" },
    { value: "backward", label: "Backward", desc: "B → A" },
  ];
  return (
    <div className="flex items-center gap-2">
      <span className="text-[11px] uppercase tracking-widest text-lab-dim">
        Direction
      </span>
      <div role="tablist" className="flex border border-lab-border">
        {options.map((o) => {
          const active = value === o.value;
          return (
            <button
              key={o.value}
              role="tab"
              aria-selected={active}
              onClick={() => onChange(o.value)}
              className={`px-2.5 py-1.5 text-[11px] font-mono tracking-wider transition-colors ${
                active
                  ? "bg-lab-gold text-lab-bg"
                  : "bg-transparent text-lab-ink hover:bg-lab-panel hover:text-lab-text"
              }`}
              title={o.desc}
            >
              {o.label} <span className="opacity-70 ml-1">{o.desc}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
