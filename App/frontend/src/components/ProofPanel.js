import React, { useState } from "react";

export default function ProofPanel({ foundation, source, target, direction, buildChain, reduceChain }) {
  const [open, setOpen] = useState(false);

  // Flatten the full chain: foundation -> A -> B
  const fullChain = [...(buildChain || []), ...(reduceChain || [])];
  const unimplementedCount = fullChain.filter((s) => !s.implemented).length;

  return (
    <section className="border border-lab-border bg-lab-panel/40">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full text-left px-4 py-3 flex items-center justify-between hover:bg-lab-panel/70 transition-colors"
      >
        <div className="flex items-baseline gap-3 flex-wrap">
          <span className="text-[10px] tracking-widest text-lab-dim uppercase font-mono">
            Reduction proof summary
          </span>
          <span className="display text-sm text-lab-text">
            {foundation}
            <span className="text-lab-dim mx-2">→</span>
            {direction === "backward" ? target : source}
            <span className="text-lab-dim mx-2">→</span>
            {direction === "backward" ? source : target}
          </span>
          <span className="text-[10px] text-lab-dim font-mono">
            {fullChain.length} steps · {unimplementedCount} stubbed
          </span>
        </div>
        <span className="text-lab-accent text-lg leading-none select-none">
          {open ? "−" : "+"}
        </span>
      </button>

      {open && (
        <div className="border-t border-lab-border px-4 py-4 animate-fade-in">
          {fullChain.length === 0 ? (
            <div className="text-lab-dim text-xs">Empty chain.</div>
          ) : (
            <ol className="space-y-2">
              {fullChain.map((step, i) => (
                <li key={i} className="flex items-start gap-3 text-xs">
                  <span className="text-lab-dim font-mono w-8 shrink-0">
                    {String(i + 1).padStart(2, "0")}.
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-lab-text">
                      <span className="font-medium">{step.from}</span>
                      <span className="text-lab-dim mx-1.5">⇒</span>
                      <span className="font-medium">{step.to}</span>
                      <span className="text-lab-ink ml-2">
                        · {step.theorem}
                      </span>
                    </div>
                    {step.security_claim && (
                      <div className="text-lab-dim italic mt-0.5 leading-relaxed">
                        {step.security_claim}
                      </div>
                    )}
                    <div className="mt-1">
                      <span
                        className={`inline-block text-[10px] px-1.5 py-0.5 border font-mono tracking-wider uppercase ${
                          step.implemented
                            ? "text-lab-accent border-lab-accentDim"
                            : "text-lab-warn border-lab-warnDim"
                        }`}
                      >
                        {step.implemented
                          ? `PA#${step.pa_number} · implemented`
                          : step.pa_number
                          ? `Due PA#${step.pa_number}`
                          : "N/A"}
                      </span>
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}

          <div className="mt-4 pt-3 border-t border-lab-border/60 text-[11px] text-lab-dim leading-relaxed">
            All intermediate hex values shown above will become real outputs
            from your PA#1–#10 implementations as the course progresses. At
            PA#0 every step is a deterministic stub — the scaffold proves the
            routing and the UI are correct before the math lands.
          </div>
        </div>
      )}
    </section>
  );
}
