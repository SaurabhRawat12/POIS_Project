import React from "react";

/**
 * A single step in a reduction chain.
 *
 * Props
 *  - index       (number)   ordinal position (1-based in the UI)
 *  - from        (string)   source primitive/foundation tag
 *  - to          (string)   destination primitive tag
 *  - theorem     (string)   human-readable construction name
 *  - pa_number   (number?)  which PA implements this step
 *  - implemented (bool)     whether the step has real code behind it yet
 *  - input_hex   (string)   input bytes
 *  - output_hex  (string)   output bytes
 *  - security_claim (string) one-liner from the routing table
 */
export default function StepDisplay({
  index,
  from,
  to,
  theorem,
  pa_number,
  implemented,
  input_hex,
  output_hex,
  security_claim,
}) {
  const statusColor = implemented
    ? "text-lab-accent border-lab-accentDim"
    : "text-lab-warn border-lab-warnDim";
  const statusLabel = implemented
    ? `PA#${pa_number} — implemented`
    : pa_number
    ? `Not yet implemented — due PA#${pa_number}`
    : "Unavailable";

  return (
    <div className="animate-fade-in border border-lab-border bg-lab-panel/60 p-3 mb-2">
      {/* Header line: step number, from -> to, PA status */}
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] text-lab-dim font-mono tracking-wider">
            STEP {String(index).padStart(2, "0")}
          </span>
          <span className="text-xs font-mono text-lab-ink">
            <span className="text-lab-text font-medium">{from}</span>
            <span className="text-lab-dim mx-1">→</span>
            <span className="text-lab-text font-medium">{to}</span>
          </span>
        </div>
        <span
          className={`text-[10px] px-1.5 py-0.5 border ${statusColor} font-mono tracking-wider uppercase`}
        >
          {statusLabel}
        </span>
      </div>

      {/* Theorem name */}
      <div className="text-sm text-lab-text mb-2 leading-snug">
        {theorem}
      </div>

      {/* Hex input / output */}
      <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        <div className="text-lab-dim font-mono">in</div>
        <div className="hex text-lab-ink">{input_hex || "—"}</div>
        <div className="text-lab-dim font-mono">out</div>
        <div
          className={`hex ${
            implemented ? "text-lab-accent" : "text-lab-warn/70"
          }`}
        >
          {output_hex || "—"}
        </div>
      </div>

      {/* Security claim */}
      {security_claim && (
        <div className="mt-2 pt-2 border-t border-lab-border/60 text-[11px] text-lab-dim italic leading-relaxed">
          {security_claim}
        </div>
      )}
    </div>
  );
}
