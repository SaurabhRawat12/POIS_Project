/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}", "./public/index.html"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
        display: ['"Fraunces"', "Georgia", "serif"],
      },
      colors: {
        // Cryptographic laboratory palette
        lab: {
          bg: "#0b0f14",        // near-black teal-tinted
          panel: "#0f1520",     // panel background
          border: "#1e2936",    // hairline borders
          muted: "#2a3644",     // secondary borders / subtle divs
          text: "#d7e0ea",      // body text (off-white with cool cast)
          dim: "#6b7a8c",       // secondary text
          ink: "#a8b8cc",       // tertiary text
          accent: "#5dd4d0",    // primary accent: muted cyan
          accentDim: "#3a8a87", // muted accent
          warn: "#ff6b8b",      // not-implemented / warning
          warnDim: "#8a2f45",   // dim variant
          gold: "#e8b852",      // for PA numbers
        },
      },
      animation: {
        "fade-in": "fade-in 240ms ease-out",
        "blink": "blink 1.4s steps(2) infinite",
      },
      keyframes: {
        "fade-in": {
          "0%": { opacity: "0", transform: "translateY(2px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "blink": {
          "0%, 100%": { opacity: "0.4" },
          "50%": { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};
