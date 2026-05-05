# CS8.401 · Minicrypt Clique Explorer

**PA#0 — Scaffold**

An interactive, live web app that visualises the entire Minicrypt clique: every
reduction from the concrete foundation (AES or DLP) to any primitive in the
clique (OWF, PRG, PRF, PRP, MAC, CRHF, HMAC), and back. As PA#1–#10 are
completed, the stub primitives are replaced with real implementations and the
app grows into a full working demonstrator.

## Architecture

```
pois_project/
├── backend/                 Python + Flask — the crypto layer
│   ├── app.py
│   ├── requirements.txt
│   ├── api/routes.py        /api/health, /api/primitives, /api/build, /api/reduce
│   └── crypto/
│       ├── foundations/     AES, DLP (stubs at PA#0)
│       └── primitives/
│           ├── registry.py  name, PA#, description for every primitive
│           └── routing.py   BFS through the clique graph
└── frontend/                React + Tailwind — the interactive UI
    ├── package.json
    └── src/
        ├── App.js           state + wiring
        ├── lib/             api wrapper + primitives mirror
        └── components/
            ├── FoundationToggle.js
            ├── DirectionToggle.js
            ├── BuildColumn.js   Leg 1 — foundation → A
            ├── ReduceColumn.js  Leg 2 — A → B
            ├── StepDisplay.js   reusable step row
            └── ProofPanel.js    collapsible full-chain summary
```

The **under-the-hood rule** from spec §2.3 is enforced architecturally:
Column 1 produces an A-instance; Column 2 receives that instance as a black
box via the `a_instance` field and never touches the foundation directly.

## Prerequisites

- Python 3.10 or newer
- Node 18 or newer (Create React App requires 14+; 18 LTS is safe)
- npm

## Run it

You need **two terminals** — one for the backend, one for the frontend.

### Terminal 1 — Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The Flask server starts on `http://127.0.0.1:5000`. Verify with:

```bash
curl http://127.0.0.1:5000/api/health
# {"stage":"PA#0","status":"ok"}
```

### Terminal 2 — Frontend

```bash
cd frontend
npm install
npm start
```

Opens `http://localhost:3000`. The dev server proxies `/api/*` to the Flask
backend via the `proxy` field in `package.json`, so no CORS headache.

## What the app does at PA#0

- **Top bar** — toggle foundation between AES-128 and DLP.
- **Column 1 (Build)** — select any source primitive A. The app computes the
  shortest reduction path from the selected foundation to A (BFS through the
  clique graph) and displays each step with theorem name, PA#, security
  claim, and hex values.
- **Column 2 (Reduce)** — select any target primitive B (≠ A). Shows the
  abstract reduction A → B. The concrete instance of A from Column 1 is
  piped in as a black box.
- **Direction toggle** — flip between forward (A → B) and backward (B → A)
  reductions.
- **Proof panel** — collapsible bottom panel listing the full
  foundation → A → B chain, all theorem names, all security claims, and
  which PA implements each step.
- **Live data flow** — every input change (foundation, primitive, seed,
  query) re-runs both chains with no page reload.
- **Stubs everywhere** — every primitive is unimplemented at PA#0 and shows
  `Not yet implemented — due PA#N` in red. Fixed deterministic hex values are
  returned by the backend so the UI is non-empty.

## What comes next

As you complete PA#1–#10, swap in real implementations in
`backend/crypto/foundations/` and `backend/crypto/primitives/` and flip
the `implemented` flag on each step in `routing.py`. Nothing else needs to
change in the frontend.

## The no-library rule (global)

All PAs from #1 onward must use only:

- Python's built-in `int` for arbitrary-precision arithmetic
- `os.urandom` for OS-level randomness

No external cryptographic libraries (PyCryptodome, cryptography, hashlib, etc.)
may appear anywhere in the dependency chain.
