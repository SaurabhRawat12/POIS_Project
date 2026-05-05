# Foundation-First Plan: PA #1, #7, #13 Before Team Split

## Summary
- Yes, we should do **PA #1, PA #7, and PA #13 first**.
- We’ll complete them as **full deliverables** (APIs, tests, demo hooks), with **PA #1 supporting both DLP and AES**.
- After that, we split the remaining work across 5 people by dependency trunks.

## Foundation Sprint (Do First)
1. Build **PA #13 (Miller-Rabin + prime generation)** first.
2. Build **PA #1 (OWF + PRG + reverse reduction)** next, using PA #13 for DLP-safe parameter generation and adding AES-based OWF path too.
3. Build **PA #7 (generic Merkle-Damgard framework)** in parallel once core utilities are stable.
4. Freeze shared interfaces after these three pass gates so teammates can build independently without API churn.

## Exact Deliverables for the First Three
- PA #13:
1. `miller_rabin(n,k)`, `is_prime(n)`, `gen_prime(bits)`.
2. Carmichael `561` demo (passes Fermat, fails Miller-Rabin).
3. Prime-generation benchmark output for required sizes.
- PA #1:
1. OWF implementations for DLP and AES-style path with unified interface.
2. PRG from OWF (forward) and OWF-from-PRG demonstration (backward).
3. NIST-style randomness tests: frequency, runs, serial.
4. Stable API for downstream PA #2 and UI demo panel.
- PA #7:
1. Generic MD engine with pluggable compression function.
2. Correct MD-strengthening padding.
3. Toy compression plugin and collision-propagation demo.
4. Stable hash interface for PA #8 and PA #10 integration.

## 5-Person Split Immediately After Freeze
1. Engineer 1: PA #2, #3 (PRF/GGM + CPA encryption).
2. Engineer 2: PA #4, #5, #6 (modes + MAC + CCA symmetric).
3. Engineer 3: PA #8, #9, #10 (DLP hash + birthday + HMAC/EtH).
4. Engineer 4: PA #11, #12, #14 (DH + RSA + CRT/Hastad).
5. Engineer 5: PA #0 integration plus PA #15, #16, #17 (signatures, ElGamal, CCA-PKC).
- Second wave after PKC branch stabilizes: Engineers 1, 2, and 5 lead PA #18, #19, #20; Engineers 3 and 4 support benchmarking, attack demos, and lineage verification.

## Gates, Tests, and Handoff Rules
- Gate A (PA #13 done): deterministic tests + 561 case + prime-gen benchmark logs.
- Gate B (PA #1 done): both OWFs operational + PRG tests + reverse reduction demo + randomness reports.
- Gate C (PA #7 done): padding edge-case tests + collision-propagation demo + stable hash contract.
- Handoff rule: no downstream branch starts until interface freeze tags are published for PA #1/#7/#13.
- Merge cadence: twice daily integration into shared branch with lineage checks to enforce “own prior implementation only.”

## Assumptions
- Python-only core, local HTTP API bridge, React demo layer.
- Toy/demo parameters are acceptable for interactive demos; correctness and dependency lineage are mandatory.
- “Full deliverable” for these three includes code, tests, and demo-ready endpoints (not just library internals).
