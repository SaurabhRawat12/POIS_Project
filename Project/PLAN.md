# 4-Day MVP Plan: CS8.401 PA#0–PA#20 (Python-Only, Local API)

## Summary
- Build a single Python codebase for all cryptographic primitives and protocol games, expose them through a local HTTP API, and connect a React/Vite web explorer for PA#0 plus all interactive demos.
- Deliver **MVP coverage for every PA (#0–#20)** in 4 days using toy/demo-safe parameters, strict lineage (later PA calls earlier PA modules), and no external crypto libraries.
- Enforce two acceptance levels per PA: `functional correctness` (required) and `security/demo evidence` (required at toy scale).

## Implementation Changes
1. Create 6 subsystems with strict dependencies: `core_math` (modexp, egcd, inverses, padding, RNG), `primitives` (OWF/PRG/PRF/PRP/MAC/CRHF/HMAC/RSA/DH/ElGamal), `protocols` (CPA/CCA games, signcryption, OT, secure gates, MPC), `attacks` (nonce reuse, length extension, Bleichenbacher toy, Hastad, malleability, MITM, birthday), `trace_lineage` (step logs + call-stack lineage), `api_ui` (FastAPI + React).
2. Fix a single canonical data model for all APIs: byte-oriented hex I/O externally, Python `int` internally for number theory, and typed dict responses with `result`, `trace`, `security_note`, `pa_id`.
3. Implement PA#0 routing engine as graph search over primitives with forward/backward mode; Column 2 receives only callable objects returned from Column 1 (black-box rule).
4. Add stub registry from day 1 for unimplemented primitives; every stub must return `not_implemented`, `due_pa`, and a safe placeholder trace so UI never crashes.
5. Add lineage guard checks in runtime: PA#6 must call PA#3 + PA#5; PA#10 must call PA#8; PA#18 must call PA#12 or PA#16; PA#20 AND must transitively call PA#19→#18→#12/#16→#13.

## Public Interfaces (Decision-Complete)
1. PA#1: `owf_evaluate(x)`, `owf_verify_hardness(trials)`, `prg_seed(s)`, `prg_next_bits(n)`, `prg_to_owf_demo()`.
2. PA#2: `prf_eval(k,x)`, `prf_to_prg(s)`, `ggm_trace(k,x)`, `prf_distinguish_game(q)`.
3. PA#3: `cpa_enc(k,m)`, `cpa_dec(k,c)`, `ind_cpa_game(rounds,reuse_nonce=False)`.
4. PA#4: `encrypt(mode,k,m)`, `decrypt(mode,k,c)`, modes `CBC|OFB|CTR`, plus IV-reuse demos.
5. PA#5: `mac_tag(k,m,scheme)`, `mac_verify(k,m,t,scheme)`, `euf_cma_game()`.
6. PA#6: `cca_enc(kE,kM,m)`, `cca_dec(kE,kM,c,t)`, verify-before-decrypt enforced.
7. PA#7: `md_hash(message,compress_fn,iv,block_size)`, `md_pad(message)`.
8. PA#8: `dlp_hash(message,out_bits=None)`, `dlp_compress(x,y)`, group setup API.
9. PA#9: `birthday_attack(hash_fn,n,method)`, `birthday_trials(n,trials)`.
10. PA#10: `hmac_tag(k,m)`, `hmac_verify(k,m,t)`, `eth_enc(kE,kM,m)`, `eth_dec(...)`, `secure_compare(t1,t2)`.
11. PA#11: `dh_alice_step1()`, `dh_bob_step1()`, `dh_alice_step2(a,B)`, `dh_bob_step2(b,A)`, `mitm_demo()`.
12. PA#12: `rsa_keygen(bits)`, `rsa_enc/dec`, `pkcs15_enc/dec`, `padding_oracle_demo()`.
13. PA#13: `miller_rabin(n,k)`, `gen_prime(bits)`, `is_prime(n)`.
14. PA#14: `crt(residues,moduli)`, `rsa_dec_crt(sk,c)`, `hastad_attack(ciphertexts,moduli,e)`.
15. PA#15: `sign(sk,m)`, `verify(vk,m,sigma)`, `euf_cma_sign_game()`.
16. PA#16: `elgamal_keygen()`, `elgamal_enc/dec`, `malleability_demo()`.
17. PA#17: `cca_pkc_enc(pk_enc,sk_sign,m)`, `cca_pkc_dec(sk_enc,vk_sign,ce,sigma)`.
18. PA#18: `ot_receiver_step1(b)`, `ot_sender_step(pk0,pk1,m0,m1)`, `ot_receiver_step2(state,c0,c1)`.
19. PA#19: `secure_and(a,b)`, `secure_xor(a,b)`, `secure_not(a)`.
20. PA#20: `Circuit(nodes,wires)`, `secure_eval(circuit,x_alice,y_bob)`, mandatory circuit builders `millionaire/equality/addition`.
21. PA#0 API endpoints: `/build-source`, `/reduce-target`, `/proof-summary`, `/demo/{pa_id}`, `/lineage/trace`.

## 4-Day Execution Plan
1. Day 1 (Platform + dependencies): scaffold monorepo, FastAPI, React/Vite, trace engine, PA#0 layout + routing + stubs, implement PA#13 first, then PA#12 + PA#11 + minimal PA#16 key flow; gate = UI loads all pairs without crash and RSA/DH primitives execute at toy scale.
2. Day 2 (Minicrypt + Hash bridge): implement PA#1–#6 and PA#7–#10 MVP paths with all required games/demos at toy parameters; wire PA#0 Column 1/2 real data flow for OWF→HMAC chain; gate = Parts I–II demo pages all operational and bidirectional-required pairs pass smoke tests.
3. Day 3 (Cryptomania + MPC base): implement PA#14, #15, #17, then PA#18 and PA#19 with transcript logging and privacy notes; gate = Hastad attack works on unpadded RSA, fails with padding; sign-then-encrypt rejects tamper; OT and Secure AND pass 100 randomized runs.
4. Day 4 (PA#20 + stabilization): implement secure circuit DAG evaluator and 3 mandatory circuits, finalize lineage call-stack report, add e2e demo tests, fix integration bugs, freeze docs and grading checklist; gate = full PA#0–#20 MVP demo walkthrough completes start-to-finish on one machine.

## Test Plan
1. Primitive unit tests: correctness identities (`Dec(Enc)=m`, `Verify(Sign)=true`, CRT recombination, Miller-Rabin known vectors, GGM determinism).
2. Security game tests: IND-CPA, IND-CCA2, EUF-CMA, PRF distinguishers with expected near-random advantage in secure modes.
3. Attack regression tests: nonce reuse break, OFB/CBC reuse leakage, length extension success vs HMAC fail, MITM DH break, textbook RSA determinism, Bleichenbacher toy recovery, ElGamal malleability, Hastad recovery.
4. MPC tests: truth tables for AND/XOR/NOT, millionaire/equality/addition correctness for n=4 and n=8, OT-call counts logged.
5. UI/API tests: endpoint contract tests and browser smoke tests for PA#0 routing, bottom proof panel, and all required interactive demo flows.

## Assumptions and Defaults
- Stack locked: Python-only core + local HTTP API + React frontend.
- Scope locked: all PA#0–#20 delivered as MVP in 4 days; toy parameters allowed for demos and attacks.
- Cryptographic strength is intentionally non-production for 4-day execution; hardening to real parameter sizes is a post-MVP phase.
- No external crypto libraries; only standard big-int arithmetic and OS randomness are used.
- If single-developer bandwidth is lower than full-time 4-day execution, fallback is to keep all PA endpoints/demos present but mark slower proofs/benchmarks as deferred with explicit TODO labels.
