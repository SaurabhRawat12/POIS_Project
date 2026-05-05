# PA #13: Miller-Rabin + Prime Generation

This module implements the PA #13 foundation for:
- PA #11 Diffie-Hellman safe-prime parameter generation
- PA #12 RSA prime generation

## Subsystem Layout (aligned with `PLAN.md`)

- `core_math/`: reusable math and randomness helpers
- `primitives/`: PA #13 primality/prime-generation implementation
- `api_ui/`: endpoint-style handlers for UI/backend integration
- `protocols/`, `attacks/`, `trace_lineage/`: scaffolded subsystem roots for upcoming PAs

## Public API (Stable Schema)

```python
from primitives.pa13_primality import miller_rabin, is_prime, gen_prime, gen_safe_prime
```

### `miller_rabin(n: int, k: int = 40, trace: bool = False) -> dict`

Returns:
- `result`: `PROBABLY_PRIME` or `COMPOSITE`
- `is_probably_prime`: `bool`
- `rounds_executed`: rounds run
- `witness`: witness value when composite (or `None`)
- `decomposition`: `{s, d}` for `n-1 = 2^s * d`
- `elapsed_ms`: runtime
- `trace`: round-by-round witness/squaring details if `trace=True`

### `is_prime(n: int, k: int = 40) -> bool`

Convenience wrapper over Miller-Rabin.

### `gen_prime(bits: int, k: int = 40, require_safe: bool = False) -> dict`

Returns:
- `prime`, `bits`, `attempts`, `k_used`, `elapsed_ms`
- `require_safe`, `q` (for safe-prime mode)
- `sanity_rounds`, `sanity_passed`

### `gen_safe_prime(q_bits: int, k: int = 40) -> dict`

Returns:
- `q` with `q_bits`
- `p = 2q + 1`
- attempts/timing/sanity metadata

## CLI

```bash
python3 scripts/pa13_cli.py check --n 561 --k 10 --trace
python3 scripts/pa13_cli.py generate --bits 512 --k 40
python3 scripts/pa13_cli.py generate --bits 512 --k 40 --safe
python3 scripts/pa13_cli.py carmichael --k 10 --trace
python3 scripts/pa13_cli.py benchmark --bit-sizes 512,1024,2048 --trials 1 --k 40
```

## Demo/Artifact Scripts

```bash
python scripts/pa13_carmichael_demo.py --k 10 --trace
python scripts/pa13_benchmark.py --bit-sizes 512,1024,2048 --trials 1 --k 40
```

Artifacts are written to `artifacts/` as JSON and CSV.

## Teammate Integration Contract

- **PA #11** should consume `gen_safe_prime(q_bits, k)` (or `gen_prime(..., require_safe=True)`).
- **PA #12** should consume `gen_prime(bits // 2, k)` and `is_prime(n, k)`.
- Return keys above are now treated as stable schema to avoid cross-team merge breaks.

## Tests

```bash
python -m unittest discover -s tests -p "test_pa13.py" -v
```

Includes:
- math utility tests (`modexp`, `egcd`, `mod_inverse`, `decompose`)
- Miller-Rabin curated cases, Carmichael numbers (`561`, `1105`, `1729`)
- deterministic seed mode checks
- benchmark artifact generation smoke test
