"""PA #13 primitive: Miller-Rabin primality testing and prime generation."""

from __future__ import annotations

import math
import random
import time
from typing import Any, Dict, Iterable, List, Tuple

from core_math.number_theory import decompose, modexp
from core_math.randomness import sample_odd_candidate, system_rng

PA_ID = "PA#13"
STATUS_COMPOSITE = "COMPOSITE"
STATUS_PROBABLY_PRIME = "PROBABLY_PRIME"

_SMALL_PRIMES: Tuple[int, ...] = (
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
)


def fermat_primality(
    n: int, bases: Iterable[int] = (2,), *, strict_coprime: bool = False
) -> Dict[str, Any]:
    """Simple Fermat primality check used for Carmichael demo output."""
    tested_bases: List[Dict[str, Any]] = []
    if n < 2:
        return {
            "n": n,
            "result": STATUS_COMPOSITE,
            "tested_bases": tested_bases,
            "reason": "n < 2",
        }

    for a in bases:
        record: Dict[str, Any] = {"base": a}
        if a <= 1 or a >= n:
            record["skipped"] = "base outside (1, n)"
            tested_bases.append(record)
            continue

        g = math.gcd(a, n)
        record["gcd"] = g
        if g != 1:
            record["result"] = STATUS_COMPOSITE
            record["reason"] = "gcd(base, n) != 1"
            tested_bases.append(record)
            if strict_coprime:
                return {
                    "n": n,
                    "result": STATUS_COMPOSITE,
                    "tested_bases": tested_bases,
                    "reason": "non-coprime base found",
                }
            continue

        residue = modexp(a, n - 1, n)
        record["a^(n-1) mod n"] = residue
        if residue != 1:
            record["result"] = STATUS_COMPOSITE
            tested_bases.append(record)
            return {
                "n": n,
                "result": STATUS_COMPOSITE,
                "tested_bases": tested_bases,
                "reason": "Fermat witness found",
            }

        record["result"] = STATUS_PROBABLY_PRIME
        tested_bases.append(record)

    return {
        "n": n,
        "result": STATUS_PROBABLY_PRIME,
        "tested_bases": tested_bases,
        "reason": "all tested coprime bases passed",
    }


def miller_rabin(
    n: int, k: int = 40, trace: bool = False, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    """
    Miller-Rabin primality testing.

    Returns a dict with stable schema for CLI/API/UI integration.
    """
    if k <= 0:
        raise ValueError("k must be >= 1")

    start = time.perf_counter()
    active_rng = rng or system_rng()
    rounds: List[Dict[str, Any]] = []

    def build_response(
        result: str,
        is_probably_prime: bool,
        reason: str,
        rounds_executed: int,
        witness: int | None = None,
        decomp: Dict[str, int] | None = None,
    ) -> Dict[str, Any]:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        response = {
            "pa_id": PA_ID,
            "algorithm": "Miller-Rabin",
            "n": n,
            "k": k,
            "result": result,
            "is_probably_prime": is_probably_prime,
            "rounds_executed": rounds_executed,
            "witness": witness,
            "decomposition": decomp,
            "reason": reason,
            "elapsed_ms": elapsed_ms,
            "trace": rounds if trace else [],
        }
        return response

    if n < 2:
        return build_response(
            STATUS_COMPOSITE,
            False,
            reason="n < 2",
            rounds_executed=0,
        )
    if n in (2, 3):
        return build_response(
            STATUS_PROBABLY_PRIME,
            True,
            reason="n is a small prime",
            rounds_executed=0,
        )
    if n % 2 == 0:
        return build_response(
            STATUS_COMPOSITE,
            False,
            reason="n is even",
            rounds_executed=0,
        )

    if n in _SMALL_PRIMES:
        return build_response(
            STATUS_PROBABLY_PRIME,
            True,
            reason="n equals small prime",
            rounds_executed=0,
        )

    s, d = decompose(n - 1)
    decomposition = {"s": s, "d": d}

    for i in range(1, k + 1):
        a = active_rng.randrange(2, n - 1)  # [2, n-2]
        x = modexp(a, d, n)

        round_record: Dict[str, Any] = {
            "round": i,
            "witness": a,
            "x0": x,
            "squarings": [],
        }

        if x == 1 or x == n - 1:
            round_record["outcome"] = "inconclusive"
            if trace:
                rounds.append(round_record)
            continue

        composite_round = True
        for r in range(1, s):
            x = (x * x) % n
            step_record = {"step": r, "x": x}
            round_record["squarings"].append(step_record)

            if x == n - 1:
                composite_round = False
                break
            if x == 1:
                composite_round = True
                break

        if composite_round:
            round_record["outcome"] = "composite"
            if trace:
                rounds.append(round_record)
            return build_response(
                STATUS_COMPOSITE,
                False,
                reason=f"witness {a} proves compositeness",
                rounds_executed=i,
                witness=a,
                decomp=decomposition,
            )

        round_record["outcome"] = "inconclusive"
        if trace:
            rounds.append(round_record)

    return build_response(
        STATUS_PROBABLY_PRIME,
        True,
        reason=f"no witness found in {k} rounds",
        rounds_executed=k,
        decomp=decomposition,
    )


def is_prime(n: int, k: int = 40, *, rng: random.Random | None = None) -> bool:
    """Convenience wrapper around miller_rabin."""
    result = miller_rabin(n, k=k, trace=False, rng=rng)
    return bool(result["is_probably_prime"])


def gen_prime(
    bits: int,
    k: int = 40,
    require_safe: bool = False,
    *,
    sanity_rounds: int = 100,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Generate a probable prime of `bits` bit length."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    if k <= 0:
        raise ValueError("k must be >= 1")
    if sanity_rounds < 0:
        raise ValueError("sanity_rounds must be >= 0")

    active_rng = rng or system_rng()
    start = time.perf_counter()
    attempts = 0
    prime = 0
    q_value: int | None = None

    while True:
        attempts += 1
        if require_safe:
            q_candidate = sample_odd_candidate(bits - 1, active_rng)
            if not is_prime(q_candidate, k=k, rng=active_rng):
                continue

            p_candidate = 2 * q_candidate + 1
            if p_candidate.bit_length() != bits:
                continue
            if not is_prime(p_candidate, k=k, rng=active_rng):
                continue

            prime = p_candidate
            q_value = q_candidate
            break

        candidate = sample_odd_candidate(bits, active_rng)
        if is_prime(candidate, k=k, rng=active_rng):
            prime = candidate
            break

    sanity_passed = True
    if sanity_rounds > 0:
        sanity_passed = is_prime(prime, k=sanity_rounds, rng=active_rng)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return {
        "pa_id": PA_ID,
        "algorithm": "PrimeGeneration",
        "prime": prime,
        "bits": bits,
        "attempts": attempts,
        "k_used": k,
        "require_safe": require_safe,
        "q": q_value,
        "sanity_rounds": sanity_rounds,
        "sanity_passed": sanity_passed,
        "elapsed_ms": elapsed_ms,
    }


def gen_safe_prime(
    q_bits: int,
    k: int = 40,
    *,
    sanity_rounds: int = 100,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """
    Generate q (q_bits) and p=2q+1 probable primes for DH-safe groups.
    """
    if q_bits < 2:
        raise ValueError("q_bits must be >= 2")

    result = gen_prime(
        bits=q_bits + 1,
        k=k,
        require_safe=True,
        sanity_rounds=sanity_rounds,
        rng=rng,
    )
    q_val = result["q"]
    if q_val is None:
        raise RuntimeError("safe prime generation did not produce q")

    return {
        "pa_id": PA_ID,
        "algorithm": "SafePrimeGeneration",
        "p": result["prime"],
        "q": q_val,
        "p_bits": result["bits"],
        "q_bits": q_bits,
        "attempts": result["attempts"],
        "k_used": result["k_used"],
        "sanity_rounds": result["sanity_rounds"],
        "sanity_passed": result["sanity_passed"],
        "elapsed_ms": result["elapsed_ms"],
    }

