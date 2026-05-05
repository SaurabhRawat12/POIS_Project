"""Framework-agnostic API handlers for PA #13."""

from __future__ import annotations

from typing import Any, Dict

from primitives.pa13_primality import PA_ID, gen_prime, gen_safe_prime, miller_rabin


def primality_check_endpoint(n: int, k: int = 40, trace: bool = False) -> Dict[str, Any]:
    """
    Endpoint-style response for primality checks.

    This function is framework-agnostic so it can be wired into FastAPI/Flask later.
    """
    result = miller_rabin(n=n, k=k, trace=trace)
    status = "PRIME" if result["is_probably_prime"] else "COMPOSITE"
    return {
        "pa_id": PA_ID,
        "status": status,
        "elapsed_ms": result["elapsed_ms"],
        "rounds_executed": result["rounds_executed"],
        "trace": result["trace"],
        "details": result,
    }


def prime_generation_endpoint(
    bits: int, k: int = 40, require_safe: bool = False
) -> Dict[str, Any]:
    """Endpoint-style response for prime generation."""
    if require_safe:
        result = gen_safe_prime(q_bits=bits - 1, k=k)
        return {
            "pa_id": PA_ID,
            "status": "SAFE_PRIME_GENERATED",
            "result": result,
        }

    result = gen_prime(bits=bits, k=k, require_safe=False)
    return {
        "pa_id": PA_ID,
        "status": "PRIME_GENERATED",
        "result": result,
    }

