"""Framework-agnostic API handlers for PA #9 -- Birthday Attack."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from attacks.pa9_birthday_attack import (
    PA_ID,
    _make_toy_hash_fn,
    attack_truncated_dlp_hash,
    birthday_attack,
    birthday_trials,
    empirical_birthday_curve,
    floyd_cycle_attack,
    md5_sha1_context,
)


def naive_birthday_endpoint(
    n: int,
    max_trials: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the naive (dict-based) birthday attack on a toy n-bit hash.

    Returns the colliding pair, hash value, and evaluation count.
    """
    hash_fn = _make_toy_hash_fn(n)
    return {
        "pa_id": PA_ID,
        "result": birthday_attack(hash_fn=hash_fn, n=n, max_trials=max_trials),
    }


def floyd_birthday_endpoint(
    n: int,
    max_steps: Optional[int] = None,
) -> Dict[str, Any]:
    """Run Floyd's cycle-finding birthday attack on a toy n-bit hash.

    Space-efficient O(1) variant of the same attack.
    """
    hash_fn = _make_toy_hash_fn(n)
    return {
        "pa_id": PA_ID,
        "result": floyd_cycle_attack(hash_fn=hash_fn, n=n, max_steps=max_steps),
    }


def attack_dlp_hash_endpoint(
    n: int = 16,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Attack PA #8's DLP hash truncated to n bits.

    Concretely shows that even a provably-secure hash is broken at
    the birthday bound when its output is too short.
    """
    return {
        "pa_id": PA_ID,
        "result": attack_truncated_dlp_hash(n=n, q_bits=q_bits),
    }


def birthday_trials_endpoint(
    n: int,
    trials: int = 100,
) -> Dict[str, Any]:
    """Run multiple birthday experiments at output size n.

    Returns the full distribution of collision-finding times across trials.
    """
    return {
        "pa_id": PA_ID,
        "result": birthday_trials(n=n, trials=trials),
    }


def birthday_curve_endpoint(
    n_values: Optional[List[int]] = None,
    trials: int = 50,
) -> Dict[str, Any]:
    """Run birthday experiments at multiple n values plus theoretical curves.

    Default n_values = [8, 10, 12, 14, 16]. Returns empirical evaluation
    counts AND the theoretical curve P(collision) = 1 - exp(-k(k-1) / 2^(n+1))
    for each n.
    """
    return {
        "pa_id": PA_ID,
        "result": empirical_birthday_curve(n_values=n_values, trials=trials),
    }


def md5_sha1_context_endpoint() -> Dict[str, Any]:
    """Birthday-bound analysis for MD5, SHA-1, and SHA-256.

    Returns 2^(n/2) for each, time at 10^9 hashes/sec, and security status.
    """
    return {
        "pa_id": PA_ID,
        "result": md5_sha1_context(),
    }