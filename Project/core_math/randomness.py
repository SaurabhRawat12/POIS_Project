"""Randomness helpers for deterministic/non-deterministic crypto experiments."""

from __future__ import annotations

import random
import secrets


def system_rng() -> random.Random:
    return secrets.SystemRandom()


def sample_odd_candidate(bits: int, rng: random.Random | None = None) -> int:
    """Sample an odd integer with exact bit length."""
    if bits < 2:
        raise ValueError("bits must be >= 2")

    active_rng = rng or system_rng()
    candidate = active_rng.getrandbits(bits)
    candidate |= 1 << (bits - 1)  # force top bit
    candidate |= 1  # force odd
    return candidate

