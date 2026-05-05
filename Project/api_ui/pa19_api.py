"""API-style handlers for PA #19 secure gates."""

from __future__ import annotations

import random
from typing import Any, Dict

from protocols.pa19_secure_gates import (
    PA_ID,
    privacy_demo,
    secure_and,
    secure_not,
    secure_xor,
    truth_table_demo,
)


def secure_and_endpoint(
    a: int, b: int, q_bits: int = 63, k: int = 20, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": secure_and(a, b, q_bits=q_bits, k=k, rng=rng)}


def secure_xor_endpoint(a: int, b: int) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": secure_xor(a, b)}


def secure_not_endpoint(a: int) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": secure_not(a)}


def truth_table_endpoint(
    runs_per_combo: int = 50,
    q_bits: int = 63,
    k: int = 20,
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": truth_table_demo(
            runs_per_combo=runs_per_combo, q_bits=q_bits, k=k, rng=rng
        ),
    }


def privacy_endpoint(
    q_bits: int = 63, k: int = 20, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": privacy_demo(q_bits=q_bits, k=k, rng=rng)}
