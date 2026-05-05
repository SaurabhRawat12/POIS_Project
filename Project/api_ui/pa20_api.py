"""API-style handlers for PA #20 secure 2-party computation."""

from __future__ import annotations

import random
from typing import Any, Dict

from protocols.pa20_mpc import (
    PA_ID,
    benchmark_8bit,
    lineage_trace,
    run_addition,
    run_equality,
    run_millionaire,
)


def equality_endpoint(
    x: int, y: int, n: int = 8, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": run_equality(x, y, n=n, rng=rng)}


def addition_endpoint(
    x: int, y: int, n: int = 8, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": run_addition(x, y, n=n, rng=rng)}


def millionaire_endpoint(
    x: int, y: int, n: int = 8, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": run_millionaire(x, y, n=n, rng=rng)}


def benchmark_endpoint(seed: int | None = None) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": benchmark_8bit(rng=rng)}


def lineage_endpoint() -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": lineage_trace()}
