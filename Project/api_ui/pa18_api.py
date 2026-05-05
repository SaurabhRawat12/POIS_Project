"""API-style handlers for PA #18 oblivious transfer."""

from __future__ import annotations

import random
from typing import Any, Dict

from primitives.pa18_oblivious_transfer import (
    PA_ID,
    ot_receiver_step1,
    ot_receiver_step2,
    ot_run,
    ot_sender_step,
    ot_setup,
    receiver_privacy_demo,
    sender_privacy_demo,
)


def ot_setup_endpoint(q_bits: int = 63, k: int = 20, seed: int | None = None) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": ot_setup(q_bits=q_bits, k=k, rng=rng)}


def ot_receiver_step1_endpoint(
    b: int, params: Dict[str, Any], seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": ot_receiver_step1(b, params, rng=rng)}


def ot_sender_step_endpoint(
    params: Dict[str, Any],
    pk_0: int,
    pk_1: int,
    m_0: int,
    m_1: int,
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": ot_sender_step(params, pk_0, pk_1, m_0, m_1, rng=rng),
    }


def ot_receiver_step2_endpoint(
    state: Dict[str, Any],
    params: Dict[str, Any],
    C_0: Dict[str, int],
    C_1: Dict[str, int],
) -> Dict[str, Any]:
    return {
        "pa_id": PA_ID,
        "result": ot_receiver_step2(state, params, C_0, C_1),
    }


def ot_run_endpoint(
    b: int, m_0: int, m_1: int, q_bits: int = 63, k: int = 20, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": ot_run(b, m_0, m_1, q_bits=q_bits, k=k, rng=rng)}


def receiver_privacy_endpoint(
    q_bits: int = 63, k: int = 20, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": receiver_privacy_demo(q_bits=q_bits, k=k, rng=rng)}


def sender_privacy_endpoint(
    q_bits: int = 63, k: int = 20, seed: int | None = None
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {"pa_id": PA_ID, "result": sender_privacy_demo(q_bits=q_bits, k=k, rng=rng)}
