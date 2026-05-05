"""API-style handlers for PA #11 DH functionality."""

from __future__ import annotations

from typing import Any, Dict

from primitives.pa11_diffie_hellman import (
    PA_ID,
    dh_alice_step1,
    dh_bob_step1,
    dh_generate_group,
    dh_alice_step2,
    dh_bob_step2,
    mitm_demo,
)


def dh_group_endpoint(q_bits: int = 255, k: int = 40) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": dh_generate_group(q_bits=q_bits, k=k)}


def dh_exchange_endpoint(params: Dict[str, int]) -> Dict[str, Any]:
    alice = dh_alice_step1(params)
    bob = dh_bob_step1(params)
    alice_secret = dh_alice_step2(alice["a"], bob["B"], params)
    bob_secret = dh_bob_step2(bob["b"], alice["A"], params)
    return {
        "pa_id": PA_ID,
        "result": {
            "alice_public": alice["A"],
            "bob_public": bob["B"],
            "alice_secret": alice_secret,
            "bob_secret": bob_secret,
            "shared_secret_match": alice_secret == bob_secret,
        },
    }


def dh_mitm_demo_endpoint(params: Dict[str, int] | None = None) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": mitm_demo(params=params)}

