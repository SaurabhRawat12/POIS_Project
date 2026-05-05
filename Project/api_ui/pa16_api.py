"""API-style handlers for PA #16 ElGamal functionality."""

from __future__ import annotations

import random
from typing import Any, Dict

from primitives.pa16_elgamal import (
    PA_ID,
    elgamal_dec,
    elgamal_enc,
    elgamal_ind_cpa_game,
    elgamal_keygen,
    malleability_demo,
)


def elgamal_keygen_endpoint(q_bits: int = 255, k: int = 40) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": elgamal_keygen(q_bits=q_bits, k=k)}


def elgamal_roundtrip_endpoint(message_int: int, q_bits: int = 63, k: int = 20) -> Dict[str, Any]:
    keys = elgamal_keygen(q_bits=q_bits, k=k)
    pk = keys["public_key"]
    sk = keys["private_key"]
    c = elgamal_enc(pk, message_int)
    m = elgamal_dec(sk, pk, c["c1"], c["c2"])
    return {
        "pa_id": PA_ID,
        "result": {
            "ciphertext": {"c1": c["c1"], "c2": c["c2"]},
            "plaintext": m,
            "roundtrip_ok": m == message_int,
        },
    }


def elgamal_malleability_demo_endpoint(
    message: int | None = None, factor: int = 2, q_bits: int = 31, k: int = 20
) -> Dict[str, Any]:
    return {
        "pa_id": PA_ID,
        "result": malleability_demo(message=message, factor=factor, q_bits=q_bits, k=k),
    }


def elgamal_ind_cpa_endpoint(
    rounds: int = 50,
    q_bits: int = 31,
    k: int = 20,
    strategy: str = "random",
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": elgamal_ind_cpa_game(
            rounds=rounds, q_bits=q_bits, k=k, strategy=strategy, rng=rng
        ),
    }

