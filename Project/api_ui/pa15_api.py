"""API-style handlers for PA #15 digital signatures."""

from __future__ import annotations

import random
from typing import Any, Dict

from primitives.pa12_rsa import rsa_keygen
from primitives.pa15_signatures import (
    PA_ID,
    euf_cma_game,
    multiplicative_forgery_demo,
    sign,
    verify,
)
from primitives.pa8_dlp_hash import DLPGroup


def sign_endpoint(
    message: str,
    bits: int = 512,
    q_bits: int = 31,
    seed: int | None = None,
) -> Dict[str, Any]:
    """Generate a fresh keypair, sign the message, and return everything."""
    rng = random.Random(seed) if seed is not None else None
    keys = rsa_keygen(bits=bits, rng=rng)
    group = DLPGroup.generate(q_bits=q_bits)

    msg_bytes = message.encode("utf-8")
    signature = sign(keys["private_key"], msg_bytes, group)

    return {
        "pa_id": PA_ID,
        "result": {
            "public_key": keys["public_key"],
            "private_key": keys["private_key"],
            "group": group.to_dict(),
            "message": message,
            "signature": signature["signature"],
            "hashed_message": signature["hashed_message"],
        },
    }


def verify_endpoint(
    message: str,
    signature: int,
    public_key: Dict[str, Any],
    group_params: Dict[str, Any],
) -> Dict[str, Any]:
    """Verify a signature given pk, the message, and the group used to hash."""
    group = DLPGroup(
        p=int(group_params["p"]),
        q=int(group_params["q"]),
        g=int(group_params["g"]),
        h_gen=int(group_params["h_gen"]),
        p_byte_len=int(group_params["p_byte_len"]),
        q_byte_len=int(group_params["q_byte_len"]),
    )
    msg_bytes = message.encode("utf-8")
    result = verify(public_key, msg_bytes, signature, group)
    return {"pa_id": PA_ID, "result": result}


def multiplicative_forgery_endpoint(
    bits: int = 512, seed: int | None = None
) -> Dict[str, Any]:
    """Run the textbook multiplicative-forgery attack on raw (unhashed) RSA."""
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": multiplicative_forgery_demo(bits=bits, rng=rng),
    }


def euf_cma_endpoint(
    queries: int = 50,
    bits: int = 512,
    q_bits: int = 31,
    seed: int | None = None,
) -> Dict[str, Any]:
    """Run the EUF-CMA security game on hash-then-sign."""
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": euf_cma_game(
            queries=queries, bits=bits, q_bits=q_bits, rng=rng
        ),
    }
