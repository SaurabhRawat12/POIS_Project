"""API-style handlers for PA #14 functionality."""

from __future__ import annotations

import random
from typing import Any, Dict, Sequence

from primitives.pa12_rsa import pkcs15_enc, rsa_enc, rsa_keygen
from primitives.pa14_crt_hastad import (
    PA_ID,
    crt,
    hastad_attack_verbose,
    rsa_dec_crt,
)


def crt_endpoint(residues: Sequence[int], moduli: Sequence[int]) -> Dict[str, Any]:
    x = crt(residues, moduli)
    return {"pa_id": PA_ID, "result": {"x": x}}


def rsa_dec_crt_endpoint(sk: Dict[str, Any], ciphertext: int) -> Dict[str, Any]:
    m = rsa_dec_crt(sk, ciphertext)
    return {"pa_id": PA_ID, "result": {"plaintext": m}}


def hastad_demo_endpoint(
    message_int: int,
    bits: int = 192,
    e: int = 3,
    use_pkcs15: bool = False,
    k: int = 12,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    active_rng = rng or random.Random()
    keys = [rsa_keygen(bits=bits, e=e, k=k, rng=active_rng) for _ in range(e)]
    pks = [k["public_key"] for k in keys]
    moduli = [pk["N"] for pk in pks]

    if use_pkcs15:
        message = message_int.to_bytes(max(1, (message_int.bit_length() + 7) // 8), "big")
        ciphertexts = [pkcs15_enc(pk, message, rng=active_rng) for pk in pks]
    else:
        ciphertexts = [rsa_enc(pk, message_int) for pk in pks]

    attack = hastad_attack_verbose(ciphertexts, moduli, e)
    return {
        "pa_id": PA_ID,
        "result": {
            "ciphertexts": ciphertexts,
            "moduli": moduli,
            "attack": attack,
            "use_pkcs15": use_pkcs15,
        },
    }
