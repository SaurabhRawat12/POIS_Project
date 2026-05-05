"""API-style handlers for PA #17 CCA-secure PKC."""

from __future__ import annotations

import random
from typing import Any, Dict

from primitives.pa8_dlp_hash import DLPGroup
from protocols.pa17_cca_pkc import (
    PA_ID,
    cca_pkc_dec,
    cca_pkc_enc,
    ind_cca2_game,
    lineage_trace,
    malleability_blocked_demo,
    pkc_keygen,
)


def _group_from_dict(group_dict: Dict[str, Any]) -> DLPGroup:
    return DLPGroup(
        p=int(group_dict["p"]),
        q=int(group_dict["q"]),
        g=int(group_dict["g"]),
        h_gen=int(group_dict["h_gen"]),
        p_byte_len=int(group_dict["p_byte_len"]),
        q_byte_len=int(group_dict["q_byte_len"]),
    )


def keygen_endpoint(
    elgamal_q_bits: int = 63,
    rsa_bits: int = 512,
    hash_q_bits: int = 31,
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    keys = pkc_keygen(
        elgamal_q_bits=elgamal_q_bits,
        rsa_bits=rsa_bits,
        hash_q_bits=hash_q_bits,
        rng=rng,
    )
    # Convert hash_group to a JSON-friendly dict for the React layer.
    return {
        "pa_id": PA_ID,
        "result": {
            "encryption_pk": keys["encryption_pk"],
            "encryption_sk": keys["encryption_sk"],
            "signing_sk": keys["signing_sk"],
            "verification_vk": keys["verification_vk"],
            "hash_group": keys["hash_group"].to_dict(),
            "lineage": keys["lineage"],
        },
    }


def encrypt_endpoint(
    pk_enc: Dict[str, Any],
    sk_sign: Dict[str, Any],
    message: int,
    hash_group: Dict[str, Any],
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    group = _group_from_dict(hash_group)
    return {
        "pa_id": PA_ID,
        "result": cca_pkc_enc(pk_enc, sk_sign, message, group, rng=rng),
    }


def decrypt_endpoint(
    sk_enc: Dict[str, Any],
    pk_enc: Dict[str, Any],
    vk_sign: Dict[str, Any],
    CE: Dict[str, int],
    sigma: int,
    hash_group: Dict[str, Any],
) -> Dict[str, Any]:
    group = _group_from_dict(hash_group)
    return {
        "pa_id": PA_ID,
        "result": cca_pkc_dec(sk_enc, pk_enc, vk_sign, CE, sigma, group),
    }


def malleability_blocked_endpoint(
    message: int | None = None,
    factor: int = 2,
    elgamal_q_bits: int = 63,
    rsa_bits: int = 512,
    hash_q_bits: int = 31,
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": malleability_blocked_demo(
            message=message,
            factor=factor,
            elgamal_q_bits=elgamal_q_bits,
            rsa_bits=rsa_bits,
            hash_q_bits=hash_q_bits,
            rng=rng,
        ),
    }


def ind_cca2_endpoint(
    rounds: int = 20,
    elgamal_q_bits: int = 63,
    rsa_bits: int = 512,
    hash_q_bits: int = 31,
    seed: int | None = None,
) -> Dict[str, Any]:
    rng = random.Random(seed) if seed is not None else None
    return {
        "pa_id": PA_ID,
        "result": ind_cca2_game(
            rounds=rounds,
            elgamal_q_bits=elgamal_q_bits,
            rsa_bits=rsa_bits,
            hash_q_bits=hash_q_bits,
            rng=rng,
        ),
    }


def lineage_endpoint() -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": lineage_trace()}
