"""API-style handlers for PA #12 RSA functionality."""

from __future__ import annotations

from typing import Any, Dict

from primitives.pa12_rsa import (
    PA_ID,
    pkcs15_dec,
    pkcs15_enc,
    rsa_dec,
    rsa_determinism_demo,
    rsa_enc,
    rsa_keygen,
)


def rsa_keygen_endpoint(bits: int = 2048, e: int = 65537, k: int = 40) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": rsa_keygen(bits=bits, e=e, k=k)}


def rsa_roundtrip_endpoint(message_int: int, bits: int = 1024) -> Dict[str, Any]:
    keys = rsa_keygen(bits=bits)
    pk = keys["public_key"]
    sk = keys["private_key"]
    cipher = rsa_enc(pk, message_int)
    plain = rsa_dec(sk, cipher)
    return {
        "pa_id": PA_ID,
        "result": {
            "ciphertext": cipher,
            "plaintext": plain,
            "roundtrip_ok": plain == message_int,
        },
    }


def pkcs15_roundtrip_endpoint(message: bytes, bits: int = 1024) -> Dict[str, Any]:
    keys = rsa_keygen(bits=bits)
    pk = keys["public_key"]
    sk = keys["private_key"]
    cipher = pkcs15_enc(pk, message)
    plain = pkcs15_dec(sk, cipher)
    return {
        "pa_id": PA_ID,
        "result": {"ciphertext": cipher, "plaintext": plain, "roundtrip_ok": plain == message},
    }


def rsa_determinism_demo_endpoint(message: bytes = b"yes", bits: int = 512) -> Dict[str, Any]:
    return {"pa_id": PA_ID, "result": rsa_determinism_demo(message=message, bits=bits)}

