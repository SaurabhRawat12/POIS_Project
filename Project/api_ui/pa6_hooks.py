"""PA #6 API-ready hooks for Encrypt-then-MAC CCA security."""

from __future__ import annotations

import os
from typing import Any

from primitives.pa4_modes import build_feistel_cipher
from primitives.pa5_mac import cbc_mac_tag, cbc_mac_verify
from primitives.pa6_cca_symmetric import (
    cca_enc,
    cca_dec,
    cpa_malleability_demo,
    cca_malleability_demo,
    ind_cca2_game,
    key_separation_demo,
)


def _read_bytes(payload: dict[str, Any], key: str, default: bytes | None = None) -> bytes:
    if f"{key}_hex" in payload:
        return bytes.fromhex(payload[f"{key}_hex"])
    if key in payload:
        value = payload[key]
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("utf-8")
    if default is None:
        raise ValueError(f"{key} is required")
    return default


def _toy_cpa_enc(key: bytes, message: bytes) -> tuple[bytes, bytes]:
    cipher = build_feistel_cipher(key)
    nonce = os.urandom(cipher.block_size)
    ct = bytearray()
    counter = int.from_bytes(nonce, "big")
    for block_index in range(0, len(message), cipher.block_size):
        block = message[block_index : block_index + cipher.block_size]
        stream = cipher.encrypt_block((counter + block_index // cipher.block_size).to_bytes(cipher.block_size, "big"))
        ct.extend(bytes(x ^ y for x, y in zip(block, stream[: len(block)])))
    return nonce, bytes(ct)


def _toy_cpa_dec(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = build_feistel_cipher(key)
    pt = bytearray()
    counter = int.from_bytes(nonce, "big")
    for block_index in range(0, len(ciphertext), cipher.block_size):
        block = ciphertext[block_index : block_index + cipher.block_size]
        stream = cipher.encrypt_block((counter + block_index // cipher.block_size).to_bytes(cipher.block_size, "big"))
        pt.extend(bytes(x ^ y for x, y in zip(block, stream[: len(block)])))
    return bytes(pt)


def pa6_cca_encrypt_hook(payload: dict[str, Any]) -> dict[str, Any]:
    key_enc = _read_bytes(payload, "key_enc")
    key_mac = _read_bytes(payload, "key_mac")
    message = _read_bytes(payload, "message")

    cipher = build_feistel_cipher(key_mac)
    blob, tag = cca_enc(
        key_enc,
        key_mac,
        message,
        cpa_enc=_toy_cpa_enc,
        mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16),
    )

    return {
        "pa_id": "PA-6",
        "result": {"ciphertext_hex": blob.hex(), "tag_hex": tag.hex()},
        "trace": {"scheme": "encrypt-then-mac"},
        "security_note": "Toy CPA/MAC used for demo; swap with PA#3/PA#5 for grading.",
    }


def pa6_cca_decrypt_hook(payload: dict[str, Any]) -> dict[str, Any]:
    key_enc = _read_bytes(payload, "key_enc")
    key_mac = _read_bytes(payload, "key_mac")
    ciphertext = _read_bytes(payload, "ciphertext")
    tag = _read_bytes(payload, "tag")

    cipher = build_feistel_cipher(key_mac)
    plaintext = cca_dec(
        key_enc,
        key_mac,
        ciphertext,
        tag,
        cpa_dec=_toy_cpa_dec,
        verify_fn=lambda k, m, t: cbc_mac_verify(k, m, t, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16),
        nonce_size=16,
    )

    return {
        "pa_id": "PA-6",
        "result": {"message_hex": None if plaintext is None else plaintext.hex()},
        "trace": {"scheme": "encrypt-then-mac"},
        "security_note": "Returns null on MAC failure; verify-before-decrypt enforced.",
    }


def pa6_cca_game_hook(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    rounds = int(payload.get("rounds", 20))

    result = ind_cca2_game(
        cpa_enc=_toy_cpa_enc,
        cpa_dec=_toy_cpa_dec,
        mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: build_feistel_cipher(k).encrypt_block(b), block_size=16),
        verify_fn=lambda k, m, t: cbc_mac_verify(k, m, t, block_cipher=lambda k2, b: build_feistel_cipher(k).encrypt_block(b), block_size=16),
        rounds=rounds,
        block_size=16,
    )

    return {
        "pa_id": "PA-6",
        "result": result,
        "trace": {"rounds": rounds},
        "security_note": "Naive adversary should have ~50% success.",
    }


def pa6_malleability_demo_hook(payload: dict[str, Any]) -> dict[str, Any]:
    key_enc = _read_bytes(payload, "key_enc")
    key_mac = _read_bytes(payload, "key_mac")
    message = _read_bytes(payload, "message")

    cpa_demo = cpa_malleability_demo(key_enc, message, cpa_enc=_toy_cpa_enc, cpa_dec=_toy_cpa_dec)
    cipher = build_feistel_cipher(key_mac)
    cca_demo = cca_malleability_demo(
        key_enc,
        key_mac,
        message,
        cpa_enc=_toy_cpa_enc,
        cpa_dec=_toy_cpa_dec,
        mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16),
        verify_fn=lambda k, m, t: cbc_mac_verify(k, m, t, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16),
        nonce_size=16,
    )

    return {
        "pa_id": "PA-6",
        "result": {"cpa": cpa_demo, "cca": cca_demo},
        "trace": {},
        "security_note": "CCA scheme rejects tampering that passes in CPA-only mode.",
    }


def pa6_key_separation_demo_hook(payload: dict[str, Any]) -> dict[str, Any]:
    key = _read_bytes(payload, "key")
    cipher = build_feistel_cipher(key)
    result = key_separation_demo(key, cpa_enc=_toy_cpa_enc, mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16))

    return {
        "pa_id": "PA-6",
        "result": result,
        "trace": {},
        "security_note": "Use independent keys for encryption and MAC.",
    }


try:
    from fastapi import APIRouter

    router = APIRouter(prefix="/demo/6", tags=["PA6"])

    @router.post("/encrypt")
    def encrypt_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa6_cca_encrypt_hook(payload)

    @router.post("/decrypt")
    def decrypt_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa6_cca_decrypt_hook(payload)

    @router.get("/cca-game")
    def cca_game_endpoint() -> dict[str, Any]:
        return pa6_cca_game_hook()

    @router.post("/malleability")
    def malleability_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa6_malleability_demo_hook(payload)

    @router.post("/key-separation")
    def key_sep_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa6_key_separation_demo_hook(payload)
except Exception:
    router = None
