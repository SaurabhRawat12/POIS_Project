"""PA #5 API-ready hooks for MACs."""

from __future__ import annotations

import os
from typing import Any

from primitives.pa4_modes import build_feistel_cipher
from primitives.pa5_mac import (
    cbc_mac_tag,
    cbc_mac_verify,
    euf_cma_game,
    length_extension_demo,
    mac_prf_distinguish_demo,
    prf_mac_tag,
    prf_mac_verify,
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


def pa5_mac_hook(payload: dict[str, Any]) -> dict[str, Any]:
    scheme = payload.get("scheme", "prf")
    key = _read_bytes(payload, "key", default=os.urandom(16))
    message = _read_bytes(payload, "message", default=b"")
    block_size = int(payload.get("block_size", 16))

    if scheme.lower() == "prf":
        tag = prf_mac_tag(key, message, block_size=block_size)
    else:
        cipher = build_feistel_cipher(key, block_size=block_size)
        tag = cbc_mac_tag(key, message, block_cipher=lambda k, b: cipher.encrypt_block(b), block_size=block_size)

    return {
        "pa_id": "PA-5",
        "result": {"tag_hex": tag.hex()},
        "trace": {"scheme": scheme, "block_size": block_size},
        "security_note": "Toy PRF/cipher used for demo; swap with PA#2 for grading.",
    }


def pa5_verify_hook(payload: dict[str, Any]) -> dict[str, Any]:
    scheme = payload.get("scheme", "prf")
    key = _read_bytes(payload, "key")
    message = _read_bytes(payload, "message")
    tag = _read_bytes(payload, "tag")
    block_size = int(payload.get("block_size", 16))

    if scheme.lower() == "prf":
        ok = prf_mac_verify(key, message, tag, block_size=block_size)
    else:
        cipher = build_feistel_cipher(key, block_size=block_size)
        ok = cbc_mac_verify(key, message, tag, block_cipher=lambda k, b: cipher.encrypt_block(b), block_size=block_size)

    return {
        "pa_id": "PA-5",
        "result": {"valid": ok},
        "trace": {"scheme": scheme, "block_size": block_size},
        "security_note": "Toy PRF/cipher used for demo; swap with PA#2 for grading.",
    }


def pa5_euf_cma_demo_hook(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    block_size = int(payload.get("block_size", 16))
    key = os.urandom(block_size)

    result = euf_cma_game(
        key,
        mac_fn=lambda k, m: prf_mac_tag(k, m, block_size=block_size),
        verify_fn=lambda k, m, t: prf_mac_verify(k, m, t, block_size=block_size),
        block_size=block_size,
    )

    return {
        "pa_id": "PA-5",
        "result": result,
        "trace": {"scheme": "prf", "block_size": block_size},
        "security_note": "Naive adversary should not forge a tag; successes should be 0.",
    }


def pa5_length_extension_demo_hook(payload: dict[str, Any]) -> dict[str, Any]:
    # Provide sensible defaults so the demo works with an empty payload
    default_key = b"mysecretkey12345"  # 16-byte key
    default_message = b"Hello World!!!!"  # 15 bytes (pad to 16)
    default_suffix = b"extra_data______"  # 16 bytes
    block_size = int(payload.get("block_size", 16))

    key = _read_bytes(payload, "key", default=default_key)
    message = _read_bytes(payload, "message", default=default_message)
    suffix = _read_bytes(payload, "suffix", default=default_suffix)

    result = length_extension_demo(key, message, suffix, block_size=block_size)

    return {
        "pa_id": "PA-5",
        "result": result,
        "trace": {"block_size": block_size},
        "security_note": "Demonstrates why HMAC uses a double hash structure.",
    }


def pa5_prf_distinguish_demo_hook(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    block_size = int(payload.get("block_size", 16))
    key = os.urandom(block_size)
    result = mac_prf_distinguish_demo(key, block_size=block_size)

    return {
        "pa_id": "PA-5",
        "result": result,
        "trace": {"queries": result["queries"], "block_size": block_size},
        "security_note": "PRF-MAC outputs should appear pseudorandom at toy scale.",
    }


try:
    from fastapi import APIRouter

    router = APIRouter(prefix="/demo/5", tags=["PA5"])

    @router.post("/tag")
    def tag_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa5_mac_hook(payload)

    @router.post("/verify")
    def verify_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa5_verify_hook(payload)

    @router.get("/euf-cma")
    def euf_cma_endpoint() -> dict[str, Any]:
        return pa5_euf_cma_demo_hook()

    @router.post("/length-extension")
    def length_extension_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa5_length_extension_demo_hook(payload)

    @router.get("/prf-distinguish")
    def prf_distinguish_endpoint() -> dict[str, Any]:
        return pa5_prf_distinguish_demo_hook()
except Exception:
    router = None
