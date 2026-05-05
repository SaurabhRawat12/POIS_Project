"""PA #7 API-ready hooks.

These functions are JSON-friendly and can be mounted into a local HTTP layer.
"""

from __future__ import annotations

from typing import Any

from primitives.pa7_merkle_damgard import (
    collision_propagation_demo,
    get_pa7_hash_interface,
)


def _read_message(payload: dict[str, Any]) -> bytes:
    """Accept either UTF-8 text (`message`) or hex (`message_hex`)."""

    if "message_hex" in payload:
        return bytes.fromhex(payload["message_hex"])

    message = payload.get("message", "")
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, bytes):
        return message

    raise TypeError("message must be str or bytes")


def pa7_md_hash_hook(payload: dict[str, Any]) -> dict[str, Any]:
    """Demo/API hook: hash a message through the PA #7 stable interface."""

    block_size = int(payload.get("block_size", 16))
    digest_size = int(payload.get("digest_size", 2))

    contract, hash_fn = get_pa7_hash_interface(block_size=block_size, digest_size=digest_size)
    msg = _read_message(payload)
    digest = hash_fn(msg)

    return {
        "pa_id": "PA-7",
        "result": {
            "hash_hex": digest.hex(),
            "contract": {
                "name": contract.name,
                "block_size": contract.block_size,
                "digest_size": contract.digest_size,
            },
        },
        "trace": {
            "message_len": len(msg),
            "message_hex": msg.hex(),
            "mode": "toy-md",
        },
        "security_note": "Toy Merkle-Damgard demo only; not production-secure.",
    }


def pa7_collision_demo_hook(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Demo/API hook: show collision propagation in Merkle-Damgard."""

    payload = payload or {}
    suffix = payload.get("suffix", "shared-suffix")
    block_size = int(payload.get("block_size", 16))
    digest_size = int(payload.get("digest_size", 2))

    demo = collision_propagation_demo(
        suffix=suffix,
        block_size=block_size,
        digest_size=digest_size,
    )

    return {
        "pa_id": "PA-7",
        "result": demo,
        "trace": {
            "block_size": block_size,
            "digest_size": digest_size,
        },
        "security_note": "Collision shown intentionally on toy compression output size.",
    }


try:
    from fastapi import APIRouter

    router = APIRouter(prefix="/demo/7", tags=["PA7"])

    @router.post("/md-hash")
    def md_hash_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa7_md_hash_hook(payload)

    @router.get("/collision")
    def collision_endpoint() -> dict[str, Any]:
        return pa7_collision_demo_hook()
except Exception:
    # FastAPI is optional here; hooks above remain usable without it.
    router = None
