"""PA #4 API-ready hooks for modes of operation."""

from __future__ import annotations

from typing import Any

from primitives.pa4_modes import (
    build_feistel_cipher,
    cbc_iv_reuse_attack_demo,
    encrypt,
    decrypt,
    ofb_keystream_reuse_attack_demo,
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


def pa4_encrypt_hook(payload: dict[str, Any]) -> dict[str, Any]:
    mode = payload.get("mode", "CBC")
    key = _read_bytes(payload, "key")
    message = _read_bytes(payload, "message", default=b"")
    block_size = int(payload.get("block_size", 16))

    cipher = build_feistel_cipher(key, block_size=block_size)
    result = encrypt(mode, key, message, block_cipher=cipher, block_size=block_size)

    return {
        "pa_id": "PA-4",
        "result": {k: v.hex() for k, v in result.items()},
        "trace": {"mode": mode.upper(), "block_size": block_size},
        "security_note": "Toy block cipher used for demo; swap with PA#2 block cipher for grading.",
    }


def pa4_decrypt_hook(payload: dict[str, Any]) -> dict[str, Any]:
    mode = payload.get("mode", "CBC")
    key = _read_bytes(payload, "key")
    block_size = int(payload.get("block_size", 16))

    cipher = build_feistel_cipher(key, block_size=block_size)

    if mode.upper() in {"CBC", "OFB"}:
        iv = _read_bytes(payload, "iv")
        ciphertext = _read_bytes(payload, "ciphertext")
        plaintext = decrypt(mode, key, {"iv": iv, "ciphertext": ciphertext}, block_cipher=cipher, block_size=block_size)
    else:
        nonce = _read_bytes(payload, "nonce")
        ciphertext = _read_bytes(payload, "ciphertext")
        plaintext = decrypt(mode, key, {"nonce": nonce, "ciphertext": ciphertext}, block_cipher=cipher, block_size=block_size)

    return {
        "pa_id": "PA-4",
        "result": {"message_hex": plaintext.hex()},
        "trace": {"mode": mode.upper(), "block_size": block_size},
        "security_note": "Toy block cipher used for demo; swap with PA#2 block cipher for grading.",
    }


def pa4_cbc_iv_reuse_demo_hook(payload: dict[str, Any]) -> dict[str, Any]:
    block_size = int(payload.get("block_size", 16))
    # Sensible defaults for demo when called with empty payload
    default_key = b"\xde\xad\xbe\xef" * 4           # 16 bytes
    default_iv  = b"\x00" * 16
    default_msg_a = b"Attack at dawn!!"              # 16 bytes
    default_msg_b = b"Attack at dawn!!"              # same => leaks equality

    key       = _read_bytes(payload, "key",       default=default_key)
    iv        = _read_bytes(payload, "iv",        default=default_iv)
    message_a = _read_bytes(payload, "message_a", default=default_msg_a)
    message_b = _read_bytes(payload, "message_b", default=default_msg_b)

    cipher = build_feistel_cipher(key, block_size=block_size)
    demo = cbc_iv_reuse_attack_demo(key, message_a, message_b, iv, block_cipher=cipher, block_size=block_size)

    return {
        "pa_id": "PA-4",
        "result": demo,
        "trace": {"mode": "CBC", "block_size": block_size},
        "security_note": "IV reuse breaks CBC confidentiality when blocks match.",
    }


def pa4_ofb_reuse_demo_hook(payload: dict[str, Any]) -> dict[str, Any]:
    block_size = int(payload.get("block_size", 16))
    # Sensible defaults for demo when called with empty payload
    default_key = b"\xde\xad\xbe\xef" * 4
    default_iv  = b"\x00" * 16
    default_msg_a = b"Secret message A"
    default_msg_b = b"Secret message B"

    key       = _read_bytes(payload, "key",       default=default_key)
    iv        = _read_bytes(payload, "iv",        default=default_iv)
    message_a = _read_bytes(payload, "message_a", default=default_msg_a)
    message_b = _read_bytes(payload, "message_b", default=default_msg_b)

    cipher = build_feistel_cipher(key, block_size=block_size)
    demo = ofb_keystream_reuse_attack_demo(key, message_a, message_b, iv, block_cipher=cipher, block_size=block_size)

    return {
        "pa_id": "PA-4",
        "result": demo,
        "trace": {"mode": "OFB", "block_size": block_size},
        "security_note": "Keystream reuse reveals XOR of plaintexts.",
    }


try:
    from fastapi import APIRouter

    router = APIRouter(prefix="/demo/4", tags=["PA4"])

    @router.post("/encrypt")
    def encrypt_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa4_encrypt_hook(payload)

    @router.post("/decrypt")
    def decrypt_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa4_decrypt_hook(payload)

    @router.post("/cbc-iv-reuse")
    def cbc_reuse_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa4_cbc_iv_reuse_demo_hook(payload)

    @router.post("/ofb-reuse")
    def ofb_reuse_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return pa4_ofb_reuse_demo_hook(payload)
except Exception:
    router = None
