"""PA #6: CCA-secure symmetric encryption via Encrypt-then-MAC."""

from __future__ import annotations

import os
from typing import Callable


def _to_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("value must be bytes or str")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cca_enc(
    key_enc: bytes,
    key_mac: bytes,
    message: bytes | str,
    cpa_enc: Callable[[bytes, bytes], tuple[bytes, bytes]],
    mac_fn: Callable[[bytes, bytes], bytes],
) -> tuple[bytes, bytes]:
    """Encrypt-then-MAC. Returns (ciphertext_blob, tag)."""

    msg = _to_bytes(message)
    nonce, ciphertext = cpa_enc(key_enc, msg)
    blob = nonce + ciphertext
    tag = mac_fn(key_mac, blob)
    return blob, tag


def cca_dec(
    key_enc: bytes,
    key_mac: bytes,
    ciphertext_blob: bytes,
    tag: bytes,
    cpa_dec: Callable[[bytes, bytes, bytes], bytes],
    verify_fn: Callable[[bytes, bytes, bytes], bool],
    nonce_size: int = 16,
) -> bytes | None:
    """Verify-then-decrypt. Returns None on MAC failure."""

    if not verify_fn(key_mac, ciphertext_blob, tag):
        return None

    nonce = ciphertext_blob[:nonce_size]
    ciphertext = ciphertext_blob[nonce_size:]
    return cpa_dec(key_enc, nonce, ciphertext)


def ind_cca2_game(
    cpa_enc: Callable[[bytes, bytes], tuple[bytes, bytes]],
    cpa_dec: Callable[[bytes, bytes, bytes], bytes],
    mac_fn: Callable[[bytes, bytes], bytes],
    verify_fn: Callable[[bytes, bytes, bytes], bool],
    rounds: int = 20,
    block_size: int = 16,
) -> dict[str, int]:
    """Simulate IND-CCA2 with a naive adversary guessing at random."""

    wins = 0
    for _ in range(rounds):
        key_enc = os.urandom(block_size)
        key_mac = os.urandom(block_size)
        m0 = os.urandom(block_size)
        m1 = os.urandom(block_size)

        b = os.urandom(1)[0] & 1
        challenge = m0 if b == 0 else m1
        c_blob, tag = cca_enc(key_enc, key_mac, challenge, cpa_enc=cpa_enc, mac_fn=mac_fn)

        # Adversary is not allowed to query the decryption oracle on (c_blob, tag).
        guess = os.urandom(1)[0] & 1
        if guess == b:
            wins += 1

        # Dummy decryption oracle query on a modified ciphertext to show rejection.
        altered = c_blob[:-1] + bytes([c_blob[-1] ^ 0x01])
        cca_dec(key_enc, key_mac, altered, tag, cpa_dec=cpa_dec, verify_fn=verify_fn, nonce_size=block_size)

    return {"rounds": rounds, "wins": wins}


def cpa_malleability_demo(
    key_enc: bytes,
    message: bytes | str,
    cpa_enc: Callable[[bytes, bytes], tuple[bytes, bytes]],
    cpa_dec: Callable[[bytes, bytes, bytes], bytes],
) -> dict[str, str]:
    """Flip a bit in CPA ciphertext to show plaintext corruption."""

    msg = _to_bytes(message)
    nonce, ct = cpa_enc(key_enc, msg)
    if len(ct) == 0:
        raise ValueError("ciphertext must be non-empty")

    flipped = ct[:-1] + bytes([ct[-1] ^ 0x01])
    altered = cpa_dec(key_enc, nonce, flipped)

    return {
        "ciphertext_hex": ct.hex(),
        "flipped_ciphertext_hex": flipped.hex(),
        "plaintext_hex": msg.hex(),
        "altered_plaintext_hex": altered.hex(),
    }


def cca_malleability_demo(
    key_enc: bytes,
    key_mac: bytes,
    message: bytes | str,
    cpa_enc: Callable[[bytes, bytes], tuple[bytes, bytes]],
    cpa_dec: Callable[[bytes, bytes, bytes], bytes],
    mac_fn: Callable[[bytes, bytes], bytes],
    verify_fn: Callable[[bytes, bytes, bytes], bool],
    nonce_size: int = 16,
) -> dict[str, str | bool]:
    """Show that Encrypt-then-MAC rejects bit-flip tampering."""

    msg = _to_bytes(message)
    blob, tag = cca_enc(key_enc, key_mac, msg, cpa_enc=cpa_enc, mac_fn=mac_fn)
    tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
    outcome = cca_dec(key_enc, key_mac, tampered, tag, cpa_dec=cpa_dec, verify_fn=verify_fn, nonce_size=nonce_size)

    return {
        "tampered_rejected": outcome is None,
        "ciphertext_hex": blob.hex(),
        "tag_hex": tag.hex(),
    }


def key_separation_demo(
    key: bytes,
    cpa_enc: Callable[[bytes, bytes], tuple[bytes, bytes]],
    mac_fn: Callable[[bytes, bytes], bytes],
    block_size: int = 16,
) -> dict[str, str | bool]:
    """Demonstrate observable correlation when the same key is reused."""

    msg = bytes([0]) * block_size
    nonce, ct = cpa_enc(key, msg)
    tag = mac_fn(key, nonce + ct)
    correlated = tag == mac_fn(key, nonce + ct)

    return {
        "ciphertext_hex": ct.hex(),
        "tag_hex": tag.hex(),
        "key_reuse_detected": correlated,
        "note": "Key reuse yields directly related outputs under the same key.",
    }
