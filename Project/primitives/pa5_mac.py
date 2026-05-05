"""PA #5: Message Authentication Codes (MACs)."""

from __future__ import annotations

import hashlib
import os
from typing import Callable

from primitives.pa7_merkle_damgard import md_hash, toy_compress


PRFFn = Callable[[bytes, bytes], bytes]


def _to_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("value must be bytes or str")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _chunk_bytes(data: bytes, block_size: int) -> list[bytes]:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _default_prf(key: bytes, block: bytes, out_len: int = 16) -> bytes:
    digest = hashlib.sha256(key + block).digest()
    return digest[:out_len]


def prf_mac_tag(
    key: bytes,
    message: bytes | str,
    prf_fn: PRFFn | None = None,
    block_size: int = 16,
) -> bytes:
    """PRF-MAC for fixed-length messages (exactly one block)."""

    msg = _to_bytes(message)
    if len(msg) != block_size:
        raise ValueError("PRF-MAC expects exactly one block")

    prf = prf_fn if prf_fn is not None else lambda k, x: _default_prf(k, x, out_len=block_size)
    return prf(key, msg)


def prf_mac_verify(
    key: bytes,
    message: bytes | str,
    tag: bytes,
    prf_fn: PRFFn | None = None,
    block_size: int = 16,
) -> bool:
    expected = prf_mac_tag(key, message, prf_fn=prf_fn, block_size=block_size)
    return expected == tag


def cbc_mac_tag(
    key: bytes,
    message: bytes | str,
    block_cipher: Callable[[bytes, bytes], bytes],
    block_size: int = 16,
) -> bytes:
    """CBC-MAC for variable-length messages."""

    msg = _to_bytes(message)
    padded = _pkcs7_pad(msg, block_size)
    blocks = _chunk_bytes(padded, block_size)

    chaining = bytes([0]) * block_size
    for block in blocks:
        chaining = block_cipher(key, _xor_bytes(chaining, block))

    return chaining


def cbc_mac_verify(
    key: bytes,
    message: bytes | str,
    tag: bytes,
    block_cipher: Callable[[bytes, bytes], bytes],
    block_size: int = 16,
) -> bool:
    expected = cbc_mac_tag(key, message, block_cipher=block_cipher, block_size=block_size)
    return expected == tag


def hmac_stub(key: bytes, message: bytes | str) -> bytes:
    """Placeholder for PA #10 implementation."""

    raise NotImplementedError("HMAC belongs to PA #10")


def mac_tag(
    key: bytes,
    message: bytes | str,
    scheme: str = "prf",
    prf_fn: PRFFn | None = None,
    block_cipher: Callable[[bytes, bytes], bytes] | None = None,
    block_size: int = 16,
) -> bytes:
    """Unified MAC API for PA #5."""

    scheme_norm = scheme.strip().lower()
    if scheme_norm == "prf":
        return prf_mac_tag(key, message, prf_fn=prf_fn, block_size=block_size)
    if scheme_norm == "cbc":
        if block_cipher is None:
            raise ValueError("block_cipher is required for CBC-MAC")
        return cbc_mac_tag(key, message, block_cipher=block_cipher, block_size=block_size)
    if scheme_norm == "hmac":
        return hmac_stub(key, message)
    raise ValueError("unsupported MAC scheme")


def mac_verify(
    key: bytes,
    message: bytes | str,
    tag: bytes,
    scheme: str = "prf",
    prf_fn: PRFFn | None = None,
    block_cipher: Callable[[bytes, bytes], bytes] | None = None,
    block_size: int = 16,
) -> bool:
    scheme_norm = scheme.strip().lower()
    if scheme_norm == "prf":
        return prf_mac_verify(key, message, tag, prf_fn=prf_fn, block_size=block_size)
    if scheme_norm == "cbc":
        if block_cipher is None:
            raise ValueError("block_cipher is required for CBC-MAC")
        return cbc_mac_verify(key, message, tag, block_cipher=block_cipher, block_size=block_size)
    if scheme_norm == "hmac":
        raise NotImplementedError("HMAC belongs to PA #10")
    raise ValueError("unsupported MAC scheme")


def mac_prf_distinguish_demo(
    key: bytes,
    prf_fn: PRFFn | None = None,
    block_size: int = 16,
    queries: int = 100,
) -> dict[str, int | float]:
    """Run a simple PRF-style distinguish test on PRF-MAC outputs."""

    prf = prf_fn if prf_fn is not None else lambda k, x: _default_prf(k, x, out_len=block_size)
    bits = []

    for _ in range(queries):
        msg = os.urandom(block_size)
        tag = prf(key, msg)
        for byte in tag:
            bits.append(bin(byte).count("1"))

    ones = sum(bits)
    total = len(bits) * 8
    return {
        "queries": queries,
        "ones": ones,
        "total_bits": total,
        "bias": abs(ones / total - 0.5),
    }


def euf_cma_game(
    key: bytes,
    mac_fn: Callable[[bytes, bytes], bytes],
    verify_fn: Callable[[bytes, bytes, bytes], bool],
    block_size: int = 16,
    queries: int = 50,
    trials: int = 20,
) -> dict[str, int]:
    """Simulate EUF-CMA with a naive adversary guessing random tags."""

    success = 0
    for _ in range(trials):
        seen = set()
        for _ in range(queries):
            msg = os.urandom(block_size)
            seen.add(msg)
            mac_fn(key, msg)

        candidate = os.urandom(block_size)
        while candidate in seen:
            candidate = os.urandom(block_size)

        guess = os.urandom(block_size)
        if verify_fn(key, candidate, guess):
            success += 1

    return {"trials": trials, "successes": success}


def _md_padding_for_length(message_len: int, block_size: int, length_size: int = 8) -> bytes:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if length_size <= 0:
        raise ValueError("length_size must be positive")

    bit_length = (message_len * 8) % (1 << (8 * length_size))
    padded = bytearray()
    padded.append(0x80)

    remainder = (message_len + len(padded) + length_size) % block_size
    if remainder:
        padded.extend(b"\x00" * (block_size - remainder))

    padded.extend(bit_length.to_bytes(length_size, "big"))
    return bytes(padded)


def _md_hash_from_state(
    state: bytes,
    message: bytes,
    prefix_len: int,
    block_size: int,
) -> bytes:
    total_len = prefix_len + len(message)
    padding = _md_padding_for_length(total_len, block_size)
    data = message + padding

    current = state
    for block in _chunk_bytes(data, block_size):
        current = toy_compress(current, block)

    return current


def length_extension_demo(
    key: bytes,
    message: bytes | str,
    suffix: bytes | str,
    block_size: int = 16,
    key_len: int | None = None,
) -> dict[str, str | bool]:
    """Demonstrate length-extension attack on naive hash MAC t = H(k || m)."""

    msg = _to_bytes(message)
    ext = _to_bytes(suffix)
    guessed_key_len = len(key) if key_len is None else key_len

    tag = md_hash(key + msg, compress_fn=toy_compress, iv=bytes(range(1, 3)), block_size=block_size)
    glue = _md_padding_for_length(guessed_key_len + len(msg), block_size)
    forged_message = msg + glue + ext

    forged_tag = _md_hash_from_state(tag, ext, guessed_key_len + len(msg) + len(glue), block_size)
    real_tag = md_hash(key + forged_message, compress_fn=toy_compress, iv=bytes(range(1, 3)), block_size=block_size)

    return {
        "forged_message_hex": forged_message.hex(),
        "orig_tag_hex": tag.hex(),
        "forged_tag_hex": forged_tag.hex(),
        "real_tag_hex": real_tag.hex(),
        "attack_success": forged_tag == real_tag,
    }
