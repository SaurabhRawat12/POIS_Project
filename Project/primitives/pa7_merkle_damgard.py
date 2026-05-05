"""PA #7: Generic Merkle-Damgard framework with MD strengthening.

This module provides:
- `md_pad`: MD-strengthening padding
- `md_hash`: generic Merkle-Damgard iteration with pluggable compression
- a toy compression plugin and collision-propagation demo for interactive use
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Callable, Protocol


class CompressionFn(Protocol):
    """Compression contract used by the generic MD engine."""

    def __call__(self, state: bytes, block: bytes) -> bytes:
        ...


@dataclass(frozen=True)
class HashContract:
    """Stable contract downstream modules can depend on."""

    name: str
    block_size: int
    digest_size: int


def _to_bytes(message: bytes | str) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be bytes or str")


def md_pad(message: bytes | str, block_size: int = 64, length_size: int = 8) -> bytes:
    """Return Merkle-Damgard strengthening padding for `message`.

    The result is the full padded message, not just the padding bytes.
    """

    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if length_size <= 0:
        raise ValueError("length_size must be positive")

    msg = _to_bytes(message)
    bit_length = (len(msg) * 8) % (1 << (8 * length_size))

    # 0x80 starts the mandatory 1-bit, then zero bytes until length footer fits.
    padded = bytearray(msg)
    padded.append(0x80)

    remainder = (len(padded) + length_size) % block_size
    if remainder:
        padded.extend(b"\x00" * (block_size - remainder))

    padded.extend(bit_length.to_bytes(length_size, "big"))
    return bytes(padded)


def md_hash(
    message: bytes | str,
    compress_fn: CompressionFn,
    iv: bytes,
    block_size: int,
) -> bytes:
    """Generic Merkle-Damgard hash iteration over padded blocks."""

    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if not isinstance(iv, (bytes, bytearray)) or len(iv) == 0:
        raise ValueError("iv must be non-empty bytes")

    padded = md_pad(message, block_size=block_size)
    state = bytes(iv)

    for offset in range(0, len(padded), block_size):
        block = padded[offset : offset + block_size]
        new_state = compress_fn(state, block)
        if not isinstance(new_state, (bytes, bytearray)):
            raise TypeError("compress_fn must return bytes")
        if len(new_state) != len(state):
            raise ValueError("compress_fn must preserve state size")
        state = bytes(new_state)

    return state


def make_md_hasher(
    compress_fn: CompressionFn,
    iv: bytes,
    block_size: int,
    name: str = "md-custom",
) -> tuple[HashContract, Callable[[bytes | str], bytes]]:
    """Build a stable callable hash interface for downstream PAs."""

    if not isinstance(iv, (bytes, bytearray)) or len(iv) == 0:
        raise ValueError("iv must be non-empty bytes")
    if block_size <= 0:
        raise ValueError("block_size must be positive")

    contract = HashContract(name=name, block_size=block_size, digest_size=len(iv))

    def _hash_fn(message: bytes | str) -> bytes:
        return md_hash(message=message, compress_fn=compress_fn, iv=bytes(iv), block_size=block_size)

    return contract, _hash_fn


def toy_compress(state: bytes, block: bytes) -> bytes:
    """Toy compression function for demos only (not cryptographically secure)."""

    if len(state) == 0:
        raise ValueError("state must be non-empty")

    bits = 8 * len(state)
    mask = (1 << bits) - 1

    s = int.from_bytes(state, "big")
    m = int.from_bytes(block, "big")

    mixed = (s ^ m ^ ((m << 7) & mask) ^ (m >> 3))
    mixed = (mixed * 0x9E3779B1) & mask
    return mixed.to_bytes(len(state), "big")


def toy_md_hash(
    message: bytes | str,
    block_size: int = 16,
    digest_size: int = 2,
    iv: bytes | None = None,
) -> bytes:
    """Reference PA #7 demo hash built with the toy compression function."""

    if digest_size <= 0:
        raise ValueError("digest_size must be positive")

    seed_iv = iv if iv is not None else bytes(range(1, digest_size + 1))
    return md_hash(message=message, compress_fn=toy_compress, iv=seed_iv, block_size=block_size)


def _counter_block(counter: int, block_size: int) -> bytes:
    """Deterministically derive a pseudo-random block from a counter."""

    material = bytearray()
    seed = counter.to_bytes(8, "big")

    while len(material) < block_size:
        seed = hashlib.sha256(seed).digest()
        material.extend(seed)

    return bytes(material[:block_size])


def find_toy_single_block_collision(
    block_size: int = 16,
    digest_size: int = 2,
    max_attempts: int = 10000,
    iv: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Find two different one-block messages colliding under `toy_compress`.

    Returns `(block_a, block_b, intermediate_state)` where:
    `toy_compress(iv, block_a) == toy_compress(iv, block_b)`.
    """

    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if digest_size <= 0:
        raise ValueError("digest_size must be positive")
    if max_attempts < 2:
        raise ValueError("max_attempts must be at least 2")

    start_state = iv if iv is not None else bytes(range(1, digest_size + 1))
    seen: dict[bytes, bytes] = {}

    for i in range(max_attempts):
        block = _counter_block(i, block_size)
        out = toy_compress(start_state, block)

        if out in seen and seen[out] != block:
            return seen[out], block, out
        seen[out] = block

    raise RuntimeError("Could not find collision within max_attempts")


def collision_propagation_demo(
    suffix: bytes | str = b"shared-suffix",
    block_size: int = 16,
    digest_size: int = 2,
) -> dict[str, str | bool]:
    """Demonstrate Merkle-Damgard collision propagation with a common suffix."""

    suffix_bytes = _to_bytes(suffix)
    iv = bytes(range(1, digest_size + 1))
    m1_block, m2_block, internal = find_toy_single_block_collision(
        block_size=block_size,
        digest_size=digest_size,
        iv=iv,
    )

    h1 = md_hash(m1_block + suffix_bytes, toy_compress, iv=iv, block_size=block_size)
    h2 = md_hash(m2_block + suffix_bytes, toy_compress, iv=iv, block_size=block_size)

    return {
        "collision_found": True,
        "block_a_hex": m1_block.hex(),
        "block_b_hex": m2_block.hex(),
        "internal_state_hex": internal.hex(),
        "hash_a_hex": h1.hex(),
        "hash_b_hex": h2.hex(),
        "hashes_equal": h1 == h2,
        "suffix_hex": suffix_bytes.hex(),
    }


def get_pa7_hash_interface(
    block_size: int = 16,
    digest_size: int = 2,
) -> tuple[HashContract, Callable[[bytes | str], bytes]]:
    """Return a stable PA #7 hash contract for PA #8 and PA #10 integration."""

    iv = bytes(range(1, digest_size + 1))
    return make_md_hasher(
        compress_fn=toy_compress,
        iv=iv,
        block_size=block_size,
        name="pa7.toy-md",
    )
