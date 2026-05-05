"""PA #4: Modes of operation for block ciphers.

Supports CBC, OFB, and randomized CTR with a pluggable block cipher.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from typing import Callable, Iterable


BlockFn = Callable[[bytes], bytes]


@dataclass(frozen=True)
class BlockCipher:
    """Block cipher interface: encrypt/decrypt single fixed-size block."""

    name: str
    block_size: int
    encrypt_block: BlockFn
    decrypt_block: BlockFn


def _to_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("value must be bytes or str")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _chunk_bytes(data: bytes, block_size: int) -> Iterable[bytes]:
    for offset in range(0, len(data), block_size):
        yield data[offset : offset + block_size]


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if block_size <= 0 or block_size >= 256:
        raise ValueError("block_size must be between 1 and 255")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid PKCS7 padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding")
    return data[:-pad_len]


def _feistel_round(key: bytes, half: bytes, round_index: int, out_len: int) -> bytes:
    seed = key + round_index.to_bytes(1, "big") + half
    return hashlib.sha256(seed).digest()[:out_len]


def build_feistel_cipher(key: bytes, block_size: int = 16, rounds: int = 6) -> BlockCipher:
    """Toy PRP for demos/tests when a PA#2 block cipher is not wired in."""

    if block_size % 2 != 0:
        raise ValueError("block_size must be even for Feistel")

    half = block_size // 2

    def encrypt_block(block: bytes) -> bytes:
        if len(block) != block_size:
            raise ValueError("block size mismatch")
        left, right = block[:half], block[half:]
        for r in range(rounds):
            f_out = _feistel_round(key, right, r, half)
            left, right = right, _xor_bytes(left, f_out)
        return left + right

    def decrypt_block(block: bytes) -> bytes:
        if len(block) != block_size:
            raise ValueError("block size mismatch")
        left, right = block[:half], block[half:]
        for r in reversed(range(rounds)):
            f_out = _feistel_round(key, left, r, half)
            left, right = _xor_bytes(right, f_out), left
        return left + right

    return BlockCipher(name="toy-feistel", block_size=block_size, encrypt_block=encrypt_block, decrypt_block=decrypt_block)


def _resolve_cipher(key: bytes, block_cipher: BlockCipher | None, block_size: int) -> BlockCipher:
    if block_cipher is not None:
        return block_cipher
    return build_feistel_cipher(key, block_size=block_size)


def cbc_encrypt(
    key: bytes,
    message: bytes | str,
    block_cipher: BlockCipher | None = None,
    iv: bytes | None = None,
    block_size: int = 16,
) -> tuple[bytes, bytes]:
    """CBC encryption with random IV and PKCS7 padding."""

    msg = _to_bytes(message)
    cipher = _resolve_cipher(key, block_cipher, block_size)
    if cipher.block_size != block_size:
        raise ValueError("block_size mismatch with cipher")

    iv_bytes = iv if iv is not None else os.urandom(block_size)
    padded = _pkcs7_pad(msg, block_size)

    prev = iv_bytes
    out = bytearray()
    for block in _chunk_bytes(padded, block_size):
        xored = _xor_bytes(block, prev)
        ct = cipher.encrypt_block(xored)
        out.extend(ct)
        prev = ct

    return iv_bytes, bytes(out)


def cbc_decrypt(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> bytes:
    """CBC decryption and PKCS7 unpadding."""

    cipher = _resolve_cipher(key, block_cipher, block_size)
    if cipher.block_size != block_size:
        raise ValueError("block_size mismatch with cipher")
    if len(ciphertext) % block_size != 0:
        raise ValueError("ciphertext length must be multiple of block_size")

    prev = iv
    out = bytearray()
    for block in _chunk_bytes(ciphertext, block_size):
        pt = _xor_bytes(cipher.decrypt_block(block), prev)
        out.extend(pt)
        prev = block

    return _pkcs7_unpad(bytes(out), block_size)


def ofb_encrypt(
    key: bytes,
    message: bytes | str,
    block_cipher: BlockCipher | None = None,
    iv: bytes | None = None,
    block_size: int = 16,
) -> tuple[bytes, bytes]:
    """OFB encryption (same operation for decryption)."""

    msg = _to_bytes(message)
    cipher = _resolve_cipher(key, block_cipher, block_size)
    if cipher.block_size != block_size:
        raise ValueError("block_size mismatch with cipher")

    iv_bytes = iv if iv is not None else os.urandom(block_size)
    out = bytearray()
    stream = iv_bytes

    for block in _chunk_bytes(msg, block_size):
        stream = cipher.encrypt_block(stream)
        out.extend(_xor_bytes(block, stream[: len(block)]))

    return iv_bytes, bytes(out)


def ofb_decrypt(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> bytes:
    """OFB decryption (identical to encryption)."""

    return ofb_encrypt(key, ciphertext, block_cipher=block_cipher, iv=iv, block_size=block_size)[1]


def ctr_encrypt(
    key: bytes,
    message: bytes | str,
    block_cipher: BlockCipher | None = None,
    nonce: bytes | None = None,
    block_size: int = 16,
) -> tuple[bytes, bytes]:
    """Randomized CTR encryption."""

    msg = _to_bytes(message)
    cipher = _resolve_cipher(key, block_cipher, block_size)
    if cipher.block_size != block_size:
        raise ValueError("block_size mismatch with cipher")

    nonce_bytes = nonce if nonce is not None else os.urandom(block_size)
    counter = int.from_bytes(nonce_bytes, "big")
    modulus = 1 << (block_size * 8)

    out = bytearray()
    for block_index, block in enumerate(_chunk_bytes(msg, block_size)):
        counter_bytes = (counter + block_index) % modulus
        stream = cipher.encrypt_block(counter_bytes.to_bytes(block_size, "big"))
        out.extend(_xor_bytes(block, stream[: len(block)]))

    return nonce_bytes, bytes(out)


def ctr_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> bytes:
    """CTR decryption (identical to encryption)."""

    return ctr_encrypt(key, ciphertext, block_cipher=block_cipher, nonce=nonce, block_size=block_size)[1]


def encrypt(
    mode: str,
    key: bytes,
    message: bytes | str,
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> dict[str, bytes]:
    """Unified encrypt API for CBC/OFB/CTR."""

    mode_norm = mode.strip().upper()
    if mode_norm == "CBC":
        iv, ct = cbc_encrypt(key, message, block_cipher=block_cipher, block_size=block_size)
        return {"iv": iv, "ciphertext": ct}
    if mode_norm == "OFB":
        iv, ct = ofb_encrypt(key, message, block_cipher=block_cipher, block_size=block_size)
        return {"iv": iv, "ciphertext": ct}
    if mode_norm == "CTR":
        nonce, ct = ctr_encrypt(key, message, block_cipher=block_cipher, block_size=block_size)
        return {"nonce": nonce, "ciphertext": ct}
    raise ValueError("unsupported mode")


def decrypt(
    mode: str,
    key: bytes,
    payload: dict[str, bytes],
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> bytes:
    """Unified decrypt API for CBC/OFB/CTR."""

    mode_norm = mode.strip().upper()
    if mode_norm == "CBC":
        return cbc_decrypt(key, payload["iv"], payload["ciphertext"], block_cipher=block_cipher, block_size=block_size)
    if mode_norm == "OFB":
        return ofb_decrypt(key, payload["iv"], payload["ciphertext"], block_cipher=block_cipher, block_size=block_size)
    if mode_norm == "CTR":
        return ctr_decrypt(key, payload["nonce"], payload["ciphertext"], block_cipher=block_cipher, block_size=block_size)
    raise ValueError("unsupported mode")


def cbc_iv_reuse_attack_demo(
    key: bytes,
    message_a: bytes | str,
    message_b: bytes | str,
    iv: bytes,
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> dict[str, object]:
    """Demonstrate CBC IV-reuse leakage for equal blocks."""

    msg_a = _to_bytes(message_a)
    msg_b = _to_bytes(message_b)
    iv_a, ct_a = cbc_encrypt(key, msg_a, block_cipher=block_cipher, iv=iv, block_size=block_size)
    iv_b, ct_b = cbc_encrypt(key, msg_b, block_cipher=block_cipher, iv=iv, block_size=block_size)

    blocks_a = list(_chunk_bytes(ct_a, block_size))
    blocks_b = list(_chunk_bytes(ct_b, block_size))
    same_blocks = [i for i, (x, y) in enumerate(zip(blocks_a, blocks_b)) if x == y]

    return {
        "iv_hex": iv_a.hex(),
        "cipher_a_hex": ct_a.hex(),
        "cipher_b_hex": ct_b.hex(),
        "same_block_indices": same_blocks,
        "blocks_compared": min(len(blocks_a), len(blocks_b)),
    }


def ofb_keystream_reuse_attack_demo(
    key: bytes,
    message_a: bytes | str,
    message_b: bytes | str,
    iv: bytes,
    block_cipher: BlockCipher | None = None,
    block_size: int = 16,
) -> dict[str, object]:
    """Demonstrate OFB keystream reuse: C1 xor C2 = M1 xor M2."""

    msg_a = _to_bytes(message_a)
    msg_b = _to_bytes(message_b)
    iv_a, ct_a = ofb_encrypt(key, msg_a, block_cipher=block_cipher, iv=iv, block_size=block_size)
    iv_b, ct_b = ofb_encrypt(key, msg_b, block_cipher=block_cipher, iv=iv, block_size=block_size)

    min_len = min(len(ct_a), len(ct_b), len(msg_a), len(msg_b))
    xor_ct = _xor_bytes(ct_a[:min_len], ct_b[:min_len])
    xor_msg = _xor_bytes(msg_a[:min_len], msg_b[:min_len])

    return {
        "iv_hex": iv_a.hex(),
        "cipher_a_hex": ct_a.hex(),
        "cipher_b_hex": ct_b.hex(),
        "xor_cipher_hex": xor_ct.hex(),
        "xor_message_hex": xor_msg.hex(),
        "xor_matches": xor_ct == xor_msg,
    }
