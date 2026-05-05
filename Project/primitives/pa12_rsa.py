"""PA #12 foundation: RSA key generation, textbook RSA, and PKCS#1 v1.5 padding."""

from __future__ import annotations

import math
import random
from typing import Any, Dict

from core_math.number_theory import mod_inverse, modexp
from core_math.randomness import system_rng
from primitives.pa13_primality import gen_prime

PA_ID = "PA#12"


def _as_bytes(message: bytes | int) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, int):
        if message < 0:
            raise ValueError("message int must be non-negative")
        if message == 0:
            return b"\x00"
        size = (message.bit_length() + 7) // 8
        return message.to_bytes(size, "big")
    raise TypeError("message must be bytes or int")


def _extract_public_key(pk: Dict[str, Any]) -> Dict[str, int]:
    if "N" in pk and "e" in pk:
        return {"N": int(pk["N"]), "e": int(pk["e"])}
    if "public_key" in pk:
        data = pk["public_key"]
        return {"N": int(data["N"]), "e": int(data["e"])}
    raise ValueError("public key format not recognized")


def _extract_private_key(sk: Dict[str, Any]) -> Dict[str, int]:
    if "N" in sk and "d" in sk:
        return {"N": int(sk["N"]), "d": int(sk["d"])}
    if "private_key" in sk:
        data = sk["private_key"]
        return {"N": int(data["N"]), "d": int(data["d"])}
    raise ValueError("private key format not recognized")


def _modulus_bytes(N: int) -> int:
    return (N.bit_length() + 7) // 8


def _i2osp(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if x >= 256**length:
        raise ValueError("integer too large for requested length")
    return x.to_bytes(length, "big")


def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def rsa_keygen(
    bits: int = 2048, e: int = 65537, k: int = 40, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    if bits < 32:
        raise ValueError("bits must be >= 32")
    if e <= 2 or e % 2 == 0:
        raise ValueError("e must be an odd integer > 2")

    active_rng = rng or system_rng()
    half = bits // 2
    p = q = 0

    while True:
        p = gen_prime(bits=half, k=k, rng=active_rng)["prime"]
        q = gen_prime(bits=bits - half, k=k, rng=active_rng)["prime"]
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break

    N = p * q
    d = mod_inverse(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inverse(q, p)

    return {
        "pa_id": PA_ID,
        "algorithm": "RSAKeyGen",
        "bits": bits,
        "public_key": {"N": N, "e": e},
        "private_key": {"N": N, "d": d},
        "crt_params": {"p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv},
        "security_note": "Generated using PA#13 prime generation and custom modexp/egcd",
    }


def rsa_enc(pk: Dict[str, Any], m: int) -> int:
    key = _extract_public_key(pk)
    if m < 0 or m >= key["N"]:
        raise ValueError("plaintext integer must satisfy 0 <= m < N")
    return modexp(m, key["e"], key["N"])


def rsa_dec(sk: Dict[str, Any], c: int) -> int:
    key = _extract_private_key(sk)
    if c < 0 or c >= key["N"]:
        raise ValueError("ciphertext integer must satisfy 0 <= c < N")
    return modexp(c, key["d"], key["N"])


def pkcs15_pad(
    message: bytes, modulus_len: int, *, rng: random.Random | None = None
) -> bytes:
    if modulus_len < 11:
        raise ValueError("modulus length must be at least 11 bytes")
    if len(message) > modulus_len - 11:
        raise ValueError("message too long for PKCS#1 v1.5 block")

    active_rng = rng or system_rng()
    ps_len = modulus_len - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = active_rng.randrange(1, 256)  # non-zero bytes only
        ps.append(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + message


def pkcs15_unpad(encoded: bytes) -> bytes:
    if len(encoded) < 11:
        raise ValueError("encoded block too short")
    if encoded[0:2] != b"\x00\x02":
        raise ValueError("invalid PKCS#1 v1.5 header")

    sep = encoded.find(b"\x00", 2)
    if sep == -1:
        raise ValueError("missing PKCS#1 v1.5 separator")
    ps = encoded[2:sep]
    if len(ps) < 8:
        raise ValueError("padding string too short")
    if any(b == 0 for b in ps):
        raise ValueError("padding string contains zero byte")

    return encoded[sep + 1 :]


def pkcs15_enc(
    pk: Dict[str, Any], message: bytes | int, *, rng: random.Random | None = None
) -> int:
    key = _extract_public_key(pk)
    msg_bytes = _as_bytes(message)
    k_len = _modulus_bytes(key["N"])
    encoded = pkcs15_pad(msg_bytes, k_len, rng=rng)
    m = _os2ip(encoded)
    return rsa_enc(key, m)


def pkcs15_dec(sk: Dict[str, Any], c: int, *, as_bytes: bool = True) -> bytes | int:
    key = _extract_private_key(sk)
    k_len = _modulus_bytes(key["N"])
    m = rsa_dec(key, c)
    encoded = _i2osp(m, k_len)
    message = pkcs15_unpad(encoded)
    if as_bytes:
        return message
    return _os2ip(message)


def rsa_determinism_demo(
    message: bytes = b"yes",
    bits: int = 512,
    *,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """
    Show textbook RSA determinism and randomized PKCS#1 v1.5 behavior.
    """
    active_rng = rng or system_rng()
    keys = rsa_keygen(bits=bits, rng=active_rng)
    pk = keys["public_key"]
    sk = keys["private_key"]

    m_int = _os2ip(message)
    if m_int >= pk["N"]:
        raise ValueError("message integer must be < N")

    c1 = rsa_enc(pk, m_int)
    c2 = rsa_enc(pk, m_int)
    p1 = pkcs15_enc(pk, message, rng=active_rng)
    p2 = pkcs15_enc(pk, message, rng=active_rng)

    return {
        "pa_id": PA_ID,
        "algorithm": "RSADeterminismDemo",
        "textbook_cipher_1": c1,
        "textbook_cipher_2": c2,
        "textbook_equal": c1 == c2,
        "pkcs15_cipher_1": p1,
        "pkcs15_cipher_2": p2,
        "pkcs15_equal": p1 == p2,
        "decrypt_check": rsa_dec(sk, c1) == m_int and pkcs15_dec(sk, p1) == message,
    }

