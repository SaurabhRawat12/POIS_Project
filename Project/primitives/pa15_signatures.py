"""PA #15: Digital Signatures (RSA hash-then-sign).

Implements the standard RSA signature scheme with required attack demos.

    sigma  = H(m)^d mod N    (signing)
    verify : sigma^e mod N == H(m)

Lineage (no external crypto libraries):
    PA #15  ->  PA #12 (RSA keygen, modular exponentiation)
            ->  PA #8  (DLP-based collision-resistant hash)
            ->  PA #13 (transitively, via PA #12 prime generation
                       and PA #8 safe-prime group setup)

Includes:
    - sign / verify (hash-then-sign)
    - sign_raw / verify_raw (no hash) -- only for the forgery demo
    - multiplicative_forgery_demo: shows raw RSA is broken
    - euf_cma_game: empirical security check on hash-then-sign
"""

from __future__ import annotations

import random
from typing import Any, Dict, List

from core_math.number_theory import modexp
from core_math.randomness import system_rng
from primitives.pa12_rsa import rsa_enc, rsa_dec, rsa_keygen
from primitives.pa8_dlp_hash import DLPGroup, dlp_hash

PA_ID = "PA#15"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _modulus_N(key: Dict[str, Any]) -> int:
    """Extract N from either a flat dict {N, e/d} or the nested keygen output."""
    if "N" in key:
        return int(key["N"])
    if "public_key" in key:
        return int(key["public_key"]["N"])
    if "private_key" in key:
        return int(key["private_key"]["N"])
    raise ValueError("key dict missing modulus N")


def _hash_to_int(message: bytes, group: DLPGroup, modulus_N: int) -> int:
    """Hash a message via PA #8 DLP hash, then reduce to an integer mod N.

    The hash output is bytes; we convert big-endian and reduce mod N so it
    fits the RSA message space.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    digest = dlp_hash(message, group)
    h = int.from_bytes(digest, "big") % modulus_N
    # Avoid the degenerate value 0 (since 0^d = 0 for any d, this would
    # make every "signature" on the zero hash trivially valid).
    return h if h != 0 else 1


# ---------------------------------------------------------------------------
# Hash-then-sign (the secure scheme)
# ---------------------------------------------------------------------------

def sign(sk: Dict[str, Any], message: bytes, group: DLPGroup) -> Dict[str, Any]:
    """RSA hash-then-sign: sigma = H(m)^d mod N.

    Parameters
    ----------
    sk : private key dict (flat {"N", "d"} or nested {"private_key": {...}})
    message : bytes (or str, will be UTF-8 encoded) to sign
    group : DLP group parameters for the PA #8 hash
    """
    N = _modulus_N(sk)
    h = _hash_to_int(message, group, N)
    sigma = rsa_dec(sk, h)  # Reuses PA #12: c^d mod N
    return {
        "pa_id": PA_ID,
        "algorithm": "RSAHashThenSign",
        "signature": sigma,
        "hashed_message": h,
        "security_note": "Hash-then-sign blocks multiplicative forgery on raw RSA.",
    }


def verify(
    pk: Dict[str, Any], message: bytes, sigma: int, group: DLPGroup
) -> Dict[str, Any]:
    """RSA verification: check that sigma^e mod N == H(m)."""
    N = _modulus_N(pk)
    expected = _hash_to_int(message, group, N)
    recovered = rsa_enc(pk, sigma)  # Reuses PA #12: m^e mod N
    valid = recovered == expected
    return {
        "pa_id": PA_ID,
        "algorithm": "RSAHashThenVerify",
        "valid": valid,
        "expected_hash": expected,
        "recovered_hash": recovered,
    }


# ---------------------------------------------------------------------------
# Raw RSA (insecure -- demo only)
# ---------------------------------------------------------------------------

def sign_raw(sk: Dict[str, Any], m: int) -> int:
    """Insecure: raw RSA signing, sigma = m^d mod N (no hashing).

    Used ONLY by `multiplicative_forgery_demo` to exhibit the attack that
    motivates hash-then-sign. Never use this in real schemes.
    """
    return rsa_dec(sk, m)


def verify_raw(pk: Dict[str, Any], m: int, sigma: int) -> bool:
    """Verify a raw (unhashed) RSA signature: sigma^e mod N == m."""
    return rsa_enc(pk, sigma) == m


# ---------------------------------------------------------------------------
# Required attack demo: multiplicative forgery on raw RSA
# ---------------------------------------------------------------------------

def multiplicative_forgery_demo(
    bits: int = 512, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    """Forge a raw-RSA signature without the secret key.

    RSA is multiplicatively homomorphic:
        (m1^d) * (m2^d) = (m1 * m2)^d   (mod N)

    So an attacker who has seen sigma1 = sign_raw(m1) and sigma2 = sign_raw(m2)
    can compute a valid signature on the new message  m3 = m1*m2 mod N
    just by multiplying the two known signatures -- no private key required.

    Hashing destroys this structure:  H(m1*m2) != H(m1)*H(m2) in general,
    so the same trick gives nothing on hash-then-sign.
    """
    active_rng = rng or system_rng()
    keys = rsa_keygen(bits=bits, rng=active_rng)
    pk = keys["public_key"]
    sk = keys["private_key"]
    N = pk["N"]

    # Pick two small messages so m1 * m2 < N (no wrap-around weirdness).
    bound = min(N, 1 << 64)
    m1 = active_rng.randrange(2, bound)
    m2 = active_rng.randrange(2, bound)

    sigma1 = sign_raw(sk, m1)
    sigma2 = sign_raw(sk, m2)

    forged_message = (m1 * m2) % N
    forged_signature = (sigma1 * sigma2) % N
    forgery_valid = verify_raw(pk, forged_message, forged_signature)

    return {
        "pa_id": PA_ID,
        "algorithm": "RSAMultiplicativeForgery",
        "m1": m1,
        "m2": m2,
        "sigma1": sigma1,
        "sigma2": sigma2,
        "forged_message": forged_message,
        "forged_signature": forged_signature,
        "forgery_valid": forgery_valid,
        "security_note": (
            "Raw RSA is multiplicatively homomorphic, so signatures on m1, m2 "
            "give a free signature on m1*m2 mod N. Hash-then-sign blocks this "
            "because H is not multiplicative."
        ),
    }


# ---------------------------------------------------------------------------
# EUF-CMA security game
# ---------------------------------------------------------------------------

def euf_cma_game(
    *,
    queries: int = 50,
    bits: int = 512,
    q_bits: int = 31,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Empirical EUF-CMA game on hash-then-sign.

    The adversary asks the signing oracle for `queries` distinct messages,
    receiving (m_i, sigma_i) for each. They then pick a fresh message
    m* (not in the queried set) and submit a guess sigma*.

    A naive adversary cannot do better than randomly guessing sigma*,
    and a random sigma* satisfies  sigma*^e mod N == H(m*)  with
    probability ~1/N -- negligible. So forgery_succeeded should be False
    in essentially every run.
    """
    active_rng = rng or system_rng()
    keys = rsa_keygen(bits=bits, rng=active_rng)
    pk = keys["public_key"]
    sk = keys["private_key"]
    group = DLPGroup.generate(q_bits=q_bits)

    queried_messages: List[bytes] = []
    queried_signatures: List[int] = []
    for i in range(queries):
        msg = f"oracle-msg-{i}-{active_rng.randrange(0, 1 << 32)}".encode()
        queried_messages.append(msg)
        result = sign(sk, msg, group)
        queried_signatures.append(result["signature"])

    # Naive adversary: pick a fresh message and guess a random signature.
    forge_msg = b"forgery-attempt-" + str(active_rng.randrange(0, 1 << 32)).encode()
    while forge_msg in queried_messages:
        forge_msg = b"forgery-attempt-" + str(active_rng.randrange(0, 1 << 32)).encode()
    forge_sigma = active_rng.randrange(1, pk["N"])

    verification = verify(pk, forge_msg, forge_sigma, group)

    return {
        "pa_id": PA_ID,
        "algorithm": "RSAEUFCMAGame",
        "queries": queries,
        "forge_message": forge_msg.decode(errors="replace"),
        "forge_signature": forge_sigma,
        "forgery_succeeded": verification["valid"],
        "security_note": (
            "EUF-CMA: a random sigma verifies with probability ~1/N. "
            "Empirically should always be False at toy parameters."
        ),
    }
