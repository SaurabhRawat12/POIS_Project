"""PA #14: Chinese Remainder Theorem + RSA CRT decrypt + Hastad broadcast attack."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Sequence, Tuple

from core_math.number_theory import mod_inverse, modexp

PA_ID = "PA#14"


def _pairwise_coprime(moduli: Sequence[int]) -> bool:
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if math.gcd(moduli[i], moduli[j]) != 1:
                return False
    return True


def crt(residues: Sequence[int], moduli: Sequence[int]) -> int:
    """
    Solve x ≡ residues[i] (mod moduli[i]) for pairwise-coprime moduli.
    Returns x in [0, N), where N = product(moduli).
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")
    if len(moduli) == 0:
        raise ValueError("at least one congruence is required")
    if any(n <= 1 for n in moduli):
        raise ValueError("all moduli must be > 1")
    if not _pairwise_coprime(moduli):
        raise ValueError("moduli must be pairwise coprime")

    N = 1
    for n in moduli:
        N *= n

    x = 0
    for a_i, n_i in zip(residues, moduli):
        M_i = N // n_i
        inv = mod_inverse(M_i % n_i, n_i)
        x = (x + (a_i % n_i) * M_i * inv) % N
    return x


def _extract_crt_key(sk: Dict[str, Any]) -> Dict[str, int]:
    if all(k in sk for k in ("p", "q", "dp", "dq", "qinv")):
        p = int(sk["p"])
        q = int(sk["q"])
        return {
            "p": p,
            "q": q,
            "dp": int(sk["dp"]),
            "dq": int(sk["dq"]),
            "qinv": int(sk["qinv"]),
            "N": int(sk.get("N", p * q)),
        }

    if "crt_params" in sk:
        crt_params = sk["crt_params"]
        p = int(crt_params["p"])
        q = int(crt_params["q"])
        return {
            "p": p,
            "q": q,
            "dp": int(crt_params["dp"]),
            "dq": int(crt_params["dq"]),
            "qinv": int(crt_params["qinv"]),
            "N": int(sk.get("private_key", {}).get("N", p * q)),
        }

    raise ValueError("CRT key format not recognized")


def rsa_dec_crt(sk: Dict[str, Any], c: int) -> int:
    """
    RSA decryption using CRT/Garner recombination:
    mp = c^dp mod p, mq = c^dq mod q,
    h = qinv * (mp - mq) mod p, m = mq + h*q.
    """
    key = _extract_crt_key(sk)
    p, q, dp, dq, qinv, N = (
        key["p"],
        key["q"],
        key["dp"],
        key["dq"],
        key["qinv"],
        key["N"],
    )
    if c < 0 or c >= N:
        raise ValueError("ciphertext integer must satisfy 0 <= c < N")

    mp = modexp(c, dp, p)
    mq = modexp(c, dq, q)
    h = (qinv * (mp - mq)) % p
    m = (mq + h * q) % N
    return m


def integer_nth_root(value: int, n: int) -> Tuple[int, bool]:
    """Return (floor(value^(1/n)), is_exact)."""
    if n <= 0:
        raise ValueError("n must be positive")
    if value < 0:
        raise ValueError("value must be non-negative")
    if value in (0, 1):
        return value, True

    # Float-based initial guesses can be wildly inaccurate for big integers.
    # Use pure-integer binary search for robust behavior.
    lo, hi = 0, 1
    while hi**n <= value:
        hi <<= 1

    while lo + 1 < hi:
        mid = (lo + hi) // 2
        mid_n = mid**n
        if mid_n <= value:
            lo = mid
        else:
            hi = mid

    return lo, (lo**n == value)


def hastad_attack(ciphertexts: Sequence[int], moduli: Sequence[int], e: int) -> int:
    """
    Recover m from e ciphertexts ci = m^e mod Ni (textbook RSA, same message).
    Returns floor(e-th-root(CRT_value)); exactness can be checked via hastad_attack_verbose.
    """
    if e <= 1:
        raise ValueError("e must be > 1")
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError("need at least e ciphertext/modulus pairs")

    c_used = [int(x) for x in ciphertexts[:e]]
    n_used = [int(x) for x in moduli[:e]]
    x = crt(c_used, n_used)
    root, _ = integer_nth_root(x, e)
    return root


def hastad_attack_verbose(
    ciphertexts: Sequence[int], moduli: Sequence[int], e: int
) -> Dict[str, Any]:
    if e <= 1:
        raise ValueError("e must be > 1")
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError("need at least e ciphertext/modulus pairs")

    c_used = [int(x) for x in ciphertexts[:e]]
    n_used = [int(x) for x in moduli[:e]]
    x = crt(c_used, n_used)
    root, is_exact = integer_nth_root(x, e)
    return {
        "pa_id": PA_ID,
        "algorithm": "HastadBroadcastAttack",
        "e": e,
        "crt_value": x,
        "recovered_root": root,
        "is_exact_root": is_exact,
        "recovered_message": root if is_exact else None,
    }


def crt_rsa_speedup_demo(
    sk: Dict[str, Any], ciphertexts: Sequence[int]
) -> Dict[str, Any]:
    """
    Minimal utility for teammate integration: batch decrypt with CRT.
    """
    out: List[int] = []
    for c in ciphertexts:
        out.append(rsa_dec_crt(sk, int(c)))
    return {
        "pa_id": PA_ID,
        "algorithm": "CRTBatchDecrypt",
        "count": len(out),
        "plaintexts": out,
    }
