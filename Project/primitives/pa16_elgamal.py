"""PA #16: ElGamal PKC (keygen, enc/dec, malleability, and CPA game helpers)."""

from __future__ import annotations

import random
from typing import Any, Dict

from core_math.number_theory import mod_inverse, modexp
from core_math.randomness import system_rng
from primitives.pa11_diffie_hellman import dh_generate_group

PA_ID = "PA#16"


def _extract_public_key(pk: Dict[str, Any]) -> Dict[str, int]:
    if all(k in pk for k in ("p", "g", "q", "h")):
        return {
            "p": int(pk["p"]),
            "g": int(pk["g"]),
            "q": int(pk["q"]),
            "h": int(pk["h"]),
        }
    if "public_key" in pk:
        k = pk["public_key"]
        return {
            "p": int(k["p"]),
            "g": int(k["g"]),
            "q": int(k["q"]),
            "h": int(k["h"]),
        }
    raise ValueError("public key format not recognized")


def _extract_private_key(sk: Dict[str, Any]) -> int:
    if "x" in sk:
        return int(sk["x"])
    if "private_key" in sk and "x" in sk["private_key"]:
        return int(sk["private_key"]["x"])
    raise ValueError("private key format not recognized")


def _sample_subgroup_message(pk: Dict[str, int], rng: random.Random) -> int:
    exp = rng.randrange(1, pk["q"])
    return modexp(pk["g"], exp, pk["p"])


def elgamal_keygen(
    params: Dict[str, int] | None = None,
    *,
    q_bits: int = 255,
    k: int = 40,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """
    Generate ElGamal keys over DH safe-prime group from PA #11.
    """
    active_rng = rng or system_rng()
    group = params or dh_generate_group(q_bits=q_bits, k=k, rng=active_rng)
    p, g, q = int(group["p"]), int(group["g"]), int(group["q"])

    x = active_rng.randrange(1, q)
    h = modexp(g, x, p)
    return {
        "pa_id": PA_ID,
        "algorithm": "ElGamalKeyGen",
        "public_key": {"p": p, "g": g, "q": q, "h": h},
        "private_key": {"x": x},
        "source": "PA#11 group parameters",
    }


def elgamal_enc(
    pk: Dict[str, Any], m: int, *, r: int | None = None, rng: random.Random | None = None
) -> Dict[str, int]:
    """
    Encrypt m in multiplicative group mod p.
    """
    key = _extract_public_key(pk)
    p, g, q, h = key["p"], key["g"], key["q"], key["h"]
    if m <= 0 or m >= p:
        raise ValueError("message must satisfy 0 < m < p")

    active_rng = rng or system_rng()
    nonce = int(r) if r is not None else active_rng.randrange(1, q)
    c1 = modexp(g, nonce, p)
    s = modexp(h, nonce, p)
    c2 = (m * s) % p
    return {"c1": c1, "c2": c2, "r": nonce}


def elgamal_dec(sk: Dict[str, Any], pk: Dict[str, Any], c1: int, c2: int) -> int:
    key = _extract_public_key(pk)
    p = key["p"]
    x = _extract_private_key(sk)
    if c1 <= 0 or c1 >= p or c2 <= 0 or c2 >= p:
        raise ValueError("ciphertext components must satisfy 0 < c1,c2 < p")

    s = modexp(c1, x, p)
    s_inv = mod_inverse(s, p)
    m = (c2 * s_inv) % p
    return m


def elgamal_malleability_transform(
    pk: Dict[str, Any], c1: int, c2: int, factor: int = 2
) -> Dict[str, int]:
    key = _extract_public_key(pk)
    p = key["p"]
    return {"c1": c1, "c2": (c2 * (factor % p)) % p, "factor": factor}


def malleability_demo(
    *,
    message: int | None = None,
    factor: int = 2,
    params: Dict[str, int] | None = None,
    q_bits: int = 31,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """
    Demonstrate: (c1, factor*c2 mod p) decrypts to factor*m mod p.
    """
    active_rng = rng or system_rng()
    keys = elgamal_keygen(params=params, q_bits=q_bits, k=k, rng=active_rng)
    pk = keys["public_key"]
    sk = keys["private_key"]

    m = int(message) if message is not None else _sample_subgroup_message(pk, active_rng)
    c = elgamal_enc(pk, m, rng=active_rng)
    modified = elgamal_malleability_transform(pk, c["c1"], c["c2"], factor=factor)

    dec_original = elgamal_dec(sk, pk, c["c1"], c["c2"])
    dec_modified = elgamal_dec(sk, pk, modified["c1"], modified["c2"])
    expected = (factor % pk["p"]) * dec_original % pk["p"]

    return {
        "pa_id": PA_ID,
        "algorithm": "ElGamalMalleabilityDemo",
        "public_key": pk,
        "original_message": m,
        "original_ciphertext": {"c1": c["c1"], "c2": c["c2"]},
        "modified_ciphertext": {"c1": modified["c1"], "c2": modified["c2"]},
        "decrypted_original": dec_original,
        "decrypted_modified": dec_modified,
        "expected_modified_plaintext": expected,
        "malleability_success": dec_modified == expected,
    }


def _recover_secret_bruteforce(pk: Dict[str, int], max_steps: int | None = None) -> int | None:
    p, g, q, h = pk["p"], pk["g"], pk["q"], pk["h"]
    steps = max_steps if max_steps is not None else q
    current = 1
    for x in range(0, min(q, steps)):
        if current == h:
            return x
        current = (current * g) % p
    return None


def elgamal_ind_cpa_game(
    *,
    rounds: int = 50,
    q_bits: int = 31,
    k: int = 20,
    strategy: str = "random",
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """
    Simple IND-CPA game utility:
    - strategy='random': adversary guesses uniformly random bit.
    - strategy='bruteforce': recover x by brute force (effective on tiny groups).
    """
    if rounds <= 0:
        raise ValueError("rounds must be > 0")
    if strategy not in {"random", "bruteforce"}:
        raise ValueError("strategy must be 'random' or 'bruteforce'")

    active_rng = rng or system_rng()
    keys = elgamal_keygen(q_bits=q_bits, k=k, rng=active_rng)
    pk = keys["public_key"]
    sk = keys["private_key"]

    wins = 0
    recovered_x = None
    if strategy == "bruteforce":
        recovered_x = _recover_secret_bruteforce(pk)

    for _ in range(rounds):
        m0 = _sample_subgroup_message(pk, active_rng)
        m1 = _sample_subgroup_message(pk, active_rng)
        while m1 == m0:
            m1 = _sample_subgroup_message(pk, active_rng)

        b = active_rng.randrange(0, 2)
        challenge_msg = m1 if b == 1 else m0
        c = elgamal_enc(pk, challenge_msg, rng=active_rng)

        if strategy == "random":
            b_guess = active_rng.randrange(0, 2)
        else:
            if recovered_x is None:
                b_guess = active_rng.randrange(0, 2)
            else:
                guess_plain = elgamal_dec({"x": recovered_x}, pk, c["c1"], c["c2"])
                b_guess = 1 if guess_plain == m1 else 0

        wins += 1 if b_guess == b else 0

    win_rate = wins / rounds
    advantage = abs(win_rate - 0.5)

    return {
        "pa_id": PA_ID,
        "algorithm": "ElGamalINDCPA",
        "strategy": strategy,
        "rounds": rounds,
        "wins": wins,
        "win_rate": win_rate,
        "advantage": advantage,
        "recovered_secret_x": recovered_x if strategy == "bruteforce" else None,
        "group_bits": pk["q"].bit_length(),
        "public_key": pk,
        "private_key": sk,
    }

