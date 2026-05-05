"""PA #11 foundation: Diffie-Hellman key exchange built on PA #13 safe primes."""

from __future__ import annotations

import random
from typing import Any, Dict

from core_math.number_theory import modexp
from core_math.randomness import system_rng
from primitives.pa13_primality import gen_safe_prime

PA_ID = "PA#11"


def dh_generate_group(
    q_bits: int = 255, k: int = 40, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    """
    Generate safe-prime DH group parameters (p=2q+1) and subgroup generator g.
    """
    active_rng = rng or system_rng()
    safe_prime = gen_safe_prime(q_bits=q_bits, k=k, rng=active_rng)
    p = safe_prime["p"]
    q = safe_prime["q"]

    # For safe primes p=2q+1, (p-1)/q == 2.
    exp = 2
    g = 1
    while g == 1:
        h = active_rng.randrange(2, p - 1)
        g = modexp(h, exp, p)
        if modexp(g, q, p) != 1:
            g = 1

    return {
        "pa_id": PA_ID,
        "algorithm": "DHGroupGeneration",
        "p": p,
        "q": q,
        "g": g,
        "source": "PA#13 safe-prime generation",
    }


def dh_alice_step1(
    params: Dict[str, int], *, rng: random.Random | None = None
) -> Dict[str, int]:
    active_rng = rng or system_rng()
    q = params["q"]
    p = params["p"]
    g = params["g"]
    a = active_rng.randrange(1, q)
    A = modexp(g, a, p)
    return {"a": a, "A": A}


def dh_bob_step1(
    params: Dict[str, int], *, rng: random.Random | None = None
) -> Dict[str, int]:
    active_rng = rng or system_rng()
    q = params["q"]
    p = params["p"]
    g = params["g"]
    b = active_rng.randrange(1, q)
    B = modexp(g, b, p)
    return {"b": b, "B": B}


def dh_alice_step2(a: int, B: int, params: Dict[str, int]) -> int:
    return modexp(B, a, params["p"])


def dh_bob_step2(b: int, A: int, params: Dict[str, int]) -> int:
    return modexp(A, b, params["p"])


def mitm_demo(
    params: Dict[str, int] | None = None, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    """
    Demonstrate MITM break on unauthenticated DH.
    Eve injects E instead of A/B, creating separate secrets.
    """
    active_rng = rng or system_rng()
    group = params or dh_generate_group(q_bits=31, k=20, rng=active_rng)

    alice = dh_alice_step1(group, rng=active_rng)
    bob = dh_bob_step1(group, rng=active_rng)
    e = active_rng.randrange(1, group["q"])
    E = modexp(group["g"], e, group["p"])

    alice_secret = dh_alice_step2(alice["a"], E, group)
    bob_secret = dh_bob_step2(bob["b"], E, group)
    eve_with_alice = modexp(alice["A"], e, group["p"])
    eve_with_bob = modexp(bob["B"], e, group["p"])

    return {
        "pa_id": PA_ID,
        "algorithm": "DH-MITM-Demo",
        "group": {"p": group["p"], "q": group["q"], "g": group["g"]},
        "alice_public": alice["A"],
        "bob_public": bob["B"],
        "eve_injected_public": E,
        "alice_secret_with_eve": alice_secret,
        "eve_secret_with_alice": eve_with_alice,
        "bob_secret_with_eve": bob_secret,
        "eve_secret_with_bob": eve_with_bob,
        "mitm_success": alice_secret == eve_with_alice and bob_secret == eve_with_bob,
    }

