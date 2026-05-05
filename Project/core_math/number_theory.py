"""Number-theoretic helpers used across primitives/protocols."""

from __future__ import annotations

from typing import Tuple


def modexp(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation."""
    if mod <= 0:
        raise ValueError("mod must be a positive integer")
    if exp < 0:
        raise ValueError("exp must be non-negative")

    base %= mod
    result = 1 % mod
    power = exp
    while power:
        if power & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        power >>= 1
    return result


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (gcd, x, y) for ax + by = gcd."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def mod_inverse(a: int, n: int) -> int:
    """Compute a^{-1} mod n using egcd."""
    if n <= 0:
        raise ValueError("modulus n must be positive")
    g, x, _ = egcd(a, n)
    if abs(g) != 1:
        raise ValueError(f"mod inverse does not exist for a={a}, n={n}")
    return x % n


def decompose(n_minus_one: int) -> Tuple[int, int]:
    """Decompose n-1 into 2^s * d with d odd."""
    if n_minus_one <= 0:
        raise ValueError("n_minus_one must be a positive integer")

    s = 0
    d = n_minus_one
    while d % 2 == 0:
        s += 1
        d //= 2
    return s, d

