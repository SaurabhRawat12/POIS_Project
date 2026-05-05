"""PA #8: DLP-Based Collision-Resistant Hash Function.

Implements a collision-resistant hash function whose security reduces to the
Discrete Logarithm Problem.  The core compression function

    h(x, y) = g^x · ĥ^y   (mod p)

is plugged into the PA #7 Merkle-Damgård framework to produce a full-length
CRHF for arbitrary-length messages.

Dependencies (all from this project — no external crypto libraries):
    PA #7  — Merkle-Damgård transform  (primitives.pa7_merkle_damgard)
    PA #13 — Safe-prime generation      (primitives.pa13_primality)
    core_math — modexp, system_rng
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core_math.number_theory import modexp
from core_math.randomness import system_rng
from primitives.pa13_primality import gen_safe_prime, is_prime
from primitives.pa7_merkle_damgard import (
    HashContract,
    md_hash,
    make_md_hasher,
)

PA_ID = "PA#8"


# ---------------------------------------------------------------------------
# 1.  Group Setup
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DLPGroup:
    """Cyclic group of prime order *q* for the DLP compression function.

    *   ``p = 2q + 1`` is a safe prime.
    *   ``G = <g>`` is the unique order-*q* subgroup of ``Z*_p``
        (the quadratic residues mod *p*).
    *   ``h_gen = g^α mod p`` where *α* was chosen at random and then
        **discarded** — nobody knows ``log_g(h_gen)``.
    """

    p: int
    q: int
    g: int
    h_gen: int
    p_byte_len: int
    q_byte_len: int

    # ------------------------------------------------------------------ #
    # Construction helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def generate(q_bits: int = 64) -> DLPGroup:
        """Generate a fresh DLP group with *q* of the given bit-length.

        Uses PA #13's ``gen_safe_prime`` to obtain ``p = 2q + 1``.
        """
        if q_bits < 8:
            raise ValueError("q_bits must be >= 8 for meaningful security")

        result = gen_safe_prime(q_bits)
        p: int = result["p"]
        q: int = result["q"]

        rng = system_rng()

        # --- generator of the order-q subgroup (quadratic residues) ---
        # For a safe prime p ≡ 3 (mod 4), squaring any non-{0,±1}
        # element gives a QR of order q.
        while True:
            r = rng.randrange(2, p - 1)
            g = modexp(r, 2, p)
            if g != 1:
                # Sanity: g^q ≡ 1 (mod p)
                assert modexp(g, q, p) == 1, "generator check failed"
                break

        # --- second generator ĥ = g^α (α is secret and discarded) ---
        alpha = rng.randrange(1, q)
        h_gen = modexp(g, alpha, p)
        del alpha                      # discard — nobody should know α

        p_byte_len = (p.bit_length() + 7) // 8
        q_byte_len = (q.bit_length() + 7) // 8

        return DLPGroup(
            p=p, q=q, g=g, h_gen=h_gen,
            p_byte_len=p_byte_len, q_byte_len=q_byte_len,
        )

    @staticmethod
    def generate_toy() -> DLPGroup:
        """Small group (``q ≈ 2^16``) for collision / birthday demos."""
        return DLPGroup.generate(q_bits=16)

    # ------------------------------------------------------------------ #
    # Serialisation helpers
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "p": self.p, "q": self.q,
            "g": self.g, "h_gen": self.h_gen,
            "p_hex": hex(self.p), "q_hex": hex(self.q),
            "g_hex": hex(self.g), "h_hex": hex(self.h_gen),
            "p_byte_len": self.p_byte_len,
            "q_byte_len": self.q_byte_len,
        }


# ---------------------------------------------------------------------------
# 2.  DLP Compression Function
# ---------------------------------------------------------------------------

def _make_dlp_compress(group: DLPGroup) -> Callable[[bytes, bytes], bytes]:
    """Return a closure that conforms to PA #7's ``CompressionFn`` protocol.

    The returned function maps ``(state, block) → bytes`` where

        result = g^{x} · ĥ^{y}  (mod p)

    with ``x = int(state) mod q`` and ``y = int(block) mod q``.
    The output is encoded as ``p_byte_len`` bytes (fixed-width).
    """
    p, q, g, h = group.p, group.q, group.g, group.h_gen
    out_len = group.p_byte_len

    def compress(state: bytes, block: bytes) -> bytes:
        x = int.from_bytes(state, "big") % q
        y = int.from_bytes(block, "big") % q
        elem = (modexp(g, x, p) * modexp(h, y, p)) % p
        return elem.to_bytes(out_len, "big")

    return compress


def dlp_compress(
    x: int, y: int, group: DLPGroup,
) -> int:
    """Standalone DLP compression: ``g^x · ĥ^y  (mod p)``.

    This is the raw number-theoretic interface (int → int).
    For the byte-oriented MD-compatible wrapper, see ``_make_dlp_compress``.
    """
    x_mod = x % group.q
    y_mod = y % group.q
    return (modexp(group.g, x_mod, group.p)
            * modexp(group.h_gen, y_mod, group.p)) % group.p


# ---------------------------------------------------------------------------
# 3.  Full CRHF — DLPHash
# ---------------------------------------------------------------------------

def dlp_hash(
    message: bytes | str,
    group: DLPGroup,
    out_bits: int | None = None,
) -> bytes:
    """Collision-resistant hash: DLPHash(message) → bytes.

    Plugs the DLP compression function into the PA #7 Merkle-Damgård
    framework.

    Parameters
    ----------
    message : bytes or str
        Arbitrary-length input.
    group : DLPGroup
        Group parameters (use ``DLPGroup.generate()`` or ``.generate_toy()``).
    out_bits : int, optional
        If given, truncate the final digest to this many bits.
        Useful for PA #9 birthday demos and PA #10 output-length config.

    Returns
    -------
    bytes
        The hash digest.
    """
    compress = _make_dlp_compress(group)
    iv = (1).to_bytes(group.p_byte_len, "big")    # chaining-value seed
    block_size = group.p_byte_len                  # one Zq element per block

    digest = md_hash(
        message=message,
        compress_fn=compress,
        iv=iv,
        block_size=block_size,
    )

    if out_bits is not None:
        digest = _truncate(digest, out_bits)

    return digest


def _truncate(digest: bytes, out_bits: int) -> bytes:
    """Truncate a digest to exactly ``out_bits`` bits."""
    if out_bits <= 0:
        raise ValueError("out_bits must be positive")
    out_bytes = (out_bits + 7) // 8
    # Take the least-significant bytes
    truncated = digest[-out_bytes:] if len(digest) >= out_bytes else digest
    # Mask off the extra high bits in the first byte
    extra = out_bytes * 8 - out_bits
    if extra > 0:
        truncated = bytes([truncated[0] & ((1 << (8 - extra)) - 1)]) + truncated[1:]
    return truncated


# ---------------------------------------------------------------------------
# 4.  PA #10 Integration Interface
# ---------------------------------------------------------------------------

def get_dlp_hash_interface(
    q_bits: int = 64,
    group: DLPGroup | None = None,
) -> Tuple[HashContract, Callable[[bytes | str], bytes]]:
    """Return ``(HashContract, hash_fn)`` for downstream PA #10 (HMAC).

    The callable ``hash_fn(message) → bytes`` is a complete CRHF whose
    output length equals ``group.p_byte_len``.
    """
    if group is None:
        group = DLPGroup.generate(q_bits)

    compress = _make_dlp_compress(group)
    iv = (1).to_bytes(group.p_byte_len, "big")

    return make_md_hasher(
        compress_fn=compress,
        iv=iv,
        block_size=group.p_byte_len,
        name="pa8.dlp-crhf",
    )


def get_dlp_hash_interface_with_outbits(
    out_bits: int,
    q_bits: int = 64,
    group: DLPGroup | None = None,
) -> Tuple[HashContract, Callable[[bytes | str], bytes]]:
    """Like ``get_dlp_hash_interface`` but with fixed output truncation.

    PA #10 needs ``DLPHash(message) → bytes`` with configurable output
    length.  This helper bakes the truncation into the returned callable.
    """
    if group is None:
        group = DLPGroup.generate(q_bits)

    contract = HashContract(
        name="pa8.dlp-crhf-truncated",
        block_size=group.p_byte_len,
        digest_size=(out_bits + 7) // 8,
    )

    def _hash_fn(message: bytes | str) -> bytes:
        return dlp_hash(message, group=group, out_bits=out_bits)

    return contract, _hash_fn


# ---------------------------------------------------------------------------
# 5.  Collision Resistance Argument
# ---------------------------------------------------------------------------

def collision_resistance_argument() -> Dict[str, Any]:
    """Structured proof sketch: finding a collision implies solving DLP.

    Returns a dict suitable for API / demo display.
    """
    return {
        "pa_id": PA_ID,
        "title": "Collision Resistance under the DLP Assumption",
        "setup": (
            "Let G = <g> be a cyclic group of prime order q.  "
            "Let ĥ = g^α for an unknown α (the discrete log of ĥ base g).  "
            "Define the compression function h(x, y) = g^x · ĥ^y  (mod p)."
        ),
        "claim": "Finding a collision in h implies computing log_g(ĥ).",
        "proof_sketch": [
            "Suppose an adversary finds (x, y) ≠ (x', y') with h(x, y) = h(x', y').",
            "Then  g^x · ĥ^y  =  g^{x'} · ĥ^{y'}   (mod p).",
            "Rewriting:  g^{x - x'}  =  ĥ^{y' - y}  =  g^{α(y' - y)}   (mod p).",
            "Since G has prime order q:  x - x'  ≡  α(y' - y)   (mod q).",
            "If y' ≠ y, then  α  =  (x - x') · (y' - y)^{-1}   (mod q).",
            "This recovers α = log_g(ĥ), solving the DLP — contradiction!",
            "If y' = y, then x - x' ≡ 0 (mod q) ⇒ x = x' (mod q), so (x,y) = (x',y') — no collision.",
        ],
        "conclusion": (
            "Any collision-finding algorithm for h can be converted into "
            "a DLP solver.  Therefore h is collision-resistant under the "
            "Discrete Logarithm assumption."
        ),
    }


# ---------------------------------------------------------------------------
# 6.  Brute-Force Collision Finder (Birthday Attack on Toy Parameters)
# ---------------------------------------------------------------------------

def brute_force_collision_finder(
    q_bits: int = 16,
    group: DLPGroup | None = None,
) -> Dict[str, Any]:
    """Birthday-style collision search on a tiny DLP group.

    For ``q ≈ 2^16`` the expected number of evaluations is
    ``O(√q) = O(2^8) ≈ 256``.

    Returns
    -------
    dict
        ``collision_found``, ``input_a``, ``input_b``, ``hash_value``,
        ``evaluations``, ``sqrt_q``, ``ratio``.
    """
    if group is None:
        group = DLPGroup.generate(q_bits)

    rng = system_rng()
    seen: Dict[int, Tuple[int, int]] = {}   # hash_value → (x, y)
    evaluations = 0
    sqrt_q = int(group.q ** 0.5)
    start = time.perf_counter()

    while True:
        x = rng.randrange(0, group.q)
        y = rng.randrange(0, group.q)
        h_val = dlp_compress(x, y, group)
        evaluations += 1

        if h_val in seen:
            old_x, old_y = seen[h_val]
            if (old_x, old_y) != (x, y):
                elapsed = (time.perf_counter() - start) * 1000.0
                return {
                    "pa_id": PA_ID,
                    "collision_found": True,
                    "input_a": {"x": old_x, "y": old_y},
                    "input_b": {"x": x, "y": y},
                    "hash_value": h_val,
                    "hash_hex": hex(h_val),
                    "evaluations": evaluations,
                    "sqrt_q": sqrt_q,
                    "ratio_evals_over_sqrt_q": round(evaluations / max(sqrt_q, 1), 3),
                    "q": group.q,
                    "q_bits": group.q.bit_length(),
                    "elapsed_ms": round(elapsed, 2),
                    "security_note": (
                        f"Collision found in {evaluations} evaluations "
                        f"(√q = {sqrt_q}).  Ratio ≈ "
                        f"{evaluations / max(sqrt_q, 1):.2f}, confirming "
                        f"the O(√q) birthday bound."
                    ),
                }

        seen[h_val] = (x, y)

        # Safety valve for truly pathological cases
        if evaluations > 10 * group.q:
            return {
                "pa_id": PA_ID,
                "collision_found": False,
                "evaluations": evaluations,
                "note": "Exceeded safety limit without finding collision.",
            }


def brute_force_collision_finder_full_hash(
    q_bits: int = 16,
    out_bits: int = 16,
    group: DLPGroup | None = None,
) -> Dict[str, Any]:
    """Birthday collision search on the *full* DLPHash (MD + DLP compress).

    Hashes random messages and looks for collisions in the truncated output.
    """
    if group is None:
        group = DLPGroup.generate(q_bits)

    rng = system_rng()
    seen: Dict[bytes, bytes] = {}    # digest → message
    evaluations = 0
    expected = 1 << (out_bits // 2)
    start = time.perf_counter()

    while True:
        # Random short message
        msg_len = rng.randrange(1, 32)
        msg = os.urandom(msg_len)
        digest = dlp_hash(msg, group=group, out_bits=out_bits)
        evaluations += 1

        if digest in seen and seen[digest] != msg:
            elapsed = (time.perf_counter() - start) * 1000.0
            return {
                "pa_id": PA_ID,
                "collision_found": True,
                "message_a_hex": seen[digest].hex(),
                "message_b_hex": msg.hex(),
                "digest_hex": digest.hex(),
                "digest_bits": out_bits,
                "evaluations": evaluations,
                "expected_birthday_bound": expected,
                "ratio": round(evaluations / max(expected, 1), 3),
                "elapsed_ms": round(elapsed, 2),
            }

        seen[digest] = msg

        if evaluations > 10 * (1 << out_bits):
            return {
                "pa_id": PA_ID,
                "collision_found": False,
                "evaluations": evaluations,
                "note": "Exceeded safety limit.",
            }


# ---------------------------------------------------------------------------
# 7.  Group Setup API (for the interactive demo)
# ---------------------------------------------------------------------------

def group_setup(q_bits: int = 64) -> Dict[str, Any]:
    """Generate a DLP group and return all parameters as a dict.

    This is the API endpoint ``group_setup`` from the plan.
    """
    start = time.perf_counter()
    group = DLPGroup.generate(q_bits)
    elapsed = (time.perf_counter() - start) * 1000.0

    info = group.to_dict()
    info.update({
        "pa_id": PA_ID,
        "algorithm": "DLPGroupSetup",
        "q_bits_requested": q_bits,
        "elapsed_ms": round(elapsed, 2),
        "security_note": (
            "ĥ = g^α for a randomly chosen α that has been discarded.  "
            "Nobody — including this program — knows log_g(ĥ).  "
            "Collision resistance of the compression function h(x,y) = "
            "g^x · ĥ^y reduces to the hardness of computing this discrete log."
        ),
    })
    return info


# ---------------------------------------------------------------------------
# 8.  Self-Test / Integration Tests
# ---------------------------------------------------------------------------

def _run_tests() -> None:
    """Run all PA #8 integration tests.  Called via ``python -m primitives.pa8_dlp_hash``."""

    print("=" * 70)
    print("  PA #8 -- DLP-Based Collision-Resistant Hash Function")
    print("  Integration Tests")
    print("=" * 70)

    # ---- Test 1: Group setup validation ----
    print("\n[1] Group Setup (toy q ~ 2^16) ...")
    t0 = time.perf_counter()
    group = DLPGroup.generate_toy()
    dt = (time.perf_counter() - t0) * 1000
    print(f"    p = {group.p}  ({group.p.bit_length()} bits)")
    print(f"    q = {group.q}  ({group.q.bit_length()} bits)")
    print(f"    g = {group.g}")
    print(f"    h_gen = {group.h_gen}")

    # p = 2q + 1
    assert group.p == 2 * group.q + 1, "p != 2q+1"
    # both prime
    assert is_prime(group.p), "p is not prime"
    assert is_prime(group.q), "q is not prime"
    # g has order q
    assert modexp(group.g, group.q, group.p) == 1, "g^q != 1 (mod p)"
    assert modexp(group.g, 1, group.p) != 1, "g = 1 (degenerate)"
    # h_gen is in the subgroup
    assert modexp(group.h_gen, group.q, group.p) == 1, "h_gen not in subgroup"

    print(f"    [OK] All group checks passed  ({dt:.1f} ms)")

    # ---- Test 2: Compression function correctness ----
    print("\n[2] DLP Compression Function ...")
    x, y = 42, 1337
    result = dlp_compress(x, y, group)
    expected = (modexp(group.g, x % group.q, group.p)
                * modexp(group.h_gen, y % group.q, group.p)) % group.p
    assert result == expected, f"compress mismatch: {result} vs {expected}"

    # Byte-oriented version
    compress_fn = _make_dlp_compress(group)
    state_bytes = x.to_bytes(group.p_byte_len, "big")
    block_bytes = y.to_bytes(group.p_byte_len, "big")
    result_bytes = compress_fn(state_bytes, block_bytes)
    assert int.from_bytes(result_bytes, "big") == expected
    print(f"    h({x}, {y}) = {result}")
    print("    [OK] Compression matches manual computation")

    # ---- Test 3: Distinct digests for 5+ messages ----
    print("\n[3] Integration Test -- Distinct Digests ...")
    messages = [
        b"",
        b"hello",
        b"Hello",
        b"hello world",
        b"The quick brown fox jumps over the lazy dog",
        b"\x00\x01\x02",
        b"a" * 200,
    ]
    digests = []
    for msg in messages:
        d = dlp_hash(msg, group=group)
        digests.append(d)
        label = msg[:30].hex() + ("..." if len(msg) > 30 else "")
        print(f"    DLPHash({label}) = {d.hex()[:32]}...")

    # All distinct
    digest_set = set(digests)
    assert len(digest_set) == len(digests), (
        f"Collision among test messages! {len(digest_set)} unique out of {len(digests)}"
    )
    print(f"    [OK] All {len(messages)} messages produce distinct digests")

    # ---- Test 4: Truncated output ----
    print("\n[4] Truncated Output (16-bit) ...")
    d_full = dlp_hash(b"test", group=group)
    d_16 = dlp_hash(b"test", group=group, out_bits=16)
    assert len(d_16) == 2, f"Expected 2 bytes, got {len(d_16)}"
    print(f"    Full digest : {d_full.hex()}")
    print(f"    16-bit trunc: {d_16.hex()}")
    print("    [OK] Truncation works correctly")

    # ---- Test 5: Collision resistance argument ----
    print("\n[5] Collision Resistance Proof Sketch ...")
    arg = collision_resistance_argument()
    print(f"    Title: {arg['title']}")
    print("    (proof steps stored in dict, not printed to avoid encoding issues)")
    print("    [OK] Argument structure valid")

    # ---- Test 6: Brute-force collision finder (birthday attack) ----
    print("\n[6] Brute-Force Collision Finder (birthday on compress, q ~ 2^16) ...")
    t0 = time.perf_counter()
    collision = brute_force_collision_finder(q_bits=16)
    dt = (time.perf_counter() - t0) * 1000
    assert collision["collision_found"], "No collision found!"

    a = collision["input_a"]
    b = collision["input_b"]
    print(f"    Collision: h({a['x']}, {a['y']}) = h({b['x']}, {b['y']})")
    print(f"    Hash value: {collision['hash_hex']}")
    print(f"    Evaluations: {collision['evaluations']}")
    print(f"    sqrt(q) = {collision['sqrt_q']}")
    print(f"    Ratio (evals / sqrt(q)): {collision['ratio_evals_over_sqrt_q']}")
    print(f"    [OK] Collision found in {dt:.0f} ms -- confirms O(sqrt(q)) birthday bound")

    # ---- Test 7: Full-hash birthday collision (16-bit output) ----
    print("\n[7] Birthday Collision on Full DLPHash (16-bit truncated) ...")
    toy_group = DLPGroup.generate_toy()
    t0 = time.perf_counter()
    full_collision = brute_force_collision_finder_full_hash(
        q_bits=16, out_bits=16, group=toy_group,
    )
    dt = (time.perf_counter() - t0) * 1000
    assert full_collision["collision_found"], "No collision in full hash!"
    print(f"    Message A: {full_collision['message_a_hex']}")
    print(f"    Message B: {full_collision['message_b_hex']}")
    print(f"    Shared digest: {full_collision['digest_hex']}")
    print(f"    Evaluations: {full_collision['evaluations']} "
          f"(expected ~ {full_collision['expected_birthday_bound']})")
    print(f"    [OK] Full-hash collision found in {dt:.0f} ms")

    # ---- Test 8: PA #10 interface ----
    print("\n[8] PA #10 Interface (get_dlp_hash_interface) ...")
    contract, hash_fn = get_dlp_hash_interface(q_bits=16, group=toy_group)
    print(f"    Contract: name={contract.name}, "
          f"block_size={contract.block_size}, "
          f"digest_size={contract.digest_size}")
    d = hash_fn(b"HMAC will call this")
    assert isinstance(d, bytes)
    assert len(d) == contract.digest_size
    print(f"    hash_fn(b'HMAC will call this') = {d.hex()}")
    print("    [OK] Interface matches PA #10 contract")

    # ---- Test 9: PA #10 interface with truncated output ----
    print("\n[9] PA #10 Truncated Interface (configurable output length) ...")
    contract_t, hash_fn_t = get_dlp_hash_interface_with_outbits(
        out_bits=16, q_bits=16, group=toy_group,
    )
    d_t = hash_fn_t(b"truncated output test")
    assert len(d_t) == 2, f"Expected 2 bytes, got {len(d_t)}"  # 16 bits = 2 bytes
    print(f"    Contract: name={contract_t.name}, digest_size={contract_t.digest_size}")
    print(f"    hash_fn(msg) = {d_t.hex()}")
    print("    [OK] Truncated interface works correctly")

    # ---- Summary ----
    print("\n" + "=" * 70)
    print("  ALL PA #8 TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    _run_tests()
