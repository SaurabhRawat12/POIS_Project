"""PA #9: Birthday Attack (Collision Finding).

Implements both the naive (dictionary-based) and Floyd's cycle-finding
birthday attacks, runs them against toy hashes and the PA #8 DLP hash,
and produces the empirical birthday curve data for verification against
the theoretical prediction  1 - e^{-k(k-1) / 2^{n+1}}.

Dependencies:
    PA #8  -- DLP-based CRHF          (primitives.pa8_dlp_hash)
    PA #7  -- Merkle-Damgard framework (primitives.pa7_merkle_damgard)
    PA #13 -- Primality testing        (primitives.pa13_primality)
    core_math -- modexp, system_rng
"""

from __future__ import annotations

import math
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core_math.randomness import system_rng
from primitives.pa8_dlp_hash import DLPGroup, dlp_hash

PA_ID = "PA#9"


# ---------------------------------------------------------------------------
# 1.  Toy Hash Functions (deliberately weak, for demo)
# ---------------------------------------------------------------------------

def toy_hash(message: bytes, n: int) -> int:
    """Deliberately weak hash: truncate a simple mix to *n* bits.

    This is NOT cryptographically secure -- it exists solely so we can
    run birthday attacks at small output sizes (n = 8, 12, 16).
    """
    if n <= 0 or n > 64:
        raise ValueError("n must be in [1, 64]")
    mask = (1 << n) - 1

    h = 0x5A5A5A5A
    for byte in message:
        h ^= byte
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF
        h = (h * 0x9E3779B1) & 0xFFFFFFFF
    return h & mask


def _make_toy_hash_fn(n: int) -> Callable[[bytes], int]:
    """Return a callable ``f(message) -> int`` with *n*-bit output."""
    def fn(msg: bytes) -> int:
        return toy_hash(msg, n)
    return fn


# ---------------------------------------------------------------------------
# 2.  Naive Birthday Algorithm (dict-based)
# ---------------------------------------------------------------------------

def birthday_attack(
    hash_fn: Callable[[bytes], int],
    n: int,
    max_trials: int | None = None,
) -> Dict[str, Any]:
    """Naive birthday attack: hash random inputs, store in a dict.

    Parameters
    ----------
    hash_fn : callable
        ``f(message: bytes) -> int`` producing an *n*-bit hash.
    n : int
        Output bit-length of *hash_fn*.
    max_trials : int, optional
        Safety cap.  Defaults to ``10 * 2^n``.

    Returns
    -------
    dict
        ``collision_found``, ``x``, ``x_prime``, ``hash_value``,
        ``evaluations``, ``expected`` (= 2^{n/2}).
    """
    if max_trials is None:
        max_trials = 10 * (1 << n)

    seen: Dict[int, bytes] = {}      # hash_value -> message
    evaluations = 0
    expected = int(math.pow(2, n / 2))
    start = time.perf_counter()

    while evaluations < max_trials:
        # Random message (variable length 1-32 bytes)
        msg = os.urandom((evaluations % 31) + 1)
        h = hash_fn(msg)
        evaluations += 1

        if h in seen and seen[h] != msg:
            elapsed = (time.perf_counter() - start) * 1000.0
            return {
                "pa_id": PA_ID,
                "algorithm": "NaiveBirthday",
                "collision_found": True,
                "x_hex": seen[h].hex(),
                "x_prime_hex": msg.hex(),
                "hash_value": h,
                "hash_hex": hex(h),
                "n_bits": n,
                "evaluations": evaluations,
                "expected_2_n_half": expected,
                "ratio": round(evaluations / max(expected, 1), 3),
                "elapsed_ms": round(elapsed, 2),
            }

        seen[h] = msg

    elapsed = (time.perf_counter() - start) * 1000.0
    return {
        "pa_id": PA_ID,
        "algorithm": "NaiveBirthday",
        "collision_found": False,
        "n_bits": n,
        "evaluations": evaluations,
        "expected_2_n_half": expected,
        "elapsed_ms": round(elapsed, 2),
        "note": "No collision found within max_trials.",
    }


# ---------------------------------------------------------------------------
# 3.  Floyd's Cycle-Finding Attack (space-efficient)
# ---------------------------------------------------------------------------

def floyd_cycle_attack(
    hash_fn: Callable[[bytes], int],
    n: int,
    max_steps: int | None = None,
) -> Dict[str, Any]:
    """Floyd's tortoise-and-hare collision finder.

    Treats the hash as a function ``f: {0,1}^n -> {0,1}^n`` by encoding
    the *n*-bit output as the next input.  Finds a cycle and then extracts
    the collision.  Space: O(1).  Time: O(2^{n/2}).

    Parameters
    ----------
    hash_fn : callable
        ``f(message: bytes) -> int`` producing an *n*-bit hash.
    n : int
        Output bit-length.
    max_steps : int, optional
        Safety cap.  Defaults to ``10 * 2^n``.
    """
    if max_steps is None:
        max_steps = 10 * (1 << n)

    byte_len = (n + 7) // 8
    expected = int(math.pow(2, n / 2))
    start = time.perf_counter()

    def f(x_int: int) -> int:
        """One step: encode int as bytes, hash, return int."""
        return hash_fn(x_int.to_bytes(byte_len, "big"))

    # -- Phase 1: find meeting point inside the cycle --
    x0 = int.from_bytes(os.urandom(byte_len), "big") & ((1 << n) - 1)
    tortoise = f(x0)
    hare = f(f(x0))
    steps = 3  # 1 for tortoise, 2 for hare

    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
        steps += 3
        if steps > max_steps:
            elapsed = (time.perf_counter() - start) * 1000.0
            return {
                "pa_id": PA_ID,
                "algorithm": "FloydCycle",
                "collision_found": False,
                "n_bits": n,
                "evaluations": steps,
                "expected_2_n_half": expected,
                "elapsed_ms": round(elapsed, 2),
                "note": "Exceeded max_steps without finding cycle.",
            }

    # -- Phase 2: find the collision --
    # Walk two pointers from x0 and the meeting point. Keep track
    # of the *previous* value so that when f(prev_a) == f(prev_b)
    # and prev_a != prev_b, we have our collision.
    ptr_a = x0
    ptr_b = hare  # == tortoise, inside the cycle

    # First, move ptr_a from x0 and ptr_b from the meeting point
    # simultaneously until they meet -- this finds mu (cycle start).
    while ptr_a != ptr_b:
        ptr_a = f(ptr_a)
        ptr_b = f(ptr_b)
        steps += 2

    mu = ptr_a  # cycle start

    # Now we know the sequence from x0 enters the cycle at mu.
    # Walk from x0, keeping (prev, curr). Also walk around the cycle
    # from mu. Find where two distinct inputs map to the same output.
    # The collision is at the junction: the tail path and the cycle
    # path both reach mu, so we need the two predecessors of mu.

    # Find the last value on the tail before mu:
    if x0 == mu:
        # x0 is already on the cycle; find cycle length and the
        # predecessor of mu on the cycle instead.
        tail_pred = None
    else:
        prev = x0
        curr = f(x0)
        steps += 1
        while curr != mu:
            prev = curr
            curr = f(curr)
            steps += 1
        tail_pred = prev  # f(tail_pred) == mu

    # Find the predecessor of mu on the cycle (walk the cycle):
    cycle_pred = mu
    nxt = f(mu)
    steps += 1
    while nxt != mu:
        cycle_pred = nxt
        nxt = f(nxt)
        steps += 1
    # Now f(cycle_pred) == mu

    if tail_pred is not None and tail_pred != cycle_pred:
        # f(tail_pred) == f(cycle_pred) == mu, and they differ
        x1, x2 = tail_pred, cycle_pred
        h_val = mu
    else:
        # x0 is on the cycle or tail_pred == cycle_pred (degenerate).
        # Fall back: walk the cycle and find any two distinct inputs
        # that hash to the same output using a small dict.
        seen_map: Dict[int, int] = {}
        current = mu
        found = False
        for _ in range(1 << n):
            output = f(current)
            steps += 1
            if output in seen_map and seen_map[output] != current:
                x1 = seen_map[output]
                x2 = current
                h_val = output
                found = True
                break
            seen_map[output] = current
            current = output

        if not found:
            elapsed = (time.perf_counter() - start) * 1000.0
            return {
                "pa_id": PA_ID,
                "algorithm": "FloydCycle",
                "collision_found": False,
                "n_bits": n,
                "evaluations": steps,
                "note": "Could not extract collision from cycle.",
                "elapsed_ms": round(elapsed, 2),
            }

    elapsed = (time.perf_counter() - start) * 1000.0
    return {
        "pa_id": PA_ID,
        "algorithm": "FloydCycle",
        "collision_found": True,
        "x_int": x1,
        "x_prime_int": x2,
        "x_hex": x1.to_bytes(byte_len, "big").hex(),
        "x_prime_hex": x2.to_bytes(byte_len, "big").hex(),
        "hash_value": h_val,
        "hash_hex": hex(h_val),
        "n_bits": n,
        "evaluations": steps,
        "expected_2_n_half": expected,
        "ratio": round(steps / max(expected, 1), 3),
        "elapsed_ms": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# 4.  Attack Truncated DLP Hash (PA #8)
# ---------------------------------------------------------------------------

def attack_truncated_dlp_hash(
    n: int = 16,
    q_bits: int = 16,
    group: DLPGroup | None = None,
) -> Dict[str, Any]:
    """Run the naive birthday attack on PA #8's DLP hash truncated to *n* bits.

    This concretely shows that even a provably-secure hash is broken at
    the birthday bound when its output is too short.

    Returns
    -------
    dict
        Collision pair, evaluation count, ratio vs 2^{n/2}.
    """
    if group is None:
        group = DLPGroup.generate(q_bits)

    def dlp_hash_truncated(msg: bytes) -> int:
        digest = dlp_hash(msg, group=group, out_bits=n)
        return int.from_bytes(digest, "big")

    result = birthday_attack(dlp_hash_truncated, n)
    result["algorithm"] = "NaiveBirthday_on_DLPHash"
    result["underlying_hash"] = "PA#8 DLP-CRHF"
    result["truncated_to_bits"] = n
    result["group_q"] = group.q
    result["group_q_bits"] = group.q.bit_length()
    result["security_note"] = (
        f"Even though the DLP hash is provably collision-resistant under the "
        f"DL assumption, truncating to {n} bits reduces the output space to "
        f"2^{n}, making birthday collisions trivial at ~2^{n // 2} = "
        f"{1 << (n // 2)} evaluations."
    )
    return result


# ---------------------------------------------------------------------------
# 5.  Empirical Birthday Curve
# ---------------------------------------------------------------------------

def birthday_trials(
    n: int,
    trials: int = 100,
    hash_fn: Callable[[bytes], int] | None = None,
) -> Dict[str, Any]:
    """Run *trials* independent birthday experiments for output size *n*.

    For each trial, count the number of hash evaluations until the first
    collision.  Returns the full distribution plus summary statistics.

    Parameters
    ----------
    n : int
        Output bit-length.
    trials : int
        Number of independent experiments.
    hash_fn : callable, optional
        Custom hash.  Defaults to ``toy_hash(msg, n)``.
    """
    if hash_fn is None:
        hash_fn = _make_toy_hash_fn(n)

    counts: List[int] = []
    start = time.perf_counter()

    for _ in range(trials):
        seen: Dict[int, bool] = {}
        k = 0
        while True:
            msg = os.urandom((k % 31) + 1)
            h = hash_fn(msg)
            k += 1
            if h in seen:
                counts.append(k)
                break
            seen[h] = True

    elapsed = (time.perf_counter() - start) * 1000.0
    expected = math.sqrt(2 ** n)
    mean_k = sum(counts) / len(counts)

    return {
        "pa_id": PA_ID,
        "n_bits": n,
        "trials": trials,
        "counts": counts,
        "mean_evaluations": round(mean_k, 2),
        "median_evaluations": sorted(counts)[trials // 2],
        "min_evaluations": min(counts),
        "max_evaluations": max(counts),
        "expected_sqrt_2n": round(expected, 2),
        "ratio_mean_over_expected": round(mean_k / expected, 3),
        "elapsed_ms": round(elapsed, 2),
    }


def empirical_birthday_curve(
    n_values: List[int] | None = None,
    trials: int = 100,
) -> Dict[str, Any]:
    """Run ``birthday_trials`` for each *n* in *n_values*.

    Produces the data needed to plot evaluations vs 2^{n/2} and overlay
    the theoretical collision probability curve.

    Default *n_values*: ``[8, 10, 12, 14, 16]``.
    """
    if n_values is None:
        n_values = [8, 10, 12, 14, 16]

    results: List[Dict[str, Any]] = []
    start = time.perf_counter()

    for n in n_values:
        r = birthday_trials(n, trials=trials)
        results.append(r)

    elapsed = (time.perf_counter() - start) * 1000.0

    # Theoretical curve data for each n:
    # P(collision after k hashes) = 1 - e^{-k(k-1) / 2^{n+1}}
    theory: Dict[int, List[Dict[str, float]]] = {}
    for n in n_values:
        points = []
        two_n = 1 << n
        max_k = int(3 * math.sqrt(two_n))
        step = max(1, max_k // 100)
        for k in range(1, max_k + 1, step):
            prob = 1.0 - math.exp(-k * (k - 1) / (2.0 * two_n))
            points.append({"k": k, "probability": round(prob, 6)})
        theory[n] = points

    return {
        "pa_id": PA_ID,
        "n_values": n_values,
        "trials_per_n": trials,
        "results": results,
        "theoretical_curves": theory,
        "elapsed_ms": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# 6.  MD5 / SHA-1 Context
# ---------------------------------------------------------------------------

def md5_sha1_context() -> Dict[str, Any]:
    """Compute 2^{n/2} for MD5 (n=128) and SHA-1 (n=160).

    Express the result in terms of modern CPU hashing speed
    (~10^9 hashes/sec) and estimate the time to find a collision.
    """
    hashes_per_sec = 1_000_000_000  # 10^9

    def analysis(name: str, n: int) -> Dict[str, Any]:
        birthday_bound = 2 ** (n // 2)
        seconds = birthday_bound / hashes_per_sec
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24
        years = days / 365.25

        return {
            "hash": name,
            "output_bits": n,
            "birthday_bound_2_n_half": f"2^{n // 2}",
            "birthday_bound_decimal": f"{birthday_bound:.2e}",
            "at_1e9_hashes_per_sec": {
                "seconds": f"{seconds:.2e}",
                "hours": f"{hours:.2e}",
                "years": f"{years:.2e}",
            },
            "status": (
                "BROKEN" if years < 1
                else "DEPRECATED" if years < 1e6
                else "SECURE"
            ),
            "note": "",
        }

    md5 = analysis("MD5", 128)
    md5["note"] = (
        "MD5 birthday bound is 2^64 ~ 1.8e19 hashes. At 10^9 hashes/sec "
        "this takes ~585 years on a single CPU -- but is trivially parallelizable. "
        "The first real MD5 collision was found in 2004 by Wang et al. "
        "MD5 is considered BROKEN for collision resistance."
    )
    md5["status"] = "BROKEN"

    sha1 = analysis("SHA-1", 160)
    sha1["note"] = (
        "SHA-1 birthday bound is 2^80 ~ 1.2e24 hashes. At 10^9 hashes/sec "
        "this takes ~3.8e7 years on a single CPU. However, the SHAttered attack "
        "(2017) found a collision with ~2^63 computations using structural "
        "weaknesses. SHA-1 is DEPRECATED."
    )
    sha1["status"] = "DEPRECATED"

    sha256 = analysis("SHA-256", 256)
    sha256["note"] = (
        "SHA-256 birthday bound is 2^128 ~ 3.4e38 hashes. At 10^9 hashes/sec "
        "this takes ~1.1e22 years -- far beyond the age of the universe (~1.4e10 "
        "years). SHA-256 is considered SECURE."
    )

    return {
        "pa_id": PA_ID,
        "cpu_speed_assumption": f"{hashes_per_sec:.0e} hashes/sec",
        "analyses": [md5, sha1, sha256],
        "takeaway": (
            "Collision resistance requires output length >= 256 bits for "
            "long-term security.  MD5 (128-bit) is broken, SHA-1 (160-bit) "
            "is deprecated, and SHA-256 (256-bit) remains secure."
        ),
    }


# ---------------------------------------------------------------------------
# 7.  Self-Test / Integration Tests
# ---------------------------------------------------------------------------

def _run_tests() -> None:
    """Run all PA #9 integration tests."""

    print("=" * 70)
    print("  PA #9 -- Birthday Attack (Collision Finding)")
    print("  Integration Tests")
    print("=" * 70)

    # ---- Test 1: Naive birthday on toy hash (n=8, 12, 16) ----
    print("\n[1] Naive Birthday Attack on Toy Hash ...")
    for n in [8, 12, 16]:
        h_fn = _make_toy_hash_fn(n)
        result = birthday_attack(h_fn, n)
        assert result["collision_found"], f"No collision for n={n}!"
        print(f"    n={n:2d}  evals={result['evaluations']:5d}  "
              f"expected~{result['expected_2_n_half']:5d}  "
              f"ratio={result['ratio']:.2f}")
    print("    [OK] All toy-hash collisions found near 2^(n/2)")

    # ---- Test 2: Floyd's cycle attack on toy hash ----
    print("\n[2] Floyd's Cycle-Finding Attack on Toy Hash ...")
    for n in [8, 12, 16]:
        h_fn = _make_toy_hash_fn(n)
        result = floyd_cycle_attack(h_fn, n)
        assert result["collision_found"], f"Floyd failed for n={n}!"
        # Verify the collision
        x1 = bytes.fromhex(result["x_hex"])
        x2 = bytes.fromhex(result["x_prime_hex"])
        assert h_fn(x1) == h_fn(x2), "Hash mismatch!"
        assert x1 != x2, "Inputs are identical!"
        print(f"    n={n:2d}  evals={result['evaluations']:5d}  "
              f"expected~{result['expected_2_n_half']:5d}  "
              f"ratio={result['ratio']:.2f}")
    print("    [OK] Floyd's attack finds valid collisions")

    # ---- Test 3: Attack truncated DLP hash (PA #8) ----
    print("\n[3] Attack Truncated DLP Hash (PA #8, n=16 bits) ...")
    t0 = time.perf_counter()
    dlp_result = attack_truncated_dlp_hash(n=16, q_bits=16)
    dt = (time.perf_counter() - t0) * 1000
    assert dlp_result["collision_found"], "No collision on DLP hash!"
    print(f"    Input A: {dlp_result['x_hex']}")
    print(f"    Input B: {dlp_result['x_prime_hex']}")
    print(f"    Shared hash: {dlp_result['hash_hex']}")
    print(f"    Evaluations: {dlp_result['evaluations']}  "
          f"(expected ~ {dlp_result['expected_2_n_half']})")
    print(f"    Ratio: {dlp_result['ratio']}")
    print(f"    [OK] DLP hash collision in {dt:.0f} ms")

    # ---- Test 4: Empirical birthday curve (n = 8, 10, 12) ----
    # Use fewer trials and smaller n for speed in tests
    print("\n[4] Empirical Birthday Curve (n=8,10,12, 50 trials each) ...")
    t0 = time.perf_counter()
    curve = empirical_birthday_curve(n_values=[8, 10, 12], trials=50)
    dt = (time.perf_counter() - t0) * 1000

    for r in curve["results"]:
        n = r["n_bits"]
        print(f"    n={n:2d}  mean_evals={r['mean_evaluations']:6.1f}  "
              f"expected~{r['expected_sqrt_2n']:6.1f}  "
              f"ratio={r['ratio_mean_over_expected']:.3f}")
        # The ratio should be roughly 1.0-2.0 (within statistical noise)
        assert 0.3 < r["ratio_mean_over_expected"] < 4.0, (
            f"Ratio {r['ratio_mean_over_expected']} too far from 1.0 for n={n}"
        )
    print(f"    [OK] Empirical means match theoretical 2^(n/2) ({dt:.0f} ms)")

    # ---- Test 5: MD5/SHA-1 context ----
    print("\n[5] MD5 / SHA-1 / SHA-256 Context ...")
    ctx = md5_sha1_context()
    for a in ctx["analyses"]:
        print(f"    {a['hash']:8s}  output={a['output_bits']:3d}-bit  "
              f"birthday=~{a['birthday_bound_2_n_half']:6s}  "
              f"time~{a['at_1e9_hashes_per_sec']['years']:>10s} years  "
              f"status={a['status']}")
    print(f"    Takeaway: {ctx['takeaway']}")
    print("    [OK] Context analysis complete")

    # ---- Test 6: Theoretical curve data ----
    print("\n[6] Theoretical Curve Data Spot-Check ...")
    curve_full = empirical_birthday_curve(n_values=[8], trials=10)
    theory_8 = curve_full["theoretical_curves"][8]
    # At k ~ sqrt(2^8) = 16, probability should be near 0.5
    near_sqrt = [p for p in theory_8 if abs(p["k"] - 16) <= 2]
    if near_sqrt:
        prob = near_sqrt[0]["probability"]
        print(f"    n=8, k~16: P(collision) = {prob:.3f}  (expected ~0.5)")
        assert 0.2 < prob < 0.9, f"Probability {prob} too far from expected range"
    print("    [OK] Theoretical curve matches expectations")

    # ---- Summary ----
    print("\n" + "=" * 70)
    print("  ALL PA #9 TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    _run_tests()
