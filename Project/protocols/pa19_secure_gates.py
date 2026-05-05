"""PA #19: Secure AND, XOR, and NOT gates.

The complete set of gate primitives needed to build any boolean circuit
securely with two parties.  AND uses one OT call (PA #18); XOR and NOT
are "free" -- no public-key crypto, no communication beyond the bits
themselves.

Functional contract per the spec:
    secure_and(a, b) : Alice has a, Bob has b. Both learn a AND b.
    secure_xor(a, b) : Both learn a XOR b.
    secure_not(a)    : Local flip of a single bit.

Privacy (informal, as required by the spec):
    - Secure AND : Alice plays OT sender with (m_0, m_1) = (0, a).
                   Bob plays OT receiver with choice b. Bob learns
                       m_b = a if b == 1
                       m_b = 0 if b == 0
                   which equals a*b = a AND b.
                   * Bob learns nothing about a beyond a AND b
                     (follows from OT receiver-privacy: when b=0 the
                      output is 0 regardless of a, so a is hidden).
                   * Alice learns nothing about b
                     (follows from OT sender-privacy: she sees no
                      message from the receiver beyond (pk_0, pk_1)
                      whose distribution is independent of b).
    - Secure XOR : Single-bit reveal; in standalone form, Bob trivially
                   learns a from output XOR b. The "free XOR" property
                   is fully meaningful only inside the GMW shared-wire
                   circuit model (used in PA #20).
    - Secure NOT : Pure local computation, no transcript at all.

Lineage (no external crypto libraries):
    PA #19 -> PA #18 (OT)  -> PA #16 (ElGamal)
                            -> PA #11 (DH group)
                            -> PA #13 (Miller-Rabin), all transitively.
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Tuple

from core_math.randomness import system_rng
from primitives.pa18_oblivious_transfer import ot_run

PA_ID = "PA#19"


# ---------------------------------------------------------------------------
# Bit <-> ElGamal-plaintext encoding
# ---------------------------------------------------------------------------
# PA #16 ElGamal requires 0 < m < p, so we cannot pass bit 0 directly.
# We encode  bit 0 -> group element 1 ,  bit 1 -> group element 2.

_BIT_ENCODE = {0: 1, 1: 2}
_BIT_DECODE = {1: 0, 2: 1}


def _encode(bit: int) -> int:
    if bit not in _BIT_ENCODE:
        raise ValueError("bit must be 0 or 1")
    return _BIT_ENCODE[bit]


def _decode(elem: int) -> int:
    if elem not in _BIT_DECODE:
        raise ValueError(f"received unexpected group element {elem}")
    return _BIT_DECODE[elem]


# ---------------------------------------------------------------------------
# Secure AND: one OT call
# ---------------------------------------------------------------------------

def secure_and(
    a: int,
    b: int,
    *,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Securely compute a AND b using a single OT call.

    Alice (input a) plays OT sender with (m_0, m_1) = (0, a).
    Bob (input b)   plays OT receiver with choice b.
    Bob gets m_b = a*b. He announces it; both parties output a AND b.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("a and b must be bits (0 or 1)")

    active_rng = rng or system_rng()

    # Encode (m_0, m_1) = (0, a) as ElGamal-safe group elements.
    m_0 = _encode(0)  # always group element 1
    m_1 = _encode(a)  # 1 if a==0, 2 if a==1

    ot = ot_run(b=b, m_0=m_0, m_1=m_1, q_bits=q_bits, k=k, rng=active_rng)
    output = _decode(ot["received"])
    expected = a & b

    return {
        "pa_id": PA_ID,
        "algorithm": "SecureAND",
        "alice_input": a,
        "bob_input": b,
        "output": output,
        "expected": expected,
        "correct": output == expected,
        "ot_calls": 1,
        "security_note": (
            "OT sender-privacy hides b from Alice; OT receiver-privacy "
            "hides a from Bob beyond what a AND b reveals."
        ),
    }


# ---------------------------------------------------------------------------
# Secure XOR: free (no OT)
# ---------------------------------------------------------------------------

def secure_xor(a: int, b: int) -> Dict[str, Any]:
    """Securely compute a XOR b. No OT call -- this is the 'free' gate.

    The standalone form trivially reveals one party's input given the other's,
    but the gate becomes fully meaningful inside the shared-wire circuit
    model in PA #20.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("a and b must be bits (0 or 1)")

    return {
        "pa_id": PA_ID,
        "algorithm": "SecureXOR",
        "alice_input": a,
        "bob_input": b,
        "output": a ^ b,
        "ot_calls": 0,
        "security_note": (
            "Free in the GMW shared-wire model: each party locally XORs "
            "their share of each input wire; no communication required."
        ),
    }


# ---------------------------------------------------------------------------
# Secure NOT: free, local
# ---------------------------------------------------------------------------

def secure_not(a: int) -> Dict[str, Any]:
    """Local bit flip. No OT, no communication. The cheapest gate of all."""
    if a not in (0, 1):
        raise ValueError("a must be a bit (0 or 1)")

    return {
        "pa_id": PA_ID,
        "algorithm": "SecureNOT",
        "input": a,
        "output": 1 - a,
        "ot_calls": 0,
        "security_note": "Pure local computation; no transcript exists.",
    }


# ---------------------------------------------------------------------------
# Truth-table demo (required: 50 runs of all four (a,b) combinations)
# ---------------------------------------------------------------------------

def truth_table_demo(
    *,
    runs_per_combo: int = 50,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Verify every (a, b) input pair produces the correct AND and XOR output.

    Each of the four combinations (0,0), (0,1), (1,0), (1,1) is run
    `runs_per_combo` times. Each run uses fresh OT randomness, so the
    test exercises both correctness and the protocol's tolerance of
    fresh random inputs.
    """
    active_rng = rng or system_rng()

    and_results: Dict[Tuple[int, int], int] = {}
    xor_results: Dict[Tuple[int, int], int] = {}
    and_correct = 0
    xor_correct = 0
    total = 0

    for a in (0, 1):
        for b in (0, 1):
            for _ in range(runs_per_combo):
                ar = secure_and(a, b, q_bits=q_bits, k=k, rng=active_rng)
                xr = secure_xor(a, b)
                if ar["correct"]:
                    and_correct += 1
                if xr["output"] == (a ^ b):
                    xor_correct += 1
                total += 1
            and_results[(a, b)] = ar["output"]
            xor_results[(a, b)] = xr["output"]

    return {
        "pa_id": PA_ID,
        "algorithm": "TruthTableDemo",
        "runs_per_combo": runs_per_combo,
        "total_runs": total,
        "and_truth_table": {f"{a},{b}": v for (a, b), v in and_results.items()},
        "xor_truth_table": {f"{a},{b}": v for (a, b), v in xor_results.items()},
        "and_correct_count": and_correct,
        "xor_correct_count": xor_correct,
        "and_perfect": and_correct == total,
        "xor_perfect": xor_correct == total,
    }


# ---------------------------------------------------------------------------
# Privacy demo: when b=0, AND output is 0 regardless of a
# ---------------------------------------------------------------------------

def privacy_demo(
    *,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Empirically demonstrate the 'when b=0' privacy property of secure AND.

    Run secure_and with Bob's bit fixed at b=0, varying Alice's bit. The
    output is always 0, so Bob's view is identical for both values of a.
    This concretely witnesses that Bob learns nothing about a in that case.

    Symmetric demo for a=0 (Alice's view independent of b).
    """
    active_rng = rng or system_rng()

    out_b0_a0 = secure_and(0, 0, q_bits=q_bits, k=k, rng=active_rng)["output"]
    out_b0_a1 = secure_and(1, 0, q_bits=q_bits, k=k, rng=active_rng)["output"]
    out_a0_b0 = secure_and(0, 0, q_bits=q_bits, k=k, rng=active_rng)["output"]
    out_a0_b1 = secure_and(0, 1, q_bits=q_bits, k=k, rng=active_rng)["output"]

    return {
        "pa_id": PA_ID,
        "algorithm": "ANDPrivacyDemo",
        "bob_view_independent_of_alice": out_b0_a0 == out_b0_a1 == 0,
        "alice_view_independent_of_bob": out_a0_b0 == out_a0_b1 == 0,
        "security_note": (
            "When b=0, output is 0 regardless of a, so Bob learns nothing "
            "about a. When a=0, output is 0 regardless of b, so Alice "
            "learns nothing about b. Both follow from a*0 = 0."
        ),
    }
