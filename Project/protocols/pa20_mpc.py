"""PA #20: All 2-Party Secure Multi-Party Computation (GMW protocol).

Given Secure AND (PA #19) and Secure XOR (free), any boolean function can be
evaluated securely between two distrusting parties. This file implements
the GMW protocol with secret-shared wires, a generic boolean-circuit
evaluator, and the three required test circuits:

    1. Millionaire's Problem  (Alice's x > Bob's y, neither reveals their value)
    2. Secure Equality        (x == y as n-bit integers)
    3. Secure Bit-Addition    (x + y mod 2^n)

GMW design (per-wire secret sharing):
    Every wire value v is held as a pair (v_A, v_B) with v_A XOR v_B = v.
    Each party sees only their own share, which is uniformly random.

    XOR  : free.  out_A = x_A XOR y_A,   out_B = x_B XOR y_B.
    NOT  : free.  Alice flips her share, Bob keeps his.
    AND  : uses two OT calls (PA #18).
                The expansion
                    x AND y = (x_A XOR x_B)(y_A XOR y_B)
                            = x_A*y_A XOR x_A*y_B XOR x_B*y_A XOR x_B*y_B
                gives two local terms (computable by Alice and Bob alone)
                and two cross terms (x_A*y_B and x_B*y_A) that are computed
                jointly via OT.

Lineage (no external crypto libraries):
    PA #20  ->  PA #19 (gate-level secure_and/secure_xor/secure_not, imported)
            ->  PA #18 (OT for GMW AND cross-terms, used directly)
            ->  PA #16 (ElGamal, used inside PA #18)
            ->  PA #11 (DH safe-prime group, used inside PA #16)
            ->  PA #13 (Miller-Rabin, used by PA #11 / PA #12 transitively)
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core_math.randomness import system_rng
from primitives.pa18_oblivious_transfer import (
    ot_receiver_step1,
    ot_receiver_step2,
    ot_sender_step,
    ot_setup,
)

# Imported to satisfy the spec's lineage requirement that PA#20 use PA#19.
# These are also re-exported for use as simple-bit gates outside GMW.
from protocols.pa19_secure_gates import secure_and, secure_not, secure_xor  # noqa: F401

PA_ID = "PA#20"


# ---------------------------------------------------------------------------
# Bit / OT bridging helpers
# ---------------------------------------------------------------------------
# PA #16 ElGamal requires 0 < m < p, so we use the same encoding as PA #19:
# bit 0 -> group element 1,  bit 1 -> group element 2.

_BIT_TO_ELEM = {0: 1, 1: 2}


def _ot_one_bit(
    params: Dict[str, Any],
    receiver_choice: int,
    sender_m0: int,
    sender_m1: int,
    *,
    rng: random.Random,
) -> int:
    """Run one bit-OT using shared `params` (no fresh group setup).

    Returns the bit the receiver gets: m_{receiver_choice}.
    """
    enc_m0 = _BIT_TO_ELEM[sender_m0]
    enc_m1 = _BIT_TO_ELEM[sender_m1]

    r1 = ot_receiver_step1(receiver_choice, params, rng=rng)
    s = ot_sender_step(params, r1["pk_0"], r1["pk_1"], enc_m0, enc_m1, rng=rng)
    r2 = ot_receiver_step2(r1["state"], params, s["C_0"], s["C_1"])

    received_elem = r2["m_b"]
    return 1 if received_elem == _BIT_TO_ELEM[1] else 0


# ---------------------------------------------------------------------------
# GMW share operations
# ---------------------------------------------------------------------------

def share_bit(bit: int, rng: random.Random) -> Tuple[int, int]:
    """Split a bit into two uniform XOR-shares.

    The owner of `bit` runs this and keeps the first share, sending the
    second share to the other party. The owner picks the random share
    so the other party's share is uniformly random in their view.
    """
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    own = rng.randint(0, 1)
    peer = bit ^ own
    return own, peer


def reconstruct_bit(alice_share: int, bob_share: int) -> int:
    """Combine the two shares to recover the underlying bit."""
    return (alice_share ^ bob_share) & 1


def gmw_xor(
    x_alice: int, x_bob: int, y_alice: int, y_bob: int
) -> Tuple[int, int]:
    """Free XOR on shares.  Returns (alice_out_share, bob_out_share)."""
    return x_alice ^ y_alice, x_bob ^ y_bob


def gmw_not(x_alice: int, x_bob: int) -> Tuple[int, int]:
    """Free NOT on shares: Alice flips her share, Bob unchanged."""
    return x_alice ^ 1, x_bob


def gmw_and(
    x_alice: int,
    x_bob: int,
    y_alice: int,
    y_bob: int,
    params: Dict[str, Any],
    *,
    rng: random.Random,
) -> Tuple[int, int]:
    """GMW AND on shares using two OT calls.

    Computes (alice_out_share, bob_out_share) such that
        alice_out_share XOR bob_out_share == (x AND y)
    where  x = x_alice XOR x_bob ,  y = y_alice XOR y_bob.

    Math:
        x AND y  =  x_A*y_A  XOR  x_A*y_B  XOR  x_B*y_A  XOR  x_B*y_B
                   |________| |____________________________| |________|
                   Alice local    cross-terms (need OT)        Bob local

    OT 1 (Alice sender, Bob receiver): outputs shares of x_A * y_B.
    OT 2 (Bob sender, Alice receiver): outputs shares of x_B * y_A.
    """
    # ----- OT 1 : shares of x_A * y_B -----
    # Alice picks random r1, sets messages (m0, m1) = (r1, r1 XOR x_A).
    # Bob's choice bit is y_B.  Bob receives r1 XOR (x_A * y_B).
    r1 = rng.randint(0, 1)
    u1 = _ot_one_bit(
        params,
        receiver_choice=y_bob,
        sender_m0=r1,
        sender_m1=r1 ^ x_alice,
        rng=rng,
    )
    # Now: r1 XOR u1 == x_alice * y_bob.

    # ----- OT 2 : shares of x_B * y_A -----
    # Symmetric: Bob picks r2, messages (r2, r2 XOR x_B), Alice's choice is y_A.
    r2 = rng.randint(0, 1)
    u2 = _ot_one_bit(
        params,
        receiver_choice=y_alice,
        sender_m0=r2,
        sender_m1=r2 ^ x_bob,
        rng=rng,
    )
    # Now: r2 XOR u2 == x_bob * y_alice.

    # ----- combine local + cross terms -----
    alice_out = (x_alice & y_alice) ^ r1 ^ u2
    bob_out = (x_bob & y_bob) ^ u1 ^ r2

    return alice_out, bob_out


# ---------------------------------------------------------------------------
# Circuit class: a DAG of AND / XOR / NOT gates
# ---------------------------------------------------------------------------

@dataclass
class Gate:
    out_wire: int
    gate_type: str            # "AND", "XOR", or "NOT"
    in_wires: Tuple[int, ...] # 2 inputs for AND/XOR, 1 input for NOT


@dataclass
class Circuit:
    """Boolean circuit expressed as a DAG of gates.

    Wire IDs are simple integers. Input wires are pre-declared as
    Alice-owned or Bob-owned; gate output wires are added as gates are
    inserted in topological order.
    """
    alice_inputs: List[int] = field(default_factory=list)
    bob_inputs: List[int] = field(default_factory=list)
    gates: List[Gate] = field(default_factory=list)
    outputs: List[int] = field(default_factory=list)
    _next_wire: int = 0

    def add_alice_input(self) -> int:
        w = self._next_wire
        self._next_wire += 1
        self.alice_inputs.append(w)
        return w

    def add_bob_input(self) -> int:
        w = self._next_wire
        self._next_wire += 1
        self.bob_inputs.append(w)
        return w

    def AND(self, x: int, y: int) -> int:
        w = self._next_wire
        self._next_wire += 1
        self.gates.append(Gate(w, "AND", (x, y)))
        return w

    def XOR(self, x: int, y: int) -> int:
        w = self._next_wire
        self._next_wire += 1
        self.gates.append(Gate(w, "XOR", (x, y)))
        return w

    def NOT(self, x: int) -> int:
        w = self._next_wire
        self._next_wire += 1
        self.gates.append(Gate(w, "NOT", (x,)))
        return w

    def set_output(self, wire: int) -> None:
        self.outputs.append(wire)

    def gate_counts(self) -> Dict[str, int]:
        counts = {"AND": 0, "XOR": 0, "NOT": 0}
        for g in self.gates:
            counts[g.gate_type] += 1
        return counts


# ---------------------------------------------------------------------------
# Secure circuit evaluator (GMW)
# ---------------------------------------------------------------------------

def secure_eval(
    circuit: Circuit,
    x_alice: List[int],
    y_bob: List[int],
    *,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Securely evaluate `circuit` on Alice's bits `x_alice` and Bob's bits `y_bob`.

    Returns a dict with output bits and a transcript summary (OT calls,
    gate counts, wall-clock time).
    """
    if len(x_alice) != len(circuit.alice_inputs):
        raise ValueError(
            f"x_alice has {len(x_alice)} bits, "
            f"circuit expects {len(circuit.alice_inputs)}"
        )
    if len(y_bob) != len(circuit.bob_inputs):
        raise ValueError(
            f"y_bob has {len(y_bob)} bits, "
            f"circuit expects {len(circuit.bob_inputs)}"
        )
    if any(b not in (0, 1) for b in x_alice + y_bob):
        raise ValueError("all input bits must be 0 or 1")

    active_rng = rng or system_rng()
    start_time = time.perf_counter()

    # One OT setup shared across every AND gate (huge speedup vs. per-gate setup).
    ot_params = ot_setup(q_bits=q_bits, k=k, rng=active_rng)

    # Wire shares: each wire id maps to (alice_share, bob_share).
    wires: Dict[int, Tuple[int, int]] = {}

    # ----- Input phase: each owner secret-shares their input bits -----
    for wire_id, bit in zip(circuit.alice_inputs, x_alice):
        a, b = share_bit(bit, active_rng)
        wires[wire_id] = (a, b)

    for wire_id, bit in zip(circuit.bob_inputs, y_bob):
        b, a = share_bit(bit, active_rng)  # Bob is the owner this time
        wires[wire_id] = (a, b)

    # ----- Gate phase -----
    ot_calls = 0
    for gate in circuit.gates:
        if gate.gate_type == "XOR":
            x, y = gate.in_wires
            wires[gate.out_wire] = gmw_xor(*wires[x], *wires[y])
        elif gate.gate_type == "NOT":
            (x,) = gate.in_wires
            wires[gate.out_wire] = gmw_not(*wires[x])
        elif gate.gate_type == "AND":
            x, y = gate.in_wires
            x_A, x_B = wires[x]
            y_A, y_B = wires[y]
            wires[gate.out_wire] = gmw_and(
                x_A, x_B, y_A, y_B, ot_params, rng=active_rng
            )
            ot_calls += 2
        else:
            raise ValueError(f"unknown gate type: {gate.gate_type}")

    # ----- Output phase: parties exchange shares of output wires -----
    output_bits = [reconstruct_bit(*wires[w]) for w in circuit.outputs]

    elapsed = time.perf_counter() - start_time

    return {
        "pa_id": PA_ID,
        "algorithm": "SecureEval",
        "outputs": output_bits,
        "ot_calls": ot_calls,
        "gate_counts": circuit.gate_counts(),
        "wall_clock_seconds": elapsed,
        "security_note": (
            "GMW protocol: every wire is XOR-shared between Alice and Bob. "
            "Intermediate values never leave shared form, so the transcript "
            "is simulatable from the output alone."
        ),
    }


# ---------------------------------------------------------------------------
# Required circuit 1: Secure Equality (x == y as n-bit integers)
# ---------------------------------------------------------------------------

def build_equality_circuit(n: int) -> Circuit:
    """Build the equality-test circuit for n-bit integers.

    Output 1 iff x == y. Strategy:
        eq_i  = NOT(x_i XOR y_i)        for each bit i
        out   = AND of all eq_i
    """
    if n <= 0:
        raise ValueError("n must be positive")

    c = Circuit()
    x_bits = [c.add_alice_input() for _ in range(n)]
    y_bits = [c.add_bob_input() for _ in range(n)]

    eq_bits = [c.NOT(c.XOR(x_bits[i], y_bits[i])) for i in range(n)]

    out = eq_bits[0]
    for i in range(1, n):
        out = c.AND(out, eq_bits[i])
    c.set_output(out)

    return c


# ---------------------------------------------------------------------------
# Required circuit 2: Secure Bit-Addition (x + y mod 2^n)
# ---------------------------------------------------------------------------

def build_addition_circuit(n: int) -> Circuit:
    """Build a ripple-carry adder for n-bit integers.

    Inputs and outputs are LSB-first. The output is the sum mod 2^n
    (carry-out of the top bit is discarded).

    Full-adder logic:
        sum_i      = x_i XOR y_i XOR c_in
        carry_out  = (x_i AND y_i) XOR ((x_i XOR y_i) AND c_in)
                     [equivalent to OR; the two AND terms can never both be 1]
    """
    if n <= 0:
        raise ValueError("n must be positive")

    c = Circuit()
    x_bits = [c.add_alice_input() for _ in range(n)]
    y_bits = [c.add_bob_input() for _ in range(n)]

    # Bit 0: half adder (no carry-in).
    sum0 = c.XOR(x_bits[0], y_bits[0])
    carry = c.AND(x_bits[0], y_bits[0])
    c.set_output(sum0)

    # Bits 1..n-1: full adder with carry chain.
    for i in range(1, n):
        x_xor_y = c.XOR(x_bits[i], y_bits[i])
        sum_i = c.XOR(x_xor_y, carry)
        c.set_output(sum_i)

        if i == n - 1:
            break  # No need to compute carry-out from the top bit.
        x_and_y = c.AND(x_bits[i], y_bits[i])
        carry_and_xy = c.AND(carry, x_xor_y)
        carry = c.XOR(x_and_y, carry_and_xy)

    return c


# ---------------------------------------------------------------------------
# Required circuit 3: Millionaire's Problem (x > y)
# ---------------------------------------------------------------------------

def build_millionaire_circuit(n: int) -> Circuit:
    """Build a 'greater than' comparator for n-bit integers (LSB-first).

    Output 1 iff x > y. Strategy: scan from MSB to LSB; the highest bit
    where x and y differ determines the result. Only one such position
    exists, so the per-position 'strictly greater' indicators can be
    XOR-aggregated.

        eq_i   = NOT(x_i XOR y_i)                       (n NOT/XOR pairs)
        sg_i   = x_i AND NOT(y_i)                       (n ANDs)
        cum_eq[i] = AND of eq_j for j > i                (n-2 ANDs)
        gt = XOR over i of (sg_i AND cum_eq[i])          (n-1 ANDs)
    """
    if n <= 0:
        raise ValueError("n must be positive")

    c = Circuit()
    x_bits = [c.add_alice_input() for _ in range(n)]
    y_bits = [c.add_bob_input() for _ in range(n)]

    eq = [c.NOT(c.XOR(x_bits[i], y_bits[i])) for i in range(n)]
    sg = [c.AND(x_bits[i], c.NOT(y_bits[i])) for i in range(n)]

    # is_gt_at[i] = "strictly greater at bit i, given all higher bits equal"
    is_gt_at: List[int] = [0] * n
    is_gt_at[n - 1] = sg[n - 1]  # nothing strictly above the MSB

    # cumulative_eq carries "all bits strictly above i are equal" from MSB down.
    if n >= 2:
        cumulative_eq = eq[n - 1]
        for i in range(n - 2, -1, -1):
            is_gt_at[i] = c.AND(sg[i], cumulative_eq)
            if i > 0:
                cumulative_eq = c.AND(cumulative_eq, eq[i])

    # The is_gt_at indicators are mutually exclusive, so OR == XOR here.
    gt = is_gt_at[0]
    for i in range(1, n):
        gt = c.XOR(gt, is_gt_at[i])
    c.set_output(gt)

    return c


# ---------------------------------------------------------------------------
# Demo runners
# ---------------------------------------------------------------------------

def _int_to_bits_lsb(value: int, n: int) -> List[int]:
    if value < 0 or value >= (1 << n):
        raise ValueError(f"value {value} out of range for {n} bits")
    return [(value >> i) & 1 for i in range(n)]


def _bits_lsb_to_int(bits: List[int]) -> int:
    return sum(b << i for i, b in enumerate(bits))


def run_equality(
    x: int, y: int, n: int = 8, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    circuit = build_equality_circuit(n)
    result = secure_eval(
        circuit,
        _int_to_bits_lsb(x, n),
        _int_to_bits_lsb(y, n),
        rng=rng,
    )
    expected = 1 if x == y else 0
    return {
        **result,
        "circuit": "equality",
        "x": x,
        "y": y,
        "n_bits": n,
        "result": result["outputs"][0],
        "expected": expected,
        "correct": result["outputs"][0] == expected,
    }


def run_addition(
    x: int, y: int, n: int = 8, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    circuit = build_addition_circuit(n)
    result = secure_eval(
        circuit,
        _int_to_bits_lsb(x, n),
        _int_to_bits_lsb(y, n),
        rng=rng,
    )
    expected = (x + y) % (1 << n)
    actual = _bits_lsb_to_int(result["outputs"])
    return {
        **result,
        "circuit": "addition",
        "x": x,
        "y": y,
        "n_bits": n,
        "result": actual,
        "expected": expected,
        "correct": actual == expected,
    }


def run_millionaire(
    x: int, y: int, n: int = 8, *, rng: random.Random | None = None
) -> Dict[str, Any]:
    circuit = build_millionaire_circuit(n)
    result = secure_eval(
        circuit,
        _int_to_bits_lsb(x, n),
        _int_to_bits_lsb(y, n),
        rng=rng,
    )
    expected = 1 if x > y else 0
    return {
        **result,
        "circuit": "millionaire",
        "x": x,
        "y": y,
        "n_bits": n,
        "result": result["outputs"][0],
        "expected": expected,
        "correct": result["outputs"][0] == expected,
    }


# ---------------------------------------------------------------------------
# Required: 8-bit benchmark report
# ---------------------------------------------------------------------------

def benchmark_8bit(
    *, rng: random.Random | None = None
) -> Dict[str, Any]:
    """Report OT-call count and wall-clock time for each circuit at n=8."""
    active_rng = rng or system_rng()

    eq_demo = run_equality(105, 105, n=8, rng=active_rng)
    add_demo = run_addition(57, 86, n=8, rng=active_rng)
    mil_demo = run_millionaire(60, 200, n=8, rng=active_rng)

    return {
        "pa_id": PA_ID,
        "algorithm": "Benchmark8Bit",
        "equality": {
            "ot_calls": eq_demo["ot_calls"],
            "wall_clock_seconds": eq_demo["wall_clock_seconds"],
            "gate_counts": eq_demo["gate_counts"],
            "correct": eq_demo["correct"],
        },
        "addition": {
            "ot_calls": add_demo["ot_calls"],
            "wall_clock_seconds": add_demo["wall_clock_seconds"],
            "gate_counts": add_demo["gate_counts"],
            "correct": add_demo["correct"],
        },
        "millionaire": {
            "ot_calls": mil_demo["ot_calls"],
            "wall_clock_seconds": mil_demo["wall_clock_seconds"],
            "gate_counts": mil_demo["gate_counts"],
            "correct": mil_demo["correct"],
        },
    }


# ---------------------------------------------------------------------------
# Lineage trace (the spec asks for an explicit call-stack walk)
# ---------------------------------------------------------------------------

def lineage_trace() -> Dict[str, Any]:
    """Document the full PA chain that fires when an AND gate executes."""
    return {
        "pa_id": PA_ID,
        "algorithm": "MPCLineage",
        "chain": [
            "PA#20.secure_eval",
            "  -> PA#20.gmw_and (per AND gate)",
            "       -> PA#18.ot_setup / ot_receiver_step1 / ot_sender_step / ot_receiver_step2",
            "            -> PA#16.elgamal_enc / elgamal_dec",
            "                 -> PA#11.dh_generate_group",
            "                      -> PA#13.gen_safe_prime (Miller-Rabin)",
            "  -> PA#20.gmw_xor / gmw_not (free, local only)",
            "  -- PA#19.secure_and / secure_xor / secure_not are imported",
            "     and re-exported as the simple-bit interface.",
        ],
        "policy": "All primitives are local implementations; no external libraries.",
    }
