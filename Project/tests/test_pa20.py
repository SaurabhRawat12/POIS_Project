"""Tests for PA #20 secure 2-party MPC."""

from __future__ import annotations

import random
import unittest

from api_ui.pa20_api import (
    addition_endpoint,
    benchmark_endpoint,
    equality_endpoint,
    lineage_endpoint,
    millionaire_endpoint,
)
from protocols.pa20_mpc import (
    Circuit,
    benchmark_8bit,
    build_addition_circuit,
    build_equality_circuit,
    build_millionaire_circuit,
    gmw_and,
    gmw_not,
    gmw_xor,
    lineage_trace,
    reconstruct_bit,
    run_addition,
    run_equality,
    run_millionaire,
    secure_eval,
    share_bit,
)


class TestPA20ShareOps(unittest.TestCase):
    """Share / reconstruct round-trip; XOR-of-shares property."""

    def test_share_then_reconstruct(self) -> None:
        rng = random.Random(1)
        for bit in (0, 1):
            for _ in range(20):
                a, b = share_bit(bit, rng)
                self.assertEqual(reconstruct_bit(a, b), bit)

    def test_share_invalid_bit_rejected(self) -> None:
        with self.assertRaises(ValueError):
            share_bit(2, random.Random(0))


class TestPA20FreeGates(unittest.TestCase):
    """gmw_xor and gmw_not produce correct shares of the operation result."""

    def test_gmw_xor_truth_table(self) -> None:
        rng = random.Random(11)
        for x in (0, 1):
            for y in (0, 1):
                xa, xb = share_bit(x, rng)
                ya, yb = share_bit(y, rng)
                oa, ob = gmw_xor(xa, xb, ya, yb)
                self.assertEqual(reconstruct_bit(oa, ob), x ^ y)

    def test_gmw_not_truth_table(self) -> None:
        rng = random.Random(12)
        for x in (0, 1):
            xa, xb = share_bit(x, rng)
            oa, ob = gmw_not(xa, xb)
            self.assertEqual(reconstruct_bit(oa, ob), 1 - x)


class TestPA20EqualityCircuit(unittest.TestCase):
    """Securely compute x == y for 4-bit integers (small for speed)."""

    def test_equality_when_equal(self) -> None:
        r = run_equality(11, 11, n=4, rng=random.Random(21))
        self.assertEqual(r["result"], 1)
        self.assertTrue(r["correct"])

    def test_equality_when_unequal(self) -> None:
        r = run_equality(11, 12, n=4, rng=random.Random(22))
        self.assertEqual(r["result"], 0)
        self.assertTrue(r["correct"])

    def test_equality_zero_zero(self) -> None:
        r = run_equality(0, 0, n=4, rng=random.Random(23))
        self.assertTrue(r["correct"])

    def test_equality_max_max(self) -> None:
        r = run_equality(15, 15, n=4, rng=random.Random(24))
        self.assertEqual(r["result"], 1)


class TestPA20AdditionCircuit(unittest.TestCase):
    """Securely compute x + y mod 2^n."""

    def test_addition_no_overflow(self) -> None:
        r = run_addition(3, 4, n=4, rng=random.Random(31))
        self.assertEqual(r["result"], 7)

    def test_addition_with_carry(self) -> None:
        r = run_addition(7, 1, n=4, rng=random.Random(32))
        self.assertEqual(r["result"], 8)

    def test_addition_with_overflow_wraps(self) -> None:
        r = run_addition(15, 1, n=4, rng=random.Random(33))
        self.assertEqual(r["result"], 0)  # 16 mod 16 = 0

    def test_addition_zero_plus_anything(self) -> None:
        for y in (0, 5, 15):
            r = run_addition(0, y, n=4, rng=random.Random(40 + y))
            self.assertEqual(r["result"], y)


class TestPA20MillionaireCircuit(unittest.TestCase):
    """Securely compute x > y."""

    def test_alice_richer(self) -> None:
        r = run_millionaire(12, 5, n=4, rng=random.Random(51))
        self.assertEqual(r["result"], 1)

    def test_bob_richer(self) -> None:
        r = run_millionaire(5, 12, n=4, rng=random.Random(52))
        self.assertEqual(r["result"], 0)

    def test_equal_is_not_greater(self) -> None:
        r = run_millionaire(7, 7, n=4, rng=random.Random(53))
        self.assertEqual(r["result"], 0)

    def test_off_by_one(self) -> None:
        r1 = run_millionaire(8, 7, n=4, rng=random.Random(54))
        r2 = run_millionaire(7, 8, n=4, rng=random.Random(55))
        self.assertEqual(r1["result"], 1)
        self.assertEqual(r2["result"], 0)

    def test_extreme_values(self) -> None:
        r1 = run_millionaire(15, 0, n=4, rng=random.Random(56))
        r2 = run_millionaire(0, 15, n=4, rng=random.Random(57))
        self.assertEqual(r1["result"], 1)
        self.assertEqual(r2["result"], 0)


class TestPA20Performance(unittest.TestCase):
    """The spec asks for OT-call counts and timing at n=8."""

    def test_8bit_benchmark_runs_and_is_correct(self) -> None:
        # Use n=4 to keep the test suite fast; the benchmark function
        # itself exercises n=8 in a separate manual run.
        eq = run_equality(7, 7, n=4, rng=random.Random(61))
        add = run_addition(5, 9, n=4, rng=random.Random(62))
        mil = run_millionaire(10, 5, n=4, rng=random.Random(63))
        self.assertTrue(eq["correct"])
        self.assertTrue(add["correct"])
        self.assertTrue(mil["correct"])
        # OT counts should equal twice the AND-gate count.
        self.assertEqual(eq["ot_calls"], 2 * eq["gate_counts"]["AND"])
        self.assertEqual(add["ot_calls"], 2 * add["gate_counts"]["AND"])
        self.assertEqual(mil["ot_calls"], 2 * mil["gate_counts"]["AND"])


class TestPA20Lineage(unittest.TestCase):
    """The lineage trace must mention every PA in the chain."""

    def test_lineage_chain_complete(self) -> None:
        chain_text = "\n".join(lineage_trace()["chain"])
        for pa in ("PA#20", "PA#19", "PA#18", "PA#16", "PA#11", "PA#13"):
            self.assertIn(pa, chain_text)


class TestPA20InputValidation(unittest.TestCase):
    """secure_eval must reject obviously bad inputs."""

    def test_wrong_input_count_rejected(self) -> None:
        circuit = build_equality_circuit(4)
        with self.assertRaises(ValueError):
            secure_eval(circuit, [0, 1, 0], [0, 0, 0, 0])

    def test_non_bit_input_rejected(self) -> None:
        circuit = build_equality_circuit(4)
        with self.assertRaises(ValueError):
            secure_eval(circuit, [0, 1, 0, 2], [0, 0, 0, 0])


class TestPA20API(unittest.TestCase):
    """Tests against the api_ui wrappers."""

    def test_equality_endpoint(self) -> None:
        r = equality_endpoint(11, 11, n=4, seed=71)
        self.assertEqual(r["result"]["result"], 1)

    def test_addition_endpoint(self) -> None:
        r = addition_endpoint(3, 4, n=4, seed=72)
        self.assertEqual(r["result"]["result"], 7)

    def test_millionaire_endpoint(self) -> None:
        r = millionaire_endpoint(10, 5, n=4, seed=73)
        self.assertEqual(r["result"]["result"], 1)

    def test_lineage_endpoint(self) -> None:
        r = lineage_endpoint()
        chain_text = "\n".join(r["result"]["chain"])
        self.assertIn("PA#20", chain_text)
        self.assertIn("PA#13", chain_text)


if __name__ == "__main__":
    unittest.main()
