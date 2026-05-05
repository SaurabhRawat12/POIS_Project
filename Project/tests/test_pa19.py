"""Tests for PA #19 secure AND, XOR, NOT gates."""

from __future__ import annotations

import random
import unittest

from api_ui.pa19_api import (
    privacy_endpoint,
    secure_and_endpoint,
    secure_not_endpoint,
    secure_xor_endpoint,
    truth_table_endpoint,
)
from protocols.pa19_secure_gates import (
    privacy_demo,
    secure_and,
    secure_not,
    secure_xor,
    truth_table_demo,
)


class TestPA19SecureAND(unittest.TestCase):
    """The OT-based AND gate must produce the correct output for every input."""

    def test_and_truth_table_individual(self) -> None:
        cases = [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)]
        for i, (a, b, expected) in enumerate(cases):
            r = secure_and(a, b, q_bits=63, k=20, rng=random.Random(100 + i))
            self.assertTrue(r["correct"], f"AND({a},{b}) failed: {r['output']}")
            self.assertEqual(r["output"], expected)

    def test_and_invalid_bits_rejected(self) -> None:
        with self.assertRaises(ValueError):
            secure_and(2, 0)
        with self.assertRaises(ValueError):
            secure_and(0, -1)

    def test_and_uses_one_ot_call(self) -> None:
        r = secure_and(1, 1, q_bits=63, k=20, rng=random.Random(7))
        self.assertEqual(r["ot_calls"], 1)


class TestPA19SecureXOR(unittest.TestCase):
    """XOR must be free (zero OT calls) and produce correct output."""

    def test_xor_truth_table(self) -> None:
        cases = [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 0)]
        for a, b, expected in cases:
            r = secure_xor(a, b)
            self.assertEqual(r["output"], expected)
            self.assertEqual(r["ot_calls"], 0)

    def test_xor_invalid_bits_rejected(self) -> None:
        with self.assertRaises(ValueError):
            secure_xor(0, 7)


class TestPA19SecureNOT(unittest.TestCase):
    """NOT must be a pure local flip with zero OT calls."""

    def test_not_flip(self) -> None:
        self.assertEqual(secure_not(0)["output"], 1)
        self.assertEqual(secure_not(1)["output"], 0)

    def test_not_zero_ot_calls(self) -> None:
        self.assertEqual(secure_not(0)["ot_calls"], 0)
        self.assertEqual(secure_not(1)["ot_calls"], 0)

    def test_not_invalid_bit_rejected(self) -> None:
        with self.assertRaises(ValueError):
            secure_not(2)


class TestPA19TruthTable(unittest.TestCase):
    """Spec requirement: 50 (or fewer for fast tests) runs per (a,b) combo."""

    def test_truth_table_correctness(self) -> None:
        # Use 5 runs/combo for test speed (200 OT calls would be slow);
        # the production demo uses 50 by default.
        demo = truth_table_demo(
            runs_per_combo=5, q_bits=63, k=20, rng=random.Random(999)
        )
        self.assertEqual(demo["total_runs"], 20)
        self.assertEqual(demo["and_correct_count"], 20)
        self.assertEqual(demo["xor_correct_count"], 20)
        self.assertTrue(demo["and_perfect"])
        self.assertTrue(demo["xor_perfect"])


class TestPA19Privacy(unittest.TestCase):
    """Empirical privacy: when one input is 0, the AND output reveals nothing."""

    def test_privacy_demo(self) -> None:
        demo = privacy_demo(q_bits=63, k=20, rng=random.Random(33))
        self.assertTrue(demo["bob_view_independent_of_alice"])
        self.assertTrue(demo["alice_view_independent_of_bob"])


class TestPA19API(unittest.TestCase):
    """Tests against the api_ui wrappers."""

    def test_and_endpoint(self) -> None:
        r = secure_and_endpoint(1, 1, q_bits=63, k=20, seed=11)
        self.assertEqual(r["result"]["output"], 1)
        self.assertTrue(r["result"]["correct"])

    def test_xor_endpoint(self) -> None:
        self.assertEqual(secure_xor_endpoint(1, 0)["result"]["output"], 1)

    def test_not_endpoint(self) -> None:
        self.assertEqual(secure_not_endpoint(1)["result"]["output"], 0)

    def test_truth_table_endpoint(self) -> None:
        r = truth_table_endpoint(runs_per_combo=2, q_bits=63, k=20, seed=12)
        self.assertTrue(r["result"]["and_perfect"])
        self.assertTrue(r["result"]["xor_perfect"])

    def test_privacy_endpoint(self) -> None:
        r = privacy_endpoint(q_bits=63, k=20, seed=13)
        self.assertTrue(r["result"]["bob_view_independent_of_alice"])
        self.assertTrue(r["result"]["alice_view_independent_of_bob"])


if __name__ == "__main__":
    unittest.main()
