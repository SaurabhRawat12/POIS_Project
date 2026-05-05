from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from api_ui.pa13_api import primality_check_endpoint
from core_math.number_theory import decompose, egcd, mod_inverse, modexp
from primitives.pa13_primality import (
    gen_prime,
    gen_safe_prime,
    is_prime,
    miller_rabin,
)
from scripts.pa13_benchmark import run_benchmark


class TestPA13MathUtilities(unittest.TestCase):
    def test_modexp_matches_pow(self) -> None:
        vectors = [
            (2, 10, 17),
            (7, 128, 13),
            (12345, 678, 99991),
            (987654321, 123456, 2147483647),
        ]
        for base, exp, mod in vectors:
            self.assertEqual(modexp(base, exp, mod), pow(base, exp, mod))

    def test_egcd_and_inverse(self) -> None:
        g, x, y = egcd(240, 46)
        self.assertEqual(g, 2)
        self.assertEqual(240 * x + 46 * y, g)

        inv = mod_inverse(17, 3120)
        self.assertEqual((17 * inv) % 3120, 1)

    def test_decompose(self) -> None:
        s, d = decompose(560)
        self.assertEqual(2**s * d, 560)
        self.assertEqual(d % 2, 1)


class TestPA13Primality(unittest.TestCase):
    def test_miller_rabin_primes_and_composites(self) -> None:
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 101, 127, 257]
        composites = [0, 1, 4, 6, 8, 9, 10, 12, 15, 21, 341, 561, 1105, 1729]

        for p in primes:
            self.assertTrue(is_prime(p, k=10))
        for n in composites:
            self.assertFalse(is_prime(n, k=10))

    def test_miller_rabin_trace_schema(self) -> None:
        result = miller_rabin(561, k=5, trace=True, rng=random.Random(42))
        self.assertEqual(result["result"], "COMPOSITE")
        self.assertGreaterEqual(result["rounds_executed"], 1)
        self.assertIsInstance(result["trace"], list)
        self.assertGreaterEqual(len(result["trace"]), 1)

    def test_edge_cases(self) -> None:
        for n in [-10, -1, 0, 1]:
            self.assertFalse(is_prime(n, k=5))
        self.assertTrue(is_prime(2, k=5))
        self.assertTrue(is_prime(3, k=5))
        self.assertFalse(is_prime(4, k=5))

    def test_composite_product_detection(self) -> None:
        rng = random.Random(1234)
        small_primes = [101, 103, 107, 109, 113]
        for _ in range(10):
            p = rng.choice(small_primes)
            q = rng.choice(small_primes)
            n = p * q
            self.assertFalse(is_prime(n, k=20))


class TestPA13PrimeGeneration(unittest.TestCase):
    def test_gen_prime_bit_length_and_sanity(self) -> None:
        result = gen_prime(bits=32, k=10, sanity_rounds=20, rng=random.Random(1))
        p = result["prime"]
        self.assertEqual(p.bit_length(), 32)
        self.assertTrue(result["sanity_passed"])
        self.assertTrue(is_prime(p, k=100))

    def test_deterministic_seed_mode(self) -> None:
        first = gen_prime(bits=24, k=8, rng=random.Random(999))
        second = gen_prime(bits=24, k=8, rng=random.Random(999))
        self.assertEqual(first["prime"], second["prime"])
        self.assertEqual(first["attempts"], second["attempts"])

    def test_gen_safe_prime(self) -> None:
        result = gen_safe_prime(q_bits=16, k=12, sanity_rounds=20, rng=random.Random(7))
        p = result["p"]
        q = result["q"]
        self.assertEqual(p, 2 * q + 1)
        self.assertTrue(is_prime(p, k=50))
        self.assertTrue(is_prime(q, k=50))


class TestPA13Smoke(unittest.TestCase):
    def test_api_payload(self) -> None:
        payload = primality_check_endpoint(n=561, k=5, trace=True)
        self.assertEqual(payload["status"], "COMPOSITE")
        self.assertIn("elapsed_ms", payload)
        self.assertIn("trace", payload)

    def test_benchmark_report_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_benchmark(
                bit_sizes=[16],
                trials=1,
                k=8,
                output_dir=Path(tmpdir),
            )
            self.assertEqual(result["status"], "ok")
            self.assertTrue(Path(result["json_path"]).exists())
            self.assertTrue(Path(result["csv_path"]).exists())


if __name__ == "__main__":
    unittest.main()
