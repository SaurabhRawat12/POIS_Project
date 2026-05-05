"""Tests for PA #15 digital signatures."""

from __future__ import annotations

import random
import unittest

from api_ui.pa15_api import (
    euf_cma_endpoint,
    multiplicative_forgery_endpoint,
    sign_endpoint,
    verify_endpoint,
)
from primitives.pa12_rsa import rsa_keygen
from primitives.pa15_signatures import (
    euf_cma_game,
    multiplicative_forgery_demo,
    sign,
    sign_raw,
    verify,
    verify_raw,
)
from primitives.pa8_dlp_hash import DLPGroup


class TestPA15Core(unittest.TestCase):
    """Direct tests against the implementation in primitives/pa15_signatures.py."""

    def setUp(self) -> None:
        self.rng = random.Random(15)
        self.keys = rsa_keygen(bits=512, rng=self.rng)
        self.group = DLPGroup.generate(q_bits=31)

    def test_sign_then_verify_roundtrip(self) -> None:
        message = b"this is the message I want to sign"
        s = sign(self.keys["private_key"], message, self.group)
        v = verify(self.keys["public_key"], message, s["signature"], self.group)
        self.assertTrue(v["valid"])
        self.assertEqual(v["expected_hash"], v["recovered_hash"])

    def test_tampered_message_rejected(self) -> None:
        s = sign(self.keys["private_key"], b"original message", self.group)
        v = verify(
            self.keys["public_key"],
            b"tampered message",
            s["signature"],
            self.group,
        )
        self.assertFalse(v["valid"])

    def test_tampered_signature_rejected(self) -> None:
        s = sign(self.keys["private_key"], b"original message", self.group)
        bad_sigma = (s["signature"] + 1) % self.keys["public_key"]["N"]
        v = verify(self.keys["public_key"], b"original message", bad_sigma, self.group)
        self.assertFalse(v["valid"])

    def test_signature_is_deterministic_for_fixed_inputs(self) -> None:
        # Hash-then-sign with the same message, key, and group should produce
        # the same signature because the hash is deterministic.
        msg = b"determinism check"
        s1 = sign(self.keys["private_key"], msg, self.group)
        s2 = sign(self.keys["private_key"], msg, self.group)
        self.assertEqual(s1["signature"], s2["signature"])


class TestPA15RawForgery(unittest.TestCase):
    """The required attack demo: raw RSA is multiplicatively forgeable."""

    def test_multiplicative_forgery_succeeds_on_raw_rsa(self) -> None:
        demo = multiplicative_forgery_demo(bits=512, rng=random.Random(7))
        self.assertTrue(demo["forgery_valid"])
        # Sanity: signatures should be in the expected range (< N is implied by mod).
        self.assertGreater(demo["forged_signature"], 0)
        self.assertGreater(demo["forged_message"], 0)

    def test_raw_helpers_roundtrip(self) -> None:
        rng = random.Random(13)
        keys = rsa_keygen(bits=512, rng=rng)
        m = 12345
        sigma = sign_raw(keys["private_key"], m)
        self.assertTrue(verify_raw(keys["public_key"], m, sigma))


class TestPA15EUFCMA(unittest.TestCase):
    """Hash-then-sign should resist EUF-CMA forgery in every test run."""

    def test_naive_forgery_attempt_fails(self) -> None:
        game = euf_cma_game(
            queries=20, bits=512, q_bits=31, rng=random.Random(99)
        )
        self.assertFalse(game["forgery_succeeded"])
        self.assertEqual(game["queries"], 20)


class TestPA15API(unittest.TestCase):
    """Tests against the api_ui wrappers (what the React app will call)."""

    def test_sign_and_verify_endpoints(self) -> None:
        signed = sign_endpoint("hello world", bits=512, q_bits=31, seed=21)
        result = signed["result"]

        verified = verify_endpoint(
            message="hello world",
            signature=result["signature"],
            public_key=result["public_key"],
            group_params=result["group"],
        )
        self.assertTrue(verified["result"]["valid"])

    def test_forgery_endpoint_returns_successful_attack(self) -> None:
        out = multiplicative_forgery_endpoint(bits=512, seed=4)
        self.assertTrue(out["result"]["forgery_valid"])

    def test_euf_cma_endpoint_blocks_forgery(self) -> None:
        out = euf_cma_endpoint(queries=10, bits=512, q_bits=31, seed=77)
        self.assertFalse(out["result"]["forgery_succeeded"])


if __name__ == "__main__":
    unittest.main()
