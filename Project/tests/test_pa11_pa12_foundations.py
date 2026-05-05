from __future__ import annotations

import random
import unittest

from core_math.number_theory import modexp
from primitives.pa11_diffie_hellman import (
    dh_alice_step1,
    dh_alice_step2,
    dh_bob_step1,
    dh_bob_step2,
    dh_generate_group,
    mitm_demo,
)
from primitives.pa12_rsa import (
    pkcs15_dec,
    pkcs15_enc,
    rsa_dec,
    rsa_determinism_demo,
    rsa_enc,
    rsa_keygen,
)
from primitives.pa13_primality import is_prime


class TestPA11Foundations(unittest.TestCase):
    def test_dh_group_generation(self) -> None:
        group = dh_generate_group(q_bits=31, k=12, rng=random.Random(1))
        p = group["p"]
        q = group["q"]
        g = group["g"]

        self.assertEqual(p, 2 * q + 1)
        self.assertTrue(is_prime(q, k=20))
        self.assertTrue(is_prime(p, k=20))
        self.assertEqual(modexp(g, q, p), 1)
        self.assertNotEqual(g, 1)

    def test_dh_key_exchange(self) -> None:
        group = dh_generate_group(q_bits=31, k=12, rng=random.Random(2))
        alice = dh_alice_step1(group, rng=random.Random(3))
        bob = dh_bob_step1(group, rng=random.Random(4))
        ka = dh_alice_step2(alice["a"], bob["B"], group)
        kb = dh_bob_step2(bob["b"], alice["A"], group)
        self.assertEqual(ka, kb)

    def test_dh_mitm_demo(self) -> None:
        demo = mitm_demo(rng=random.Random(5))
        self.assertTrue(demo["mitm_success"])


class TestPA12Foundations(unittest.TestCase):
    def test_rsa_keygen_and_roundtrip(self) -> None:
        keys = rsa_keygen(bits=256, k=12, rng=random.Random(9))
        pk = keys["public_key"]
        sk = keys["private_key"]
        m = 123456789
        c = rsa_enc(pk, m)
        p = rsa_dec(sk, c)
        self.assertEqual(m, p)

    def test_pkcs15_roundtrip(self) -> None:
        keys = rsa_keygen(bits=256, k=12, rng=random.Random(11))
        pk = keys["public_key"]
        sk = keys["private_key"]
        msg = b"vote=yes"
        c = pkcs15_enc(pk, msg, rng=random.Random(12))
        out = pkcs15_dec(sk, c)
        self.assertEqual(out, msg)

    def test_rsa_determinism_demo(self) -> None:
        demo = rsa_determinism_demo(message=b"yes", bits=256, rng=random.Random(15))
        self.assertTrue(demo["textbook_equal"])
        self.assertFalse(demo["pkcs15_equal"])
        self.assertTrue(demo["decrypt_check"])


if __name__ == "__main__":
    unittest.main()

