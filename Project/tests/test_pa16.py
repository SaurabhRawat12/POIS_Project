from __future__ import annotations

import random
import unittest

from api_ui.pa16_api import (
    elgamal_ind_cpa_endpoint,
    elgamal_keygen_endpoint,
    elgamal_malleability_demo_endpoint,
    elgamal_roundtrip_endpoint,
)
from primitives.pa16_elgamal import (
    elgamal_dec,
    elgamal_enc,
    elgamal_ind_cpa_game,
    elgamal_keygen,
    malleability_demo,
)


class TestPA16Core(unittest.TestCase):
    def test_keygen_encrypt_decrypt(self) -> None:
        keys = elgamal_keygen(q_bits=31, k=12, rng=random.Random(31))
        pk = keys["public_key"]
        sk = keys["private_key"]

        message = 12345
        c = elgamal_enc(pk, message, rng=random.Random(32))
        p = elgamal_dec(sk, pk, c["c1"], c["c2"])
        self.assertEqual(p, message)

    def test_malleability_demo(self) -> None:
        demo = malleability_demo(q_bits=31, k=12, factor=2, rng=random.Random(41))
        self.assertTrue(demo["malleability_success"])
        self.assertEqual(
            demo["decrypted_modified"], demo["expected_modified_plaintext"]
        )

    def test_ind_cpa_random_strategy(self) -> None:
        game = elgamal_ind_cpa_game(
            rounds=100, q_bits=31, k=12, strategy="random", rng=random.Random(51)
        )
        self.assertEqual(game["strategy"], "random")
        self.assertLess(game["advantage"], 0.2)

    def test_ind_cpa_bruteforce_tiny_group(self) -> None:
        game = elgamal_ind_cpa_game(
            rounds=30, q_bits=10, k=8, strategy="bruteforce", rng=random.Random(61)
        )
        self.assertEqual(game["strategy"], "bruteforce")
        self.assertIsNotNone(game["recovered_secret_x"])
        self.assertGreater(game["win_rate"], 0.8)


class TestPA16API(unittest.TestCase):
    def test_api_smoke(self) -> None:
        k = elgamal_keygen_endpoint(q_bits=31, k=12)["result"]
        self.assertIn("public_key", k)
        self.assertIn("private_key", k)

        r = elgamal_roundtrip_endpoint(message_int=321, q_bits=31, k=12)["result"]
        self.assertTrue(r["roundtrip_ok"])

        m = elgamal_malleability_demo_endpoint(q_bits=31, k=12)["result"]
        self.assertTrue(m["malleability_success"])

        cpa_rand = elgamal_ind_cpa_endpoint(
            rounds=60, q_bits=31, k=12, strategy="random", seed=71
        )["result"]
        self.assertLess(cpa_rand["advantage"], 0.3)

        cpa_break = elgamal_ind_cpa_endpoint(
            rounds=20, q_bits=10, k=8, strategy="bruteforce", seed=72
        )["result"]
        self.assertGreater(cpa_break["win_rate"], 0.75)


if __name__ == "__main__":
    unittest.main()

