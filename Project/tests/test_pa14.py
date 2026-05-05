from __future__ import annotations

import random
import unittest

from api_ui.pa14_api import crt_endpoint, hastad_demo_endpoint, rsa_dec_crt_endpoint
from primitives.pa12_rsa import pkcs15_enc, rsa_dec, rsa_enc, rsa_keygen
from primitives.pa14_crt_hastad import (
    crt,
    hastad_attack,
    hastad_attack_verbose,
    integer_nth_root,
    rsa_dec_crt,
)


class TestPA14CRT(unittest.TestCase):
    def test_crt_simple_system(self) -> None:
        x = crt([2, 3, 2], [3, 5, 7])
        self.assertEqual(x, 23)

    def test_integer_nth_root(self) -> None:
        root, exact = integer_nth_root(27, 3)
        self.assertEqual(root, 3)
        self.assertTrue(exact)

        root2, exact2 = integer_nth_root(28, 3)
        self.assertEqual(root2, 3)
        self.assertFalse(exact2)


class TestPA14RSACRT(unittest.TestCase):
    def test_rsa_dec_crt_matches_standard(self) -> None:
        keys = rsa_keygen(bits=256, e=65537, k=20, rng=random.Random(20))
        pk = keys["public_key"]
        sk = keys
        for m in [1, 2, 42, 12345, 999999]:
            c = rsa_enc(pk, m)
            plain_std = rsa_dec(keys["private_key"], c)
            plain_crt = rsa_dec_crt(sk, c)
            self.assertEqual(plain_std, plain_crt)
            self.assertEqual(m, plain_crt)


class TestPA14Hastad(unittest.TestCase):
    def test_hastad_attack_recovers_message(self) -> None:
        e = 3
        keys = [rsa_keygen(bits=128, e=e, k=8) for _ in range(e)]
        pks = [k["public_key"] for k in keys]
        moduli = [pk["N"] for pk in pks]

        message = 123456789
        ciphertexts = [rsa_enc(pk, message) for pk in pks]
        recovered = hastad_attack(ciphertexts, moduli, e)
        info = hastad_attack_verbose(ciphertexts, moduli, e)

        self.assertEqual(recovered, message)
        self.assertTrue(info["is_exact_root"])
        self.assertEqual(info["recovered_message"], message)

    def test_pkcs15_breaks_hastad_exact_root(self) -> None:
        e = 3
        keys = [rsa_keygen(bits=128, e=e, k=8) for _ in range(e)]
        pks = [k["public_key"] for k in keys]
        moduli = [pk["N"] for pk in pks]
        msg = b"yes"
        ciphertexts = [pkcs15_enc(pk, msg) for pk in pks]
        info = hastad_attack_verbose(ciphertexts, moduli, e)
        self.assertFalse(info["is_exact_root"])


class TestPA14API(unittest.TestCase):
    def test_api_smoke(self) -> None:
        crt_payload = crt_endpoint([2, 3, 2], [3, 5, 7])
        self.assertEqual(crt_payload["result"]["x"], 23)

        keys = rsa_keygen(bits=128, e=65537, k=8)
        c = rsa_enc(keys["public_key"], 77)
        crt_dec = rsa_dec_crt_endpoint(keys, c)
        self.assertEqual(crt_dec["result"]["plaintext"], 77)

        demo_plain = hastad_demo_endpoint(
            message_int=12345, bits=128, e=3, use_pkcs15=False, k=8, rng=random.Random(21)
        )
        self.assertTrue(demo_plain["result"]["attack"]["is_exact_root"])

        demo_pkcs = hastad_demo_endpoint(
            message_int=12345, bits=128, e=3, use_pkcs15=True, k=8, rng=random.Random(22)
        )
        self.assertFalse(demo_pkcs["result"]["attack"]["is_exact_root"])


if __name__ == "__main__":
    unittest.main()
