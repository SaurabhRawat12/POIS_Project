"""Tests for PA #17 CCA-secure PKC (Encrypt-then-Sign)."""

from __future__ import annotations

import random
import unittest

from api_ui.pa17_api import (
    decrypt_endpoint,
    encrypt_endpoint,
    ind_cca2_endpoint,
    keygen_endpoint,
    lineage_endpoint,
    malleability_blocked_endpoint,
)
from primitives.pa8_dlp_hash import DLPGroup
from protocols.pa17_cca_pkc import (
    BOTTOM,
    cca_pkc_dec,
    cca_pkc_enc,
    ind_cca2_game,
    lineage_trace,
    malleability_blocked_demo,
    pkc_keygen,
)


def _make_keys(seed: int = 1) -> dict:
    return pkc_keygen(
        elgamal_q_bits=63, rsa_bits=512, hash_q_bits=31,
        rng=random.Random(seed),
    )


class TestPA17Roundtrip(unittest.TestCase):
    """Encryption followed by decryption should recover the plaintext."""

    def test_basic_roundtrip(self) -> None:
        keys = _make_keys(seed=11)
        sealed = cca_pkc_enc(
            keys["encryption_pk"], keys["signing_sk"],
            42, keys["hash_group"], rng=random.Random(12),
        )
        opened = cca_pkc_dec(
            keys["encryption_sk"], keys["encryption_pk"],
            keys["verification_vk"], sealed["CE"], sealed["sigma"],
            keys["hash_group"],
        )
        self.assertTrue(opened["verified"])
        self.assertEqual(opened["plaintext"], 42)

    def test_multiple_messages(self) -> None:
        keys = _make_keys(seed=21)
        for m in (1, 2, 100, 999, 31415):
            sealed = cca_pkc_enc(
                keys["encryption_pk"], keys["signing_sk"],
                m, keys["hash_group"], rng=random.Random(m),
            )
            opened = cca_pkc_dec(
                keys["encryption_sk"], keys["encryption_pk"],
                keys["verification_vk"], sealed["CE"], sealed["sigma"],
                keys["hash_group"],
            )
            self.assertEqual(opened["plaintext"], m)


class TestPA17TamperRejection(unittest.TestCase):
    """Any modification to CE must cause decryption to return BOTTOM."""

    def test_tampered_c2_rejected(self) -> None:
        keys = _make_keys(seed=31)
        p = keys["encryption_pk"]["p"]
        sealed = cca_pkc_enc(
            keys["encryption_pk"], keys["signing_sk"],
            500, keys["hash_group"], rng=random.Random(32),
        )
        tampered = {"c1": sealed["CE"]["c1"], "c2": (sealed["CE"]["c2"] * 2) % p}
        opened = cca_pkc_dec(
            keys["encryption_sk"], keys["encryption_pk"],
            keys["verification_vk"], tampered, sealed["sigma"],
            keys["hash_group"],
        )
        self.assertFalse(opened["verified"])
        self.assertIs(opened["plaintext"], BOTTOM)

    def test_tampered_c1_rejected(self) -> None:
        keys = _make_keys(seed=41)
        p = keys["encryption_pk"]["p"]
        sealed = cca_pkc_enc(
            keys["encryption_pk"], keys["signing_sk"],
            777, keys["hash_group"], rng=random.Random(42),
        )
        tampered = {"c1": (sealed["CE"]["c1"] + 1) % p, "c2": sealed["CE"]["c2"]}
        opened = cca_pkc_dec(
            keys["encryption_sk"], keys["encryption_pk"],
            keys["verification_vk"], tampered, sealed["sigma"],
            keys["hash_group"],
        )
        self.assertIs(opened["plaintext"], BOTTOM)

    def test_tampered_signature_rejected(self) -> None:
        keys = _make_keys(seed=51)
        sealed = cca_pkc_enc(
            keys["encryption_pk"], keys["signing_sk"],
            123, keys["hash_group"], rng=random.Random(52),
        )
        bad_sigma = (sealed["sigma"] + 1) % keys["verification_vk"]["N"]
        opened = cca_pkc_dec(
            keys["encryption_sk"], keys["encryption_pk"],
            keys["verification_vk"], sealed["CE"], bad_sigma,
            keys["hash_group"],
        )
        self.assertIs(opened["plaintext"], BOTTOM)


class TestPA17MalleabilityDemo(unittest.TestCase):
    """The required side-by-side comparison: ElGamal vs CCA-PKC."""

    def test_plain_elgamal_succumbs_cca_pkc_blocks(self) -> None:
        demo = malleability_blocked_demo(
            elgamal_q_bits=63, rsa_bits=512, hash_q_bits=31,
            rng=random.Random(61),
        )
        self.assertTrue(demo["legit_correct"])
        self.assertTrue(demo["tampered_rejected"])
        # The plain-ElGamal control should still show the attack working.
        self.assertTrue(demo["plain_elgamal_attack_succeeded"])


class TestPA17CCAGame(unittest.TestCase):
    """Decryption oracle should reject every tampered ciphertext."""

    def test_oracle_rejects_all_tampers(self) -> None:
        game = ind_cca2_game(
            rounds=10, elgamal_q_bits=63, rsa_bits=512, hash_q_bits=31,
            rng=random.Random(71),
        )
        self.assertTrue(game["all_tampered_rejected"])
        self.assertEqual(game["oracle_rejected"], game["oracle_queries"])


class TestPA17Lineage(unittest.TestCase):
    """The lineage trace should mention every required prior PA."""

    def test_lineage_chain_is_complete(self) -> None:
        chain_text = "\n".join(lineage_trace()["chain"])
        for pa in ("PA#17", "PA#16", "PA#15", "PA#13", "PA#11", "PA#12", "PA#8"):
            self.assertIn(pa, chain_text)


class TestPA17API(unittest.TestCase):
    """Tests against the api_ui wrappers."""

    def test_keygen_encrypt_decrypt_endpoints(self) -> None:
        keys_resp = keygen_endpoint(
            elgamal_q_bits=63, rsa_bits=512, hash_q_bits=31, seed=81
        )
        keys = keys_resp["result"]

        enc_resp = encrypt_endpoint(
            pk_enc=keys["encryption_pk"],
            sk_sign=keys["signing_sk"],
            message=2024,
            hash_group=keys["hash_group"],
            seed=82,
        )
        sealed = enc_resp["result"]

        dec_resp = decrypt_endpoint(
            sk_enc=keys["encryption_sk"],
            pk_enc=keys["encryption_pk"],
            vk_sign=keys["verification_vk"],
            CE=sealed["CE"],
            sigma=sealed["sigma"],
            hash_group=keys["hash_group"],
        )
        self.assertEqual(dec_resp["result"]["plaintext"], 2024)

    def test_malleability_endpoint(self) -> None:
        resp = malleability_blocked_endpoint(
            elgamal_q_bits=63, rsa_bits=512, hash_q_bits=31, seed=83
        )
        self.assertTrue(resp["result"]["tampered_rejected"])
        self.assertTrue(resp["result"]["plain_elgamal_attack_succeeded"])

    def test_cca2_endpoint(self) -> None:
        resp = ind_cca2_endpoint(
            rounds=5, elgamal_q_bits=63, rsa_bits=512, hash_q_bits=31, seed=84
        )
        self.assertTrue(resp["result"]["all_tampered_rejected"])

    def test_lineage_endpoint(self) -> None:
        resp = lineage_endpoint()
        chain_text = "\n".join(resp["result"]["chain"])
        self.assertIn("PA#17", chain_text)
        self.assertIn("PA#13", chain_text)


if __name__ == "__main__":
    unittest.main()
