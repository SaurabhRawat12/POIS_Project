import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from primitives.pa4_modes import (
    build_feistel_cipher,
    cbc_decrypt,
    cbc_encrypt,
    ctr_decrypt,
    ctr_encrypt,
    ofb_decrypt,
    ofb_encrypt,
    cbc_iv_reuse_attack_demo,
    ofb_keystream_reuse_attack_demo,
)


class TestPA4Modes(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"K" * 16
        self.cipher = build_feistel_cipher(self.key, block_size=16)

    def test_cbc_correctness_varied_lengths(self) -> None:
        for msg in [b"short", b"A" * 16, b"B" * 40]:
            iv, ct = cbc_encrypt(self.key, msg, block_cipher=self.cipher, block_size=16)
            pt = cbc_decrypt(self.key, iv, ct, block_cipher=self.cipher, block_size=16)
            self.assertEqual(pt, msg)

    def test_ofb_correctness_varied_lengths(self) -> None:
        for msg in [b"short", b"A" * 16, b"B" * 40]:
            iv, ct = ofb_encrypt(self.key, msg, block_cipher=self.cipher, block_size=16)
            pt = ofb_decrypt(self.key, iv, ct, block_cipher=self.cipher, block_size=16)
            self.assertEqual(pt, msg)

    def test_ctr_correctness_varied_lengths(self) -> None:
        for msg in [b"short", b"A" * 16, b"B" * 40]:
            nonce, ct = ctr_encrypt(self.key, msg, block_cipher=self.cipher, block_size=16)
            pt = ctr_decrypt(self.key, nonce, ct, block_cipher=self.cipher, block_size=16)
            self.assertEqual(pt, msg)

    def test_cbc_iv_reuse_demo(self) -> None:
        iv = b"I" * 16
        msg_a = b"A" * 16 + b"X" * 5
        msg_b = b"A" * 16 + b"Y" * 5
        demo = cbc_iv_reuse_attack_demo(self.key, msg_a, msg_b, iv, block_cipher=self.cipher, block_size=16)
        self.assertIn(0, demo["same_block_indices"])

    def test_ofb_keystream_reuse_demo(self) -> None:
        iv = b"I" * 16
        msg_a = b"hello world"
        msg_b = b"secrets here"
        demo = ofb_keystream_reuse_attack_demo(self.key, msg_a, msg_b, iv, block_cipher=self.cipher, block_size=16)
        self.assertTrue(demo["xor_matches"])


if __name__ == "__main__":
    unittest.main()
