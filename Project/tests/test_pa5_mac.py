import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from primitives.pa4_modes import build_feistel_cipher
from primitives.pa5_mac import (
    prf_mac_tag,
    prf_mac_verify,
    cbc_mac_tag,
    cbc_mac_verify,
    euf_cma_game,
    length_extension_demo,
)


class TestPA5MAC(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"K" * 16
        self.cipher = build_feistel_cipher(self.key, block_size=16)

    def test_prf_mac_fixed_length(self) -> None:
        msg = b"A" * 16
        tag = prf_mac_tag(self.key, msg, block_size=16)
        self.assertTrue(prf_mac_verify(self.key, msg, tag, block_size=16))

    def test_cbc_mac_variable_length(self) -> None:
        msg = b"hello world"
        tag = cbc_mac_tag(self.key, msg, block_cipher=lambda k, b: self.cipher.encrypt_block(b), block_size=16)
        self.assertTrue(cbc_mac_verify(self.key, msg, tag, block_cipher=lambda k, b: self.cipher.encrypt_block(b), block_size=16))

    def test_euf_cma_game_naive_adversary(self) -> None:
        result = euf_cma_game(
            self.key,
            mac_fn=lambda k, m: prf_mac_tag(k, m, block_size=8),
            verify_fn=lambda k, m, t: prf_mac_verify(k, m, t, block_size=8),
            block_size=8,
            queries=20,
            trials=10,
        )
        self.assertEqual(result["successes"], 0)

    def test_length_extension_demo(self) -> None:
        result = length_extension_demo(b"secret", b"msg", b"suffix", block_size=16)
        self.assertTrue(result["attack_success"])


if __name__ == "__main__":
    unittest.main()
