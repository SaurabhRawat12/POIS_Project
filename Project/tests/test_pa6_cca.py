import pathlib
import sys
import unittest
import os

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from primitives.pa4_modes import build_feistel_cipher
from primitives.pa5_mac import cbc_mac_tag, cbc_mac_verify
from primitives.pa6_cca_symmetric import (
    cca_enc,
    cca_dec,
    ind_cca2_game,
    cpa_malleability_demo,
    cca_malleability_demo,
)


def toy_cpa_enc(key: bytes, message: bytes) -> tuple[bytes, bytes]:
    cipher = build_feistel_cipher(key)
    nonce = os.urandom(cipher.block_size)
    ct = bytearray()
    counter = int.from_bytes(nonce, "big")
    for block_index in range(0, len(message), cipher.block_size):
        block = message[block_index : block_index + cipher.block_size]
        stream = cipher.encrypt_block((counter + block_index // cipher.block_size).to_bytes(cipher.block_size, "big"))
        ct.extend(bytes(x ^ y for x, y in zip(block, stream[: len(block)])))
    return nonce, bytes(ct)


def toy_cpa_dec(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = build_feistel_cipher(key)
    pt = bytearray()
    counter = int.from_bytes(nonce, "big")
    for block_index in range(0, len(ciphertext), cipher.block_size):
        block = ciphertext[block_index : block_index + cipher.block_size]
        stream = cipher.encrypt_block((counter + block_index // cipher.block_size).to_bytes(cipher.block_size, "big"))
        pt.extend(bytes(x ^ y for x, y in zip(block, stream[: len(block)])))
    return bytes(pt)


class TestPA6CCA(unittest.TestCase):
    def test_cca_encrypt_then_decrypt(self) -> None:
        key_enc = b"E" * 16
        key_mac = b"M" * 16
        msg = b"hello world"
        cipher = build_feistel_cipher(key_mac)
        blob, tag = cca_enc(
            key_enc,
            key_mac,
            msg,
            cpa_enc=toy_cpa_enc,
            mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16),
        )
        out = cca_dec(
            key_enc,
            key_mac,
            blob,
            tag,
            cpa_dec=toy_cpa_dec,
            verify_fn=lambda k, m, t: cbc_mac_verify(k, m, t, block_cipher=lambda k2, b: cipher.encrypt_block(b), block_size=16),
            nonce_size=16,
        )
        self.assertEqual(out, msg)

    def test_ind_cca2_game_runs(self) -> None:
        result = ind_cca2_game(
            cpa_enc=toy_cpa_enc,
            cpa_dec=toy_cpa_dec,
            mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: build_feistel_cipher(k).encrypt_block(b), block_size=16),
            verify_fn=lambda k, m, t: cbc_mac_verify(k, m, t, block_cipher=lambda k2, b: build_feistel_cipher(k).encrypt_block(b), block_size=16),
            rounds=10,
            block_size=16,
        )
        self.assertIn("wins", result)

    def test_malleability_demo(self) -> None:
        key_enc = b"E" * 16
        key_mac = b"M" * 16
        msg = b"message"
        cpa = cpa_malleability_demo(key_enc, msg, cpa_enc=toy_cpa_enc, cpa_dec=toy_cpa_dec)
        self.assertNotEqual(cpa["plaintext_hex"], cpa["altered_plaintext_hex"])
        cca = cca_malleability_demo(
            key_enc,
            key_mac,
            msg,
            cpa_enc=toy_cpa_enc,
            cpa_dec=toy_cpa_dec,
            mac_fn=lambda k, m: cbc_mac_tag(k, m, block_cipher=lambda k2, b: build_feistel_cipher(k).encrypt_block(b), block_size=16),
            verify_fn=lambda k, m, t: cbc_mac_verify(k, m, t, block_cipher=lambda k2, b: build_feistel_cipher(k).encrypt_block(b), block_size=16),
            nonce_size=16,
        )
        self.assertTrue(cca["tampered_rejected"])


if __name__ == "__main__":
    unittest.main()
