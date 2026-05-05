import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from api_ui.pa7_hooks import pa7_collision_demo_hook, pa7_md_hash_hook
from primitives.pa7_merkle_damgard import (
    get_pa7_hash_interface,
    md_hash,
    md_pad,
    toy_compress,
)


class TestPA7MerkleDamgard(unittest.TestCase):
    def test_md_pad_block_alignment_and_length_footer(self) -> None:
        message = b"abc"
        padded = md_pad(message, block_size=16, length_size=8)

        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(padded[-8:], (len(message) * 8).to_bytes(8, "big"))

    def test_md_pad_edge_case_exact_fit_after_0x80(self) -> None:
        # len=7 with block_size=16 and length_size=8 should fit in one final block.
        message = b"A" * 7
        padded = md_pad(message, block_size=16, length_size=8)

        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-8:], (56).to_bytes(8, "big"))

    def test_md_pad_edge_case_forces_extra_block(self) -> None:
        # len=8 with block_size=16 and length_size=8 must spill to a second block.
        message = b"B" * 8
        padded = md_pad(message, block_size=16, length_size=8)

        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-8:], (64).to_bytes(8, "big"))

    def test_md_hash_matches_manual_iteration(self) -> None:
        iv = b"\x01\x02"
        block_size = 8
        message = b"PA7-manual"

        # Manual MD loop equivalent to md_hash for comparison.
        padded = md_pad(message, block_size=block_size)
        manual = iv
        for i in range(0, len(padded), block_size):
            manual = toy_compress(manual, padded[i : i + block_size])

        computed = md_hash(message, compress_fn=toy_compress, iv=iv, block_size=block_size)
        self.assertEqual(computed, manual)

    def test_stable_interface_contract(self) -> None:
        contract, hash_fn = get_pa7_hash_interface(block_size=16, digest_size=2)
        digest = hash_fn("hello")

        self.assertEqual(contract.name, "pa7.toy-md")
        self.assertEqual(contract.block_size, 16)
        self.assertEqual(contract.digest_size, 2)
        self.assertEqual(len(digest), 2)

    def test_collision_propagation_demo(self) -> None:
        response = pa7_collision_demo_hook({"suffix": "same-tail"})
        result = response["result"]

        self.assertTrue(result["collision_found"])
        self.assertTrue(result["hashes_equal"])
        self.assertNotEqual(result["block_a_hex"], result["block_b_hex"])

    def test_md_hash_hook_output_shape(self) -> None:
        response = pa7_md_hash_hook({"message": "hello"})

        self.assertEqual(response["pa_id"], "PA-7")
        self.assertIn("hash_hex", response["result"])
        self.assertIn("contract", response["result"])


if __name__ == "__main__":
    unittest.main()
