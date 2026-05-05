"""Tests for PA #18 1-out-of-2 oblivious transfer."""

from __future__ import annotations

import random
import unittest

from api_ui.pa18_api import (
    ot_run_endpoint,
    receiver_privacy_endpoint,
    sender_privacy_endpoint,
)
from primitives.pa18_oblivious_transfer import (
    ot_receiver_step1,
    ot_receiver_step2,
    ot_run,
    ot_sender_step,
    ot_setup,
    receiver_privacy_demo,
    sender_privacy_demo,
)


class TestPA18Correctness(unittest.TestCase):
    """Functional correctness: receiver always learns m_b."""

    def test_b_zero_receives_m0(self) -> None:
        result = ot_run(b=0, m_0=12345, m_1=67890, q_bits=63, k=20, rng=random.Random(1))
        self.assertEqual(result["received"], 12345)
        self.assertTrue(result["correct"])

    def test_b_one_receives_m1(self) -> None:
        result = ot_run(b=1, m_0=12345, m_1=67890, q_bits=63, k=20, rng=random.Random(2))
        self.assertEqual(result["received"], 67890)
        self.assertTrue(result["correct"])

    def test_one_hundred_random_trials(self) -> None:
        rng = random.Random(42)
        wins = 0
        for _ in range(100):
            b = rng.randint(0, 1)
            m_0 = rng.randint(2, 10**9)
            m_1 = rng.randint(2, 10**9)
            r = ot_run(b=b, m_0=m_0, m_1=m_1, q_bits=63, k=20, rng=rng)
            if r["correct"]:
                wins += 1
        self.assertEqual(wins, 100)

    def test_invalid_choice_bit_rejected(self) -> None:
        params = ot_setup(q_bits=63, k=20, rng=random.Random(7))
        with self.assertRaises(ValueError):
            ot_receiver_step1(2, params)


class TestPA18ReceiverPrivacy(unittest.TestCase):
    """Sender cannot distinguish b=0 from b=1 from (pk_0, pk_1)."""

    def test_constraint_pk0_times_pk1_equals_C(self) -> None:
        demo = receiver_privacy_demo(q_bits=63, k=20, rng=random.Random(3))
        self.assertTrue(demo["constraint_holds_for_b0"])
        self.assertTrue(demo["constraint_holds_for_b1"])


class TestPA18SenderPrivacy(unittest.TestCase):
    """Receiver cannot decrypt m_{1-b}."""

    def test_cheat_attempt_does_not_recover_other_message(self) -> None:
        demo = sender_privacy_demo(q_bits=63, k=20, rng=random.Random(4))
        self.assertEqual(demo["legit_received"], demo["m_0"])
        self.assertFalse(demo["cheat_recovered_m_1"])


class TestPA18MaliciousReceiver(unittest.TestCase):
    """A receiver who sends an invalid (pk_0, pk_1) is rejected by the sender."""

    def test_sender_rejects_invalid_pk_constraint(self) -> None:
        params = ot_setup(q_bits=63, k=20, rng=random.Random(11))
        # Try to send pk_0 = pk_1 = g (both real keys, both with known sk = 1).
        # This violates pk_0 * pk_1 = C with overwhelming probability.
        bad_pk = params["g"]
        with self.assertRaises(ValueError):
            ot_sender_step(params, bad_pk, bad_pk, 100, 200, rng=random.Random(12))


class TestPA18API(unittest.TestCase):
    """Tests against the api_ui wrappers (what the React app will call)."""

    def test_ot_run_endpoint(self) -> None:
        out = ot_run_endpoint(b=1, m_0=999, m_1=1234, q_bits=63, k=20, seed=21)
        self.assertTrue(out["result"]["correct"])
        self.assertEqual(out["result"]["received"], 1234)

    def test_receiver_privacy_endpoint(self) -> None:
        out = receiver_privacy_endpoint(q_bits=63, k=20, seed=22)
        self.assertTrue(out["result"]["constraint_holds_for_b0"])
        self.assertTrue(out["result"]["constraint_holds_for_b1"])

    def test_sender_privacy_endpoint(self) -> None:
        out = sender_privacy_endpoint(q_bits=63, k=20, seed=23)
        self.assertFalse(out["result"]["cheat_recovered_m_1"])


if __name__ == "__main__":
    unittest.main()
