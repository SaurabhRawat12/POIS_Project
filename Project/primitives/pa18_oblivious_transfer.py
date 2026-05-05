"""PA #18: 1-out-of-2 Oblivious Transfer (Bellare-Micali on ElGamal).

The atomic primitive of secure multi-party computation.

    Sender holds (m_0, m_1).
    Receiver holds choice bit b in {0, 1}.

After the protocol:
    Receiver learns m_b and nothing about m_{1-b}.
    Sender learns nothing about b.

Bellare-Micali construction on top of PA #16 ElGamal:

    Public setup     :  cyclic group (p, g, q) plus a fixed public element C
                        (a random group element whose discrete log is unknown).

    Receiver step 1  :  pick random k in [1, q).
                        Honest key: pk_b   = g^k mod p   (knows sk_b = k).
                        Fake key  : pk_{1-b} = C * pk_b^{-1} mod p  (no trapdoor).
                        Send (pk_0, pk_1) to sender.

    Sender step      :  verify  pk_0 * pk_1 == C  (mod p).
                        Encrypt m_0 under pk_0 and m_1 under pk_1
                        using PA #16 ElGamal.  Send both ciphertexts.

    Receiver step 2  :  decrypt only the b-th ciphertext (skips the other).

Why secure:
    Receiver privacy : pk_0 and pk_1 look uniformly random under the constraint
                       pk_0 * pk_1 = C, so the sender cannot tell which is real.
    Sender privacy   : receiver does not know the discrete log of pk_{1-b},
                       so decrypting C_{1-b} reduces to solving DLP.

Lineage (no external crypto libraries):
    PA #18 -> PA #16 (ElGamal enc/dec)
           -> PA #11 (DH safe-prime group setup)
           -> PA #13 (Miller-Rabin prime generation, transitively)

Public API (used by PA #19):
    ot_setup(...)             -> shared parameters
    ot_receiver_step1(b, ...) -> (pk_0, pk_1, state)
    ot_sender_step(...)       -> (C_0, C_1)
    ot_receiver_step2(...)    -> m_b
"""

from __future__ import annotations

import random
from typing import Any, Dict, Tuple

from core_math.number_theory import mod_inverse, modexp
from core_math.randomness import system_rng
from primitives.pa11_diffie_hellman import dh_generate_group
from primitives.pa16_elgamal import elgamal_dec, elgamal_enc

PA_ID = "PA#18"


# ---------------------------------------------------------------------------
# Setup: shared public parameters
# ---------------------------------------------------------------------------

def ot_setup(
    *,
    q_bits: int = 255,
    k: int = 40,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Generate shared OT parameters: group (p, g, q) plus fixed public element C.

    C is constructed as g^alpha for a random alpha that is then DISCARDED, so
    nobody knows the discrete log of C. This is the standard trick that makes
    Bellare-Micali OT secure.
    """
    active_rng = rng or system_rng()
    group = dh_generate_group(q_bits=q_bits, k=k, rng=active_rng)
    p, g, q = int(group["p"]), int(group["g"]), int(group["q"])

    # Sample alpha, compute C = g^alpha, then discard alpha.
    alpha = active_rng.randrange(1, q)
    C = modexp(g, alpha, p)
    del alpha  # nobody should know log_g(C)

    return {
        "pa_id": PA_ID,
        "algorithm": "OTSetup",
        "p": p,
        "g": g,
        "q": q,
        "C": C,
        "security_note": (
            "C = g^alpha for alpha discarded. Discrete log of C is unknown to "
            "all parties, which is essential for Bellare-Micali OT security."
        ),
    }


# ---------------------------------------------------------------------------
# Receiver: step 1 -- generate the two public keys
# ---------------------------------------------------------------------------

def ot_receiver_step1(
    b: int,
    params: Dict[str, Any],
    *,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Receiver chooses bit b and constructs (pk_0, pk_1).

    Returns:
        pk_0, pk_1 : the two public keys to send to the sender
        state      : private state (b, secret) for use in step 2
    """
    if b not in (0, 1):
        raise ValueError("choice bit b must be 0 or 1")

    p, g, q, C = int(params["p"]), int(params["g"]), int(params["q"]), int(params["C"])
    active_rng = rng or system_rng()

    # Honest key: receiver knows the secret
    k_secret = active_rng.randrange(1, q)
    pk_real = modexp(g, k_secret, p)

    # Fake key: pk_other = C * pk_real^{-1}; constraint pk_0 * pk_1 = C holds
    pk_real_inv = mod_inverse(pk_real, p)
    pk_fake = (C * pk_real_inv) % p

    if b == 0:
        pk_0, pk_1 = pk_real, pk_fake
    else:
        pk_0, pk_1 = pk_fake, pk_real

    state = {"b": b, "k_secret": k_secret}

    return {
        "pa_id": PA_ID,
        "algorithm": "OTReceiverStep1",
        "pk_0": pk_0,
        "pk_1": pk_1,
        "state": state,
    }


# ---------------------------------------------------------------------------
# Sender: encrypt both messages, one under each pk
# ---------------------------------------------------------------------------

def ot_sender_step(
    params: Dict[str, Any],
    pk_0: int,
    pk_1: int,
    m_0: int,
    m_1: int,
    *,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Sender encrypts m_0 under pk_0 and m_1 under pk_1.

    First verifies the constraint pk_0 * pk_1 == C. If a malicious receiver
    sent two real public keys (so they could decrypt both), this check fails.
    """
    p, g, q, C = int(params["p"]), int(params["g"]), int(params["q"]), int(params["C"])

    if (pk_0 * pk_1) % p != C:
        raise ValueError(
            "OT sender check failed: pk_0 * pk_1 != C (mod p). "
            "Receiver may be trying to learn both messages."
        )
    if not (0 < m_0 < p) or not (0 < m_1 < p):
        raise ValueError("messages must satisfy 0 < m < p")

    active_rng = rng or system_rng()

    # Build PA #16-style public-key dicts and encrypt.
    pk_dict_0 = {"p": p, "g": g, "q": q, "h": pk_0}
    pk_dict_1 = {"p": p, "g": g, "q": q, "h": pk_1}

    enc_0 = elgamal_enc(pk_dict_0, m_0, rng=active_rng)
    enc_1 = elgamal_enc(pk_dict_1, m_1, rng=active_rng)

    return {
        "pa_id": PA_ID,
        "algorithm": "OTSenderStep",
        "C_0": {"c1": enc_0["c1"], "c2": enc_0["c2"]},
        "C_1": {"c1": enc_1["c1"], "c2": enc_1["c2"]},
        "security_note": (
            "Both messages encrypted under different public keys; receiver "
            "can decrypt only the one for which they hold the secret."
        ),
    }


# ---------------------------------------------------------------------------
# Receiver: step 2 -- decrypt only the b-th ciphertext
# ---------------------------------------------------------------------------

def ot_receiver_step2(
    state: Dict[str, Any],
    params: Dict[str, Any],
    C_0: Dict[str, int],
    C_1: Dict[str, int],
) -> Dict[str, Any]:
    """Receiver decrypts only the b-th ciphertext using sk_b = k_secret."""
    p, g, q = int(params["p"]), int(params["g"]), int(params["q"])
    b = int(state["b"])
    k_secret = int(state["k_secret"])

    chosen = C_0 if b == 0 else C_1
    c1, c2 = int(chosen["c1"]), int(chosen["c2"])

    # Reconstruct pk_b dict so we can call PA #16 elgamal_dec as a black box.
    pk_b_h = modexp(g, k_secret, p)
    pk_b_dict = {"p": p, "g": g, "q": q, "h": pk_b_h}
    sk_dict = {"x": k_secret}

    m_b = elgamal_dec(sk_dict, pk_b_dict, c1, c2)

    return {
        "pa_id": PA_ID,
        "algorithm": "OTReceiverStep2",
        "b": b,
        "m_b": m_b,
    }


# ---------------------------------------------------------------------------
# Convenience: full one-shot OT (sender + receiver in one call, for testing)
# ---------------------------------------------------------------------------

def ot_run(
    b: int,
    m_0: int,
    m_1: int,
    *,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Run a full OT exchange end-to-end. Useful for tests and demos."""
    active_rng = rng or system_rng()
    params = ot_setup(q_bits=q_bits, k=k, rng=active_rng)

    r1 = ot_receiver_step1(b, params, rng=active_rng)
    s = ot_sender_step(
        params, r1["pk_0"], r1["pk_1"], m_0, m_1, rng=active_rng
    )
    r2 = ot_receiver_step2(r1["state"], params, s["C_0"], s["C_1"])

    return {
        "pa_id": PA_ID,
        "algorithm": "OTRun",
        "b": b,
        "m_0": m_0,
        "m_1": m_1,
        "received": r2["m_b"],
        "correct": r2["m_b"] == (m_0 if b == 0 else m_1),
        "transcript": {
            "params": {"p": params["p"], "g": params["g"], "q": params["q"], "C": params["C"]},
            "pk_0": r1["pk_0"],
            "pk_1": r1["pk_1"],
            "C_0": s["C_0"],
            "C_1": s["C_1"],
        },
    }


# ---------------------------------------------------------------------------
# Demo: receiver privacy and sender privacy
# ---------------------------------------------------------------------------

def receiver_privacy_demo(
    params: Dict[str, Any] | None = None,
    *,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Show that pk_0 and pk_1 satisfy pk_0 * pk_1 = C regardless of b.

    Since both keys look uniformly random under that constraint, the sender
    cannot distinguish b=0 from b=1 by looking at the public keys.
    """
    active_rng = rng or system_rng()
    setup = params or ot_setup(q_bits=q_bits, k=k, rng=active_rng)
    p, C = int(setup["p"]), int(setup["C"])

    r0 = ot_receiver_step1(0, setup, rng=active_rng)
    r1 = ot_receiver_step1(1, setup, rng=active_rng)

    constraint_b0 = (r0["pk_0"] * r0["pk_1"]) % p == C
    constraint_b1 = (r1["pk_0"] * r1["pk_1"]) % p == C

    return {
        "pa_id": PA_ID,
        "algorithm": "OTReceiverPrivacyDemo",
        "constraint_holds_for_b0": constraint_b0,
        "constraint_holds_for_b1": constraint_b1,
        "security_note": (
            "pk_0 * pk_1 = C in both cases, with each key uniformly random "
            "under that constraint. Sender cannot tell b=0 from b=1."
        ),
    }


def sender_privacy_demo(
    *,
    q_bits: int = 63,
    k: int = 20,
    rng: random.Random | None = None,
) -> Dict[str, Any]:
    """Show that the receiver cannot decrypt the message they did NOT pick.

    The receiver runs OT honestly with b=0, learns m_0, and then attempts
    to decrypt C_1. Without the secret for pk_1 (which they do not know),
    elgamal_dec produces garbage, not m_1.
    """
    active_rng = rng or system_rng()
    m_0 = active_rng.randrange(2, 1 << 30)
    m_1 = active_rng.randrange(2, 1 << 30)
    while m_1 == m_0:
        m_1 = active_rng.randrange(2, 1 << 30)

    run = ot_run(b=0, m_0=m_0, m_1=m_1, q_bits=q_bits, k=k, rng=active_rng)

    # Cheat attempt: decrypt C_1 using the receiver's only secret (sk_0 = k_secret).
    # That secret is wrong for pk_1, so the result is garbage.
    params = run["transcript"]["params"]
    C_1 = run["transcript"]["C_1"]
    p, g, q = params["p"], params["g"], params["q"]
    # We re-run to get the receiver state cleanly.
    setup = {"p": p, "g": g, "q": q, "C": params["C"]}
    receiver = ot_receiver_step1(0, setup, rng=active_rng)
    sender = ot_sender_step(setup, receiver["pk_0"], receiver["pk_1"], m_0, m_1, rng=active_rng)
    legit = ot_receiver_step2(receiver["state"], setup, sender["C_0"], sender["C_1"])

    # Now cheat: try to decrypt sender["C_1"] using sk_0 anyway.
    pk_b_h_wrong = modexp(g, receiver["state"]["k_secret"], p)
    pk_dict_wrong = {"p": p, "g": g, "q": q, "h": pk_b_h_wrong}
    sk_dict = {"x": receiver["state"]["k_secret"]}
    cheat_decrypt = elgamal_dec(
        sk_dict, pk_dict_wrong,
        sender["C_1"]["c1"], sender["C_1"]["c2"],
    )

    return {
        "pa_id": PA_ID,
        "algorithm": "OTSenderPrivacyDemo",
        "m_0": m_0,
        "m_1": m_1,
        "legit_received": legit["m_b"],
        "cheat_attempt_on_C_1": cheat_decrypt,
        "cheat_recovered_m_1": cheat_decrypt == m_1,
        "security_note": (
            "Receiver chose b=0, so they hold sk_0 only. Re-using sk_0 to "
            "decrypt C_1 produces garbage, not m_1."
        ),
    }
