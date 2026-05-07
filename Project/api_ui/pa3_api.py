"""Framework-agnostic API handlers for PA #3 -- CPA-secure encryption."""

from __future__ import annotations

from typing import Any, Dict

from protocols.cpa_enc import (
    cpa_dec,
    cpa_enc,
    ind_cpa_dummy_adversary_experiment,
    ind_cpa_game,
    ind_cpa_nonce_reuse_attack_experiment,
)

PA_ID = "PA#3"


def _aes_stub() -> Dict[str, Any]:
    """Shared AES-not-implemented response."""
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "CPA-AES",
            "status": "NOT_IMPLEMENTED",
            "due_pa": "PA#4",
        },
    }


def cpa_encrypt_endpoint(
    k: str,
    m: str,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """CPA-secure encryption: C = <r, F_k(r) XOR m>.

    k is a binary string (key length n). m is a binary string of any length;
    multi-block messages use F_k(r), F_k(r+1), ... as the keystream.
    """
    if method == "aes":
        return _aes_stub()
    r, c = cpa_enc(k=k, m=m, method=method, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": f"CPA-Encrypt ({method.upper()})",
            "key": k,
            "message": m,
            "nonce": r,
            "ciphertext": c,
            "n_bits": len(k),
            "message_bits": len(m),
            "p": p,
            "g": g,
        },
    }


def cpa_decrypt_endpoint(
    k: str,
    r: str,
    c: str,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """CPA decryption: m = c XOR F_k(r)."""
    if method == "aes":
        return _aes_stub()
    m = cpa_dec(k=k, r=r, c=c, method=method, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": f"CPA-Decrypt ({method.upper()})",
            "key": k,
            "nonce": r,
            "ciphertext": c,
            "plaintext": m,
            "n_bits": len(k),
            "p": p,
            "g": g,
        },
    }


def ind_cpa_game_endpoint(
    k: str,
    m0: str,
    m1: str,
    reuse_nonce: bool = False,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Single round of the IND-CPA game.

    Challenger flips bit b, encrypts m_b, returns the challenge ciphertext.
    Set reuse_nonce=True to demonstrate the broken deterministic variant.
    """
    if method == "aes":
        return _aes_stub()
    return {
        "pa_id": PA_ID,
        "result": ind_cpa_game(
            k=k, m0=m0, m1=m1, reuse_nonce=reuse_nonce,
            method=method, p=p, g=g,
        ),
    }


def dummy_adversary_endpoint(
    k: str,
    m0: str,
    m1: str,
    rounds: int = 100,
    oracle_queries: int = 50,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Multi-round IND-CPA experiment (secure mode).

    A dummy adversary with encryption-oracle access should stay near 50%
    success rate, giving empirical advantage ~0.
    """
    if method == "aes":
        return _aes_stub()
    return {
        "pa_id": PA_ID,
        "result": ind_cpa_dummy_adversary_experiment(
            k=k, m0=m0, m1=m1,
            rounds=rounds, oracle_queries=oracle_queries,
            method=method, p=p, g=g,
        ),
    }


def nonce_reuse_attack_endpoint(
    k: str,
    m0: str,
    m1: str,
    rounds: int = 100,
    reuse_nonce: bool = True,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Multi-round nonce-reuse attack (broken mode).

    With reuse_nonce=True, encryption becomes deterministic. The adversary
    queries m0 and m1 once each, then matches the challenge ciphertext.
    Expect ~100% adversary success.
    """
    if method == "aes":
        return _aes_stub()
    return {
        "pa_id": PA_ID,
        "result": ind_cpa_nonce_reuse_attack_experiment(
            k=k, m0=m0, m1=m1,
            rounds=rounds, reuse_nonce=reuse_nonce,
            method=method, p=p, g=g,
        ),
    }