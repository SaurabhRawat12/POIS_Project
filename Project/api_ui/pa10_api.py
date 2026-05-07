"""Framework-agnostic API handlers for PA #10 -- HMAC + Encrypt-then-HMAC."""

from __future__ import annotations

from typing import Any, Dict, Optional

from primitives.pa8_dlp_hash import DLPGroup
from primitives.pa10_hmac import (
    PA_ID,
    crhf_to_mac_demo,
    eth_dec,
    eth_enc,
    hmac_tag,
    hmac_verify,
    length_extension_demo,
    mac_to_crhf_demo,
    secure_compare,
    timing_comparison_demo,
)


def _build_group(params: Dict[str, int]) -> DLPGroup:
    """Reconstruct a DLPGroup from a serialized params dict."""
    p = int(params["p"])
    q = int(params["q"])
    g = int(params["g"])
    h_gen = int(params["h_gen"])
    return DLPGroup(
        p=p,
        q=q,
        g=g,
        h_gen=h_gen,
        p_byte_len=(p.bit_length() + 7) // 8,
        q_byte_len=(q.bit_length() + 7) // 8,
    )


def _resolve_group(params: Optional[Dict[str, int]], q_bits: int) -> DLPGroup:
    """Either reconstruct from params or generate a fresh toy group."""
    if params is None:
        return DLPGroup.generate(q_bits=q_bits)
    return _build_group(params)


def hmac_tag_endpoint(
    key_hex: str,
    message: str,
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Compute HMAC_k(m) using PA #8's DLP hash."""
    group = _resolve_group(params, q_bits)
    key = bytes.fromhex(key_hex)
    tag = hmac_tag(key=key, message=message, group=group)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "HMAC-DLPHash",
            "key_hex": key.hex(),
            "message": message,
            "tag_hex": tag.hex(),
            "tag_bytes": len(tag),
            "group": {
                "p": group.p, "q": group.q,
                "g": group.g, "h_gen": group.h_gen,
            },
        },
    }


def hmac_verify_endpoint(
    key_hex: str,
    message: str,
    tag_hex: str,
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Verify an HMAC tag (constant-time comparison)."""
    group = _resolve_group(params, q_bits)
    key = bytes.fromhex(key_hex)
    tag = bytes.fromhex(tag_hex)
    valid = hmac_verify(key=key, message=message, tag=tag, group=group)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "HMAC-Verify",
            "verdict": "ACCEPT" if valid else "REJECT",
            "valid": valid,
            "key_hex": key.hex(),
            "message": message,
            "tag_hex": tag.hex(),
        },
    }


def length_extension_demo_endpoint(
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Show that H(k||m) is broken by length-extension; HMAC is not."""
    group = _resolve_group(params, q_bits)
    return {
        "pa_id": PA_ID,
        "result": length_extension_demo(group=group),
    }


def crhf_to_mac_demo_endpoint(
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Forward direction: CRHF -> MAC via HMAC (EUF-CMA game with 50 queries)."""
    group = _resolve_group(params, q_bits)
    return {
        "pa_id": PA_ID,
        "result": crhf_to_mac_demo(group=group),
    }


def mac_to_crhf_demo_endpoint(
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Backward direction: MAC -> CRHF (MD wraps HMAC as compression)."""
    group = _resolve_group(params, q_bits)
    return {
        "pa_id": PA_ID,
        "result": mac_to_crhf_demo(group=group),
    }


def eth_encrypt_endpoint(
    key_e_hex: str,
    key_m_hex: str,
    message: str,
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Encrypt-then-HMAC: CTR-mode encrypt, then HMAC the (nonce || ciphertext)."""
    group = _resolve_group(params, q_bits)
    key_e = bytes.fromhex(key_e_hex)
    key_m = bytes.fromhex(key_m_hex)
    msg_bytes = message.encode("utf-8")
    nonce, ciphertext, tag = eth_enc(
        key_e=key_e, key_m=key_m, message=msg_bytes, group=group,
    )
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "Encrypt-then-HMAC",
            "message": message,
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "tag_hex": tag.hex(),
            "group": {
                "p": group.p, "q": group.q,
                "g": group.g, "h_gen": group.h_gen,
            },
        },
    }


def eth_decrypt_endpoint(
    key_e_hex: str,
    key_m_hex: str,
    nonce_hex: str,
    ciphertext_hex: str,
    tag_hex: str,
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 16,
) -> Dict[str, Any]:
    """Encrypt-then-HMAC decrypt (verify HMAC first; reject on mismatch)."""
    group = _resolve_group(params, q_bits)
    key_e = bytes.fromhex(key_e_hex)
    key_m = bytes.fromhex(key_m_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    plaintext_bytes = eth_dec(
        key_e=key_e, key_m=key_m, nonce=nonce,
        ciphertext=ciphertext, tag=tag, group=group,
    )
    if plaintext_bytes is None:
        return {
            "pa_id": PA_ID,
            "result": {
                "pa_id": PA_ID,
                "algorithm": "Encrypt-then-HMAC-Decrypt",
                "verdict": "REJECT",
                "reason": "HMAC tag verification failed",
                "plaintext": None,
            },
        }
    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext = None
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "Encrypt-then-HMAC-Decrypt",
            "verdict": "ACCEPT",
            "plaintext": plaintext,
            "plaintext_hex": plaintext_bytes.hex(),
        },
    }


def timing_demo_endpoint(
    tag_length: int = 32,
    trials: int = 5000,
) -> Dict[str, Any]:
    """Compare naive vs constant-time tag comparison (timing-leak demo)."""
    return {
        "pa_id": PA_ID,
        "result": timing_comparison_demo(tag_length=tag_length, trials=trials),
    }


def secure_compare_endpoint(a_hex: str, b_hex: str) -> Dict[str, Any]:
    """Constant-time byte-string comparison."""
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "ConstantTimeCompare",
            "a_hex": a.hex(),
            "b_hex": b.hex(),
            "equal": secure_compare(a, b),
        },
    }