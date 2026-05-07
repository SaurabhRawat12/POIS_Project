"""Framework-agnostic API handlers for PA #8 -- DLP-based CRHF."""

from __future__ import annotations

from typing import Any, Dict, Optional

from primitives.pa8_dlp_hash import (
    PA_ID,
    DLPGroup,
    brute_force_collision_finder,
    brute_force_collision_finder_full_hash,
    collision_resistance_argument,
    dlp_compress,
    dlp_hash,
    group_setup,
)


def _build_group(params: Dict[str, int]) -> DLPGroup:
    """Reconstruct a DLPGroup from a serialized params dict.

    Caller is trusted to provide valid (p, q, g, h_gen) where p = 2q+1
    and g, h_gen are in the order-q subgroup. No validation is performed.
    """
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


def group_setup_endpoint(q_bits: int = 32) -> Dict[str, Any]:
    """Generate a fresh DLP group with q of the given bit-length.

    Returns p, q, g, h_gen, hex forms, and byte lengths. The caller can
    pass these back via the `params` field of subsequent endpoints.
    """
    return {
        "pa_id": PA_ID,
        "result": group_setup(q_bits=q_bits),
    }


def compress_endpoint(
    x: int,
    y: int,
    params: Dict[str, int],
) -> Dict[str, Any]:
    """Apply the DLP compression function: h(x, y) = g^x * h_gen^y mod p."""
    group = _build_group(params)
    h_val = dlp_compress(x=x, y=y, group=group)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "DLPCompression",
            "x": x,
            "y": y,
            "compress_value": h_val,
            "compress_hex": hex(h_val),
            "p": group.p,
            "q": group.q,
            "g": group.g,
            "h_gen": group.h_gen,
        },
    }


def hash_endpoint(
    message: str,
    params: Optional[Dict[str, int]] = None,
    q_bits: int = 32,
    out_bits: Optional[int] = None,
) -> Dict[str, Any]:
    """Hash a UTF-8 message via Merkle-Damgard + DLP compression.

    If `params` is None, a fresh group is generated with `q_bits` bits.
    If `out_bits` is given, the digest is truncated to that many bits.
    """
    if params is None:
        group = DLPGroup.generate(q_bits=q_bits)
    else:
        group = _build_group(params)

    msg_bytes = message.encode("utf-8")
    digest = dlp_hash(message=msg_bytes, group=group, out_bits=out_bits)

    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "DLPHash (PA#7 MD + DLP compression)",
            "message": message,
            "message_hex": msg_bytes.hex(),
            "digest_hex": digest.hex(),
            "digest_bytes": len(digest),
            "out_bits": out_bits,
            "group": {
                "p": group.p,
                "q": group.q,
                "g": group.g,
                "h_gen": group.h_gen,
            },
        },
    }


def proof_endpoint() -> Dict[str, Any]:
    """Return the structured collision-resistance proof sketch (no params)."""
    return {
        "pa_id": PA_ID,
        "result": collision_resistance_argument(),
    }


def collision_compress_endpoint(
    q_bits: int = 16,
    params: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Birthday attack on the compression function only.

    Toy q_bits (default 16) so a collision is found in ~2^8 = 256 evaluations.
    """
    group = _build_group(params) if params else None
    return {
        "pa_id": PA_ID,
        "result": brute_force_collision_finder(q_bits=q_bits, group=group),
    }


def collision_hash_endpoint(
    q_bits: int = 16,
    out_bits: int = 16,
    params: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Birthday attack on the full DLPHash, truncated to out_bits."""
    group = _build_group(params) if params else None
    return {
        "pa_id": PA_ID,
        "result": brute_force_collision_finder_full_hash(
            q_bits=q_bits, out_bits=out_bits, group=group
        ),
    }