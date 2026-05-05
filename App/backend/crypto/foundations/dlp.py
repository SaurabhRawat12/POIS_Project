"""
DLP Foundation (concrete OWF/OWP) — STUB for PA#0.

DLP: f(x) = g^x mod p in a cyclic group of prime order q.
Will be implemented in PA#1 (OWF) and PA#11 (group parameter generation).
"""
from typing import Dict

# Placeholder — a small-looking hex that resembles a group element
_PLACEHOLDER = "c19b8f4e" * 4


def as_owf(seed_hex: str) -> Dict:
    """DLP-based OWF: f(x) = g^x mod p."""
    return {
        "primitive": "OWF",
        "foundation": "DLP",
        "theorem": "DLP: f(x) = g^x mod p (one-way by DL assumption)",
        "pa_number": 1,
        "implemented": False,
        "input_hex": seed_hex,
        "output_hex": _PLACEHOLDER,
        "note": "Stub — real DLP implementation due PA#1.",
    }


def as_owp(seed_hex: str) -> Dict:
    """DLP is a one-way permutation on Z_q (since g generates order-q subgroup)."""
    return {
        "primitive": "OWP",
        "foundation": "DLP",
        "theorem": "f(x) = g^x mod p is a permutation on Z_q when g generates the subgroup",
        "pa_number": 1,
        "implemented": False,
        "input_hex": seed_hex,
        "output_hex": _PLACEHOLDER,
        "note": "Stub — DLP is a OWP for free once PA#1 is done.",
    }
