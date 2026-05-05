"""
AES Foundation (concrete PRP/PRF) — STUB for PA#0.

Will be implemented in PA#2. For now exposes the same interface shape
(asOWF, asPRF, asPRP) so the scaffold can route to it, returning
placeholder hex values with implemented=False.
"""
from typing import Dict

# Fixed placeholder hex so the UI has something concrete to display
# without any real computation. Replaced when PA#2 lands.
_PLACEHOLDER = "7f3ac19b" * 4  # 32 hex chars = 128-bit AES block


def as_owf(seed_hex: str) -> Dict:
    """AES-based OWF: f(k) = AES_k(0^128) XOR k. Stubbed."""
    return {
        "primitive": "OWF",
        "foundation": "AES",
        "theorem": "AES-based OWF: f(k) = AES_k(0^128) XOR k",
        "pa_number": 1,
        "implemented": False,
        "input_hex": seed_hex,
        "output_hex": _PLACEHOLDER,
        "note": "Stub — real implementation due PA#1 (AES variant) or PA#2 (AES itself).",
    }


def as_prf(key_hex: str, input_hex: str) -> Dict:
    """AES as a PRF: F_k(x) = AES_k(x)."""
    return {
        "primitive": "PRF",
        "foundation": "AES",
        "theorem": "AES as PRF (switching lemma: PRP → PRF)",
        "pa_number": 2,
        "implemented": False,
        "input_hex": input_hex,
        "output_hex": _PLACEHOLDER,
        "note": "Stub — real AES implementation due PA#2.",
    }


def as_prp(key_hex: str, input_hex: str) -> Dict:
    """AES directly as a PRP."""
    return {
        "primitive": "PRP",
        "foundation": "AES",
        "theorem": "AES-128 is a concrete PRP",
        "pa_number": 4,
        "implemented": False,
        "input_hex": input_hex,
        "output_hex": _PLACEHOLDER,
        "note": "Stub — real AES implementation due PA#2/#4.",
    }
