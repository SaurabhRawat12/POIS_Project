"""Framework-agnostic API handlers for PA #1 -- OWF + PRG.

Wraps the older-style modules primitives/owf.py and primitives/prg.py.
Those modules predate the PA_ID convention, so PA_ID is defined locally.
"""

from __future__ import annotations

from typing import Any, Dict

from primitives.owf import owf_evaluate, owf_verify_hardness
from primitives.prg import PRG, prg_as_owf_hardness, prg_to_owf_demo

PA_ID = "PA#1"


def owf_evaluate_endpoint(
    x: int,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Evaluate the One-Way Function f(x).

    For DLP: f(x) = g^x mod p.
    For AES: not yet implemented (due PA#4).
    """
    if method == "aes":
        return {
            "pa_id": PA_ID,
            "result": {
                "pa_id": PA_ID,
                "algorithm": "OWF-AES",
                "status": "NOT_IMPLEMENTED",
                "due_pa": "PA#4",
            },
        }
    y = owf_evaluate(x=x, method=method, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": f"OWF-{method.upper()}",
            "x": x,
            "y": y,
            "y_hex": hex(y),
            "p": p,
            "g": g,
            "formula": "f(x) = g^x mod p",
        },
    }


def owf_hardness_endpoint(
    method: str = "dlp",
    trials: int = 1000,
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Empirical hardness check: try `trials` random inversions, expect failure.

    Returns SECURE if no inversion found, BROKEN if a collision-style guess hit.
    """
    if method == "aes":
        return {
            "pa_id": PA_ID,
            "result": {
                "pa_id": PA_ID,
                "algorithm": "OWF-AES",
                "status": "NOT_IMPLEMENTED",
                "due_pa": "PA#4",
            },
        }
    msg = owf_verify_hardness(method=method, trials=trials, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": f"OWF-{method.upper()}-HardnessCheck",
            "trials": trials,
            "p": p,
            "g": g,
            "verdict": "SECURE" if str(msg).startswith("SECURE") else "BROKEN",
            "message": msg,
        },
    }


def prg_generate_endpoint(
    seed: int,
    n_bits: int = 64,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Generate n_bits of pseudorandom output from a fresh PRG instance.

    Forward direction: OWF -> PRG via Blum-Micali (hard-core bit construction).
    Each output bit is the LSB of the current state; state advances via OWF.
    """
    prg = PRG()
    prg.seed(seed, method=method, p=p, g=g)
    output = prg.next_bits(n_bits)
    ones = output.count("1")
    zeros = output.count("0")
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": f"PRG-from-OWF ({method.upper()}) via hard-core bit",
            "seed": seed,
            "n_bits": n_bits,
            "output_bits": output,
            "p": p,
            "g": g,
            "stats": {
                "ones": ones,
                "zeros": zeros,
                "ratio_ones": ones / n_bits if n_bits else 0.0,
            },
        },
    }


def prg_to_owf_demo_endpoint(
    seed_val: int = 32415,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Backward direction: PRG -> OWF.

    Define f(s) = G(s); inverting f recovers seed s, breaking PRG security.
    """
    return {
        "pa_id": PA_ID,
        "result": prg_to_owf_demo(seed_val=seed_val, method=method, p=p, g=g),
    }


def prg_as_owf_hardness_endpoint(
    seed_val: int = 32415,
    trials: int = 5000,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Empirical hardness: try to invert G(s) by guessing s. Expect failure."""
    msg = prg_as_owf_hardness(
        seed_val=seed_val, trials=trials, method=method, p=p, g=g,
    )
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "PRG-as-OWF-HardnessCheck",
            "seed_val": seed_val,
            "trials": trials,
            "p": p,
            "g": g,
            "verdict": "SECURE" if str(msg).startswith("SECURE") else "BROKEN",
            "message": msg,
        },
    }