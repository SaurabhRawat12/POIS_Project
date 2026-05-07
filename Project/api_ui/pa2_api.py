"""Framework-agnostic API handlers for PA #2 -- PRF via GGM tree."""

from __future__ import annotations

from typing import Any, Dict

from primitives.prf import (
    ggm_trace,
    prf_distinguish_game,
    prf_distinguishing_experiment,
    prf_eval,
    prf_to_prg,
)

PA_ID = "PA#2"


def _aes_stub() -> Dict[str, Any]:
    """Shared AES-not-implemented response for any PRF endpoint."""
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "PRF-AES",
            "status": "NOT_IMPLEMENTED",
            "due_pa": "PA#4",
        },
    }


def prf_eval_endpoint(
    k: str,
    x: str,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Evaluate the GGM PRF F_k(x).

    Both k and x are binary strings of equal length n. Returns the n-bit
    leaf value at the root-to-leaf path defined by the bits of x.
    """
    if method == "aes":
        return _aes_stub()
    output = prf_eval(k=k, x=x, method=method, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": f"PRF-GGM-{method.upper()}",
            "key": k,
            "input": x,
            "output": output,
            "n_bits": len(k),
            "p": p,
            "g": g,
        },
    }


def prf_trace_endpoint(
    k: str,
    x: str,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Return the full GGM tree trace (root to leaf) for query x."""
    if method == "aes":
        return _aes_stub()
    trace_result = ggm_trace(k=k, x=x, method=method, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "GGM-Trace",
            "key": k,
            "input": x,
            "n_bits": len(k),
            "p": p,
            "g": g,
            **trace_result,
        },
    }


def prf_to_prg_endpoint(
    s: str,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Backward direction: PRF -> PRG via G(s) = F_s(0^n) || F_s(1^n)."""
    if method == "aes":
        return _aes_stub()
    output = prf_to_prg(s=s, method=method, p=p, g=g)
    return {
        "pa_id": PA_ID,
        "result": {
            "pa_id": PA_ID,
            "algorithm": "PRG-from-PRF",
            "seed": s,
            "n_bits_in": len(s),
            "n_bits_out": len(output),
            "output": output,
            "p": p,
            "g": g,
            "construction": "G(s) = F_s(0^n) || F_s(1^n)",
        },
    }


def prf_distinguish_game_endpoint(
    k: str,
    q: int = 100,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Single round of the PRF distinguishing game.

    Challenger picks PRF or random oracle by coin flip; adversary sees
    q (input, output) pairs and must guess which source was used.
    """
    if method == "aes":
        return _aes_stub()
    return {
        "pa_id": PA_ID,
        "result": prf_distinguish_game(k=k, q=q, method=method, p=p, g=g),
    }


def prf_distinguish_experiment_endpoint(
    k: str,
    rounds: int = 100,
    q: int = 100,
    method: str = "dlp",
    p: int = 65537,
    g: int = 3,
) -> Dict[str, Any]:
    """Multi-round experiment with a dummy 50/50 adversary.

    Empirical advantage should converge to ~0 in secure PRF mode.
    """
    if method == "aes":
        return _aes_stub()
    return {
        "pa_id": PA_ID,
        "result": prf_distinguishing_experiment(
            k=k, rounds=rounds, q=q, method=method, p=p, g=g,
        ),
    }