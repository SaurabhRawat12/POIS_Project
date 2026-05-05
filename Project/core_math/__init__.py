"""Core math subsystem (shared low-level building blocks)."""

from .number_theory import decompose, egcd, mod_inverse, modexp
from .randomness import sample_odd_candidate, system_rng

__all__ = [
    "modexp",
    "egcd",
    "mod_inverse",
    "decompose",
    "system_rng",
    "sample_odd_candidate",
]

