"""
Primitive Registry — single source of truth for the Minicrypt Clique.

Each primitive carries:
  - short name (what the UI displays)
  - full name
  - PA number where it is implemented
  - whether it is implemented yet (always False at PA#0)
  - brief description
"""
from typing import Dict, List

PRIMITIVES: Dict[str, Dict] = {
    "OWF": {
        "name": "OWF",
        "full_name": "One-Way Function",
        "pa_number": 1,
        "implemented": False,
        "description": "Easy to compute, hard to invert. The seed of all Minicrypt.",
    },
    "PRG": {
        "name": "PRG",
        "full_name": "Pseudorandom Generator",
        "pa_number": 1,
        "implemented": False,
        "description": "Stretches a short seed into a computationally-random stream.",
    },
    "PRF": {
        "name": "PRF",
        "full_name": "Pseudorandom Function",
        "pa_number": 2,
        "implemented": False,
        "description": "Keyed function indistinguishable from a random oracle.",
    },
    "PRP": {
        "name": "PRP",
        "full_name": "Pseudorandom Permutation",
        "pa_number": 4,
        "implemented": False,
        "description": "A PRF that is also a bijection — a secure block cipher.",
    },
    "OWP": {
        "name": "OWP",
        "full_name": "One-Way Permutation",
        "pa_number": 1,
        "implemented": False,
        "description": "A OWF that is also a bijection. DLP is the canonical example.",
    },
    "MAC": {
        "name": "MAC",
        "full_name": "Message Authentication Code",
        "pa_number": 5,
        "implemented": False,
        "description": "Symmetric-key integrity tag. EUF-CMA secure.",
    },
    "CRHF": {
        "name": "CRHF",
        "full_name": "Collision-Resistant Hash",
        "pa_number": 8,
        "implemented": False,
        "description": "Compresses arbitrary input; collisions are hard to find.",
    },
    "HMAC": {
        "name": "HMAC",
        "full_name": "Hash-based MAC",
        "pa_number": 10,
        "implemented": False,
        "description": "The bridge that connects CRHF to MAC in the clique.",
    },
}


def list_primitives() -> List[Dict]:
    """Return registry as a list (for the frontend dropdowns)."""
    return list(PRIMITIVES.values())


def get(name: str) -> Dict:
    return PRIMITIVES.get(name, {
        "name": name,
        "full_name": name,
        "pa_number": None,
        "implemented": False,
        "description": "Unknown primitive.",
    })
