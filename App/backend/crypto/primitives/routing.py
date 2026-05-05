"""
Routing Table — the reduction graph of the Minicrypt Clique.

Every edge (A -> B) carries:
  - theorem name        (e.g., "GGM tree construction")
  - pa_number           (which PA implements this construction)
  - security_claim      (one-line proof sketch)

Column 1 (Build):  Foundation -> Source primitive A.
Column 2 (Reduce): Source A    -> Target primitive B.

For any (A, B) pair the API returns the shortest path through the graph.
"""
from collections import deque
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Edge definitions. Each directed edge is:
#   (src, dst) -> { theorem, pa_number, security_claim }
# ---------------------------------------------------------------------------

REDUCTION_EDGES: Dict[Tuple[str, str], Dict] = {
    # --- OWF <-> PRG ---
    ("OWF", "PRG"): {
        "theorem": "HILL / Goldreich-Levin hard-core-bit construction",
        "pa_number": 1,
        "security_claim": "If f is a OWF with hard-core predicate b, G(x) = b(x)||b(f(x))||... is a PRG.",
    },
    ("PRG", "OWF"): {
        "theorem": "PRG is immediately a OWF",
        "pa_number": 1,
        "security_claim": "Inverting f(s) = G(s) would recover the seed and break PRG security.",
    },

    # --- OWF <-> OWP ---
    ("OWF", "OWP"): {
        "theorem": "DLP instantiation: g^x mod p is already a OWP on Z_q",
        "pa_number": 1,
        "security_claim": "Any OWF on a domain with samplable preimages can be made a OWP (DLP trivially).",
    },
    ("OWP", "OWF"): {
        "theorem": "A OWP is a special case of a OWF (trivial)",
        "pa_number": 1,
        "security_claim": "Bijective + hard to invert ⇒ hard to invert.",
    },

    # --- OWP <-> PRG (direct) ---
    ("OWP", "PRG"): {
        "theorem": "OWP + hard-core bit: G(x) = (f(x), b(x))",
        "pa_number": 1,
        "security_claim": "Expands by one bit per application; distinguishing breaks hardcore predicate.",
    },

    # --- PRG <-> PRF ---
    ("PRG", "PRF"): {
        "theorem": "GGM tree construction",
        "pa_number": 2,
        "security_claim": "F_k(b1..bn) = G_{bn}(...G_{b1}(k)); n PRG calls per evaluation.",
    },
    ("PRF", "PRG"): {
        "theorem": "Length-doubling PRG from PRF: G(s) = F_s(0)||F_s(1)",
        "pa_number": 2,
        "security_claim": "A distinguisher on G gives a distinguisher on F.",
    },

    # --- PRF <-> PRP ---
    ("PRF", "PRP"): {
        "theorem": "Luby-Rackoff 3-round Feistel",
        "pa_number": 4,
        "security_claim": "3 rounds ⇒ PRP; 4 rounds ⇒ strong PRP.",
    },
    ("PRP", "PRF"): {
        "theorem": "PRF/PRP switching lemma",
        "pa_number": 2,
        "security_claim": "On super-polynomial domains, PRP ≈ PRF with negligible advantage.",
    },

    # --- PRF <-> MAC ---
    ("PRF", "MAC"): {
        "theorem": "PRF-MAC: Mac_k(m) = F_k(m)",
        "pa_number": 5,
        "security_claim": "A forgery distinguishes F from a random function, breaking PRF.",
    },
    ("MAC", "PRF"): {
        "theorem": "Secure MAC on random inputs is a PRF",
        "pa_number": 5,
        "security_claim": "Unforgeability on random messages implies pseudorandom outputs.",
    },

    # --- CRHF <-> HMAC ---
    ("CRHF", "HMAC"): {
        "theorem": "HMAC construction: HMAC_k(m) = H((k⊕opad) || H((k⊕ipad) || m))",
        "pa_number": 10,
        "security_claim": "Secure when the compression function is a PRF (not just collision-resistant).",
    },
    ("HMAC", "CRHF"): {
        "theorem": "Fix key k: H'(m) = HMAC_k(m) is collision-resistant",
        "pa_number": 10,
        "security_claim": "Any collision would constitute a MAC forgery.",
    },

    # --- HMAC <-> MAC ---
    ("HMAC", "MAC"): {
        "theorem": "HMAC is a secure EUF-CMA MAC (PA#10 directly constructs this)",
        "pa_number": 10,
        "security_claim": "Direct: HMAC satisfies the MAC correctness and unforgeability properties.",
    },
    ("MAC", "HMAC"): {
        "theorem": "Any PRF-based MAC can be recast in the HMAC double-hash structure",
        "pa_number": 10,
        "security_claim": "Inner compression = MAC; outer hash provides length-extension resistance.",
    },

    # --- CRHF <-> MAC (via HMAC, but also direct MD-based) ---
    ("MAC", "CRHF"): {
        "theorem": "MAC as MD compression function",
        "pa_number": 10,
        "security_claim": "Apply Merkle-Damgård with the MAC as h; a collision = a MAC forgery.",
    },
}


# Build adjacency for BFS
def _neighbors(node: str) -> List[str]:
    return [b for (a, b) in REDUCTION_EDGES.keys() if a == node]


def shortest_path(src: str, dst: str) -> Optional[List[str]]:
    """BFS for shortest reduction path from src to dst through the clique."""
    if src == dst:
        return [src]
    visited = {src}
    queue = deque([[src]])
    while queue:
        path = queue.popleft()
        tail = path[-1]
        for nxt in _neighbors(tail):
            if nxt in visited:
                continue
            new_path = path + [nxt]
            if nxt == dst:
                return new_path
            visited.add(nxt)
            queue.append(new_path)
    return None


def path_to_steps(path: List[str]) -> List[Dict]:
    """Convert a node path into an ordered list of edge-step dicts."""
    steps = []
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        edge = REDUCTION_EDGES.get((a, b))
        if not edge:
            steps.append({
                "from": a, "to": b,
                "theorem": f"No direct reduction {a} → {b}",
                "pa_number": None,
                "security_claim": "",
                "implemented": False,
            })
            continue
        steps.append({
            "from": a,
            "to": b,
            "theorem": edge["theorem"],
            "pa_number": edge["pa_number"],
            "security_claim": edge["security_claim"],
            "implemented": False,  # nothing is implemented at PA#0
        })
    return steps


# ---------------------------------------------------------------------------
# Leg 1: Foundation -> Source primitive
# ---------------------------------------------------------------------------

# What primitive each foundation natively provides
FOUNDATION_ENTRY = {
    "AES": "PRP",   # AES is natively a PRP
    "DLP": "OWF",   # DLP is natively a OWF (also a OWP)
}


def build_chain(foundation: str, target: str) -> List[Dict]:
    """Leg 1: build the chain from concrete foundation to source primitive A."""
    entry = FOUNDATION_ENTRY.get(foundation)
    if entry is None:
        return [{
            "from": foundation, "to": target,
            "theorem": f"Unknown foundation: {foundation}",
            "pa_number": None, "security_claim": "", "implemented": False,
        }]
    path = shortest_path(entry, target)
    if path is None:
        return [{
            "from": entry, "to": target,
            "theorem": f"No path from {foundation} foundation ({entry}) to {target}",
            "pa_number": None, "security_claim": "",
            "implemented": False,
        }]
    # Prepend the foundation → entry step
    foundation_step = {
        "from": foundation,
        "to": entry,
        "theorem": f"{foundation} is natively a {entry}",
        "pa_number": 1 if foundation == "DLP" else 2,
        "security_claim": f"Direct instantiation of {entry} from the {foundation} foundation.",
        "implemented": False,
    }
    return [foundation_step] + path_to_steps(path)


def reduce_chain(source: str, target: str) -> List[Dict]:
    """Leg 2: the abstract reduction A → B (Column 2)."""
    if source == target:
        return [{
            "from": source, "to": target,
            "theorem": "Identity (A = B)",
            "pa_number": None, "security_claim": "Trivial.",
            "implemented": True,
        }]
    path = shortest_path(source, target)
    if path is None:
        return [{
            "from": source, "to": target,
            "theorem": f"No reduction path {source} → {target} in this direction",
            "pa_number": None,
            "security_claim": "Try the bidirectional toggle — the reverse direction may exist.",
            "implemented": False,
        }]
    return path_to_steps(path)
