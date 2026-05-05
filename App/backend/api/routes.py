"""
Flask API routes for the Minicrypt Clique Explorer.

Endpoints
---------
GET  /api/health                    liveness probe
GET  /api/primitives                list all clique primitives
POST /api/build                     Leg 1: foundation -> source primitive chain
POST /api/reduce                    Leg 2: source -> target reduction chain
"""
from flask import Blueprint, jsonify, request

from crypto.primitives.registry import list_primitives, get as get_primitive
from crypto.primitives.routing import build_chain, reduce_chain

api_bp = Blueprint("api", __name__)


# Deterministic stub hex values so the UI shows something concrete
# while primitives are still unimplemented.
_STUB_INPUT = "a3f24e87b21c49df8e06f14c3a9b2c7d"
_STUB_OUTPUT_CHAIN = [
    "7f3ac19b8f4e22d1a5b3c7d8e9f0a1b2",
    "c19b8f4e22d1a5b37f3ac1b24e87b21c",
    "88d4a572019fbe33c4a7d8e1f2b39c40",
    "4e22d1a5b3c7d8e97f3ac19b8f4e22d1",
]


def _stub_hex(step_index: int) -> str:
    """Deterministic placeholder hex varying per step."""
    return _STUB_OUTPUT_CHAIN[step_index % len(_STUB_OUTPUT_CHAIN)]


@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "stage": "PA#0"})


@api_bp.route("/primitives", methods=["GET"])
def primitives():
    return jsonify({"primitives": list_primitives()})


@api_bp.route("/build", methods=["POST"])
def build():
    """Leg 1: Column 1. Foundation -> Source primitive A."""
    data = request.get_json(silent=True) or {}
    foundation = data.get("foundation", "AES")
    source = data.get("source", "PRG")
    seed_hex = data.get("seed", _STUB_INPUT)

    chain = build_chain(foundation, source)
    # Annotate each step with stub input/output hex
    prev_value = seed_hex
    for i, step in enumerate(chain):
        step["input_hex"] = prev_value
        step["output_hex"] = _stub_hex(i)
        prev_value = step["output_hex"]

    return jsonify({
        "foundation": foundation,
        "source": source,
        "seed": seed_hex,
        "primitive_info": get_primitive(source),
        "chain": chain,
        "final_output": prev_value,
    })


@api_bp.route("/reduce", methods=["POST"])
def reduce():
    """Leg 2: Column 2. Source A -> Target B (abstract reduction)."""
    data = request.get_json(silent=True) or {}
    source = data.get("source", "PRG")
    target = data.get("target", "PRF")
    direction = data.get("direction", "forward")  # "forward" or "backward"
    query_hex = data.get("query", _STUB_INPUT)
    # The output of Column 1 is piped in as the concrete instance of A
    a_instance_hex = data.get("a_instance", _STUB_OUTPUT_CHAIN[0])

    # Swap if backward
    if direction == "backward":
        src, dst = target, source
    else:
        src, dst = source, target

    chain = reduce_chain(src, dst)

    prev_value = query_hex
    for i, step in enumerate(chain):
        step["input_hex"] = prev_value
        step["output_hex"] = _stub_hex(i + 2)  # offset from build chain
        prev_value = step["output_hex"]

    return jsonify({
        "source": source,
        "target": target,
        "direction": direction,
        "query": query_hex,
        "a_instance": a_instance_hex,
        "primitive_info": {
            "source": get_primitive(source),
            "target": get_primitive(target),
        },
        "chain": chain,
        "final_output": prev_value,
    })
