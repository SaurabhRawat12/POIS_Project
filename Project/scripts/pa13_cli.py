"""Canonical CLI for PA #13 utilities (subsystem-first layout)."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api_ui.pa13_api import primality_check_endpoint
from primitives.pa13_primality import fermat_primality, gen_prime, gen_safe_prime


def _dump(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _cmd_check(args: argparse.Namespace) -> None:
    payload = primality_check_endpoint(n=args.n, k=args.k, trace=args.trace)
    _dump(payload)


def _cmd_generate(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed) if args.seed is not None else None
    if args.safe:
        result = gen_safe_prime(q_bits=args.bits - 1, k=args.k, rng=rng)
    else:
        result = gen_prime(bits=args.bits, k=args.k, rng=rng)
    _dump(result)


def _cmd_carmichael(args: argparse.Namespace) -> None:
    n = 561
    bases = tuple(args.bases)
    fermat = fermat_primality(n=n, bases=bases)
    mr = primality_check_endpoint(n=n, k=args.k, trace=args.trace)
    payload = {
        "n": n,
        "fermat": fermat,
        "miller_rabin": mr,
    }
    _dump(payload)


def _cmd_benchmark(args: argparse.Namespace) -> None:
    from scripts.pa13_benchmark import run_benchmark

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bit_sizes = [int(bits.strip()) for bits in args.bit_sizes.split(",") if bits.strip()]
    results = run_benchmark(
        bit_sizes=bit_sizes,
        trials=args.trials,
        k=args.k,
        output_dir=output_dir,
    )
    _dump(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PA #13 tools")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="Run Miller-Rabin check")
    check_parser.add_argument("--n", type=int, required=True, help="Integer to test")
    check_parser.add_argument("--k", type=int, default=40, help="MR rounds")
    check_parser.add_argument("--trace", action="store_true", help="Include round trace")
    check_parser.set_defaults(func=_cmd_check)

    gen_parser = subparsers.add_parser("generate", help="Generate a prime")
    gen_parser.add_argument("--bits", type=int, required=True, help="Prime bit length")
    gen_parser.add_argument("--k", type=int, default=40, help="MR rounds")
    gen_parser.add_argument("--safe", action="store_true", help="Generate safe prime")
    gen_parser.add_argument(
        "--seed", type=int, default=None, help="Optional deterministic seed"
    )
    gen_parser.set_defaults(func=_cmd_generate)

    carm_parser = subparsers.add_parser("carmichael", help="Carmichael 561 demo")
    carm_parser.add_argument("--k", type=int, default=10, help="MR rounds")
    carm_parser.add_argument(
        "--bases",
        nargs="+",
        type=int,
        default=[2, 5, 10, 13, 50],
        help="Fermat bases",
    )
    carm_parser.add_argument("--trace", action="store_true", help="Include MR trace")
    carm_parser.set_defaults(func=_cmd_carmichael)

    bench_parser = subparsers.add_parser("benchmark", help="Run benchmark and export")
    bench_parser.add_argument(
        "--bit-sizes",
        type=str,
        default="512,1024,2048",
        help="Comma-separated bit sizes",
    )
    bench_parser.add_argument("--trials", type=int, default=1, help="Trials per bit size")
    bench_parser.add_argument("--k", type=int, default=40, help="MR rounds")
    bench_parser.add_argument(
        "--output-dir", type=str, default="artifacts", help="Output directory"
    )
    bench_parser.set_defaults(func=_cmd_benchmark)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

