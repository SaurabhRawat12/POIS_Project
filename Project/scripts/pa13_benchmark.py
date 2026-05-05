"""PA #13 benchmark runner: 512/1024/2048-bit prime generation."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from primitives.pa13_primality import gen_prime


def run_benchmark(
    bit_sizes: List[int], trials: int, k: int, output_dir: Path
) -> Dict[str, Any]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rows: List[Dict[str, Any]] = []

    for bits in bit_sizes:
        attempts: List[int] = []
        elapsed_ms: List[float] = []

        for _ in range(trials):
            result = gen_prime(bits=bits, k=k, require_safe=False)
            attempts.append(int(result["attempts"]))
            elapsed_ms.append(float(result["elapsed_ms"]))

        avg_attempts = statistics.mean(attempts)
        avg_elapsed_ms = statistics.mean(elapsed_ms)
        expected_ln_n = bits * math.log(2.0)  # ln(2^bits)

        row = {
            "bits": bits,
            "trials": trials,
            "k": k,
            "avg_attempts": avg_attempts,
            "min_attempts": min(attempts),
            "max_attempts": max(attempts),
            "expected_ln_2_pow_bits": expected_ln_n,
            "attempts_vs_ln_ratio": avg_attempts / expected_ln_n,
            "avg_elapsed_ms": avg_elapsed_ms,
            "min_elapsed_ms": min(elapsed_ms),
            "max_elapsed_ms": max(elapsed_ms),
        }
        rows.append(row)

    json_path = output_dir / f"pa13_benchmark_{timestamp}.json"
    csv_path = output_dir / f"pa13_benchmark_{timestamp}.csv"

    payload = {
        "generated_at_utc": timestamp,
        "bit_sizes": bit_sizes,
        "trials": trials,
        "k": k,
        "results": rows,
    }

    with json_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    return {
        "status": "ok",
        "json_path": str(json_path),
        "csv_path": str(csv_path),
        "results": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PA #13 prime benchmarks")
    parser.add_argument(
        "--bit-sizes",
        type=str,
        default="512,1024,2048",
        help="Comma-separated bit sizes",
    )
    parser.add_argument("--trials", type=int, default=1, help="Trials per bit size")
    parser.add_argument("--k", type=int, default=40, help="Miller-Rabin rounds")
    parser.add_argument(
        "--output-dir", type=str, default="artifacts", help="Output directory"
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bit_sizes = [int(bits.strip()) for bits in args.bit_sizes.split(",") if bits.strip()]

    result = run_benchmark(bit_sizes=bit_sizes, trials=args.trials, k=args.k, output_dir=output_dir)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
