"""PA #13 Carmichael demo: 561 fools Fermat, caught by Miller-Rabin."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from primitives.pa13_primality import fermat_primality, miller_rabin


def run_demo(bases: List[int], k: int, trace: bool) -> Dict[str, Any]:
    n = 561
    fermat = fermat_primality(n=n, bases=bases)
    mr = miller_rabin(n=n, k=k, trace=trace)
    return {
        "pa_id": "PA#13",
        "demo": "Carmichael-561",
        "n": n,
        "fermat_result": fermat["result"],
        "miller_rabin_result": mr["result"],
        "fermat_details": fermat,
        "miller_rabin_details": mr,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PA #13 Carmichael demo")
    parser.add_argument(
        "--bases",
        nargs="+",
        type=int,
        default=[2, 5, 10, 13, 50],
        help="Fermat test bases",
    )
    parser.add_argument("--k", type=int, default=10, help="Miller-Rabin rounds")
    parser.add_argument("--trace", action="store_true", help="Include MR round trace")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="artifacts",
        help="Directory to write JSON report",
    )
    args = parser.parse_args()

    payload = run_demo(bases=args.bases, k=args.k, trace=args.trace)
    print(json.dumps(payload, indent=2))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"pa13_carmichael_demo_{timestamp}.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"\nSaved report: {output_path}")


if __name__ == "__main__":
    main()
