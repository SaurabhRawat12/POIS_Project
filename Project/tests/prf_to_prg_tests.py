import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from primitives.prf import prf_to_prg
from testing.randomness_tests import frequency_test, runs_test, serial_test


def collect_prf_to_prg_bits(seed, samples=250, method="dlp", **kwargs):
    bits = []
    seed_int = int(seed, 2)
    width = len(seed)

    for offset in range(samples):
        current_seed = bin((seed_int + offset) % (2**width))[2:].zfill(width)
        bits.append(prf_to_prg(current_seed, method=method, **kwargs))

    return "".join(bits)


def run_prf_to_prg_statistical_tests(seed="1010101111001101", samples=64, method="dlp", **kwargs):
    bit_string = collect_prf_to_prg_bits(seed, samples=samples, method=method, **kwargs)

    frequency_passed, frequency_p = frequency_test(bit_string)
    runs_passed, runs_p = runs_test(bit_string)
    serial_passed, serial_chi_square = serial_test(bit_string)

    return {
        "source": "PRF-to-PRG G(s)=F_s(0^n)||F_s(1^n)",
        "seed": seed,
        "samples": samples,
        "total_bits": len(bit_string),
        "frequency": {"passed": frequency_passed, "p_value": frequency_p},
        "runs": {"passed": runs_passed, "p_value": runs_p},
        "serial": {"passed": serial_passed, "chi_square": serial_chi_square},
    }


if __name__ == "__main__":
    results = run_prf_to_prg_statistical_tests(p=65537, g=3)
    print(f"Testing {results['source']}")
    print(f"Total bits: {results['total_bits']}")
    print(
        "Frequency Test: "
        f"Passed={results['frequency']['passed']}, "
        f"p-value={results['frequency']['p_value']}"
    )
    print(
        "Runs Test: "
        f"Passed={results['runs']['passed']}, "
        f"p-value={results['runs']['p_value']}"
    )
    print(
        "Serial Test: "
        f"Passed={results['serial']['passed']}, "
        f"chi-square={results['serial']['chi_square']}"
    )
