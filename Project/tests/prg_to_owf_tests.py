import math
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from primitives.prg import prg_seed, prg_next_bits


def frequency_test(bit_string):
    n = len(bit_string)
    if n == 0:
        return False, 0.0
    s_n = sum(1 if b == '1' else -1 for b in bit_string)
    s_obs = abs(s_n) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2))
    return p_value >= 0.01, p_value


def runs_test(bit_string):
    n = len(bit_string)
    pi = bit_string.count('1') / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return False, 0.0
    v_n = 1
    for i in range(1, n):
        if bit_string[i] != bit_string[i - 1]:
            v_n += 1
    numerator = abs(v_n - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(numerator / denominator)
    return p_value >= 0.01, p_value


def serial_test(bit_string):
    n = len(bit_string)
    counts = {'00': 0, '01': 0, '10': 0, '11': 0}
    for i in range(n - 1):
        pair = bit_string[i:i + 2]
        counts[pair] += 1
    expected = (n - 1) / 4.0
    chi_square = sum((counts[pair] - expected) ** 2 / expected for pair in counts)
    passed = chi_square <= 11.345
    return passed, chi_square


if __name__ == "__main__":
    prg_seed(12345, method="dlp", p=65537, g=3)
    bits = prg_next_bits(1000)

    print("\nRunning Frequency Test:")
    passed, p_val = frequency_test(bits)
    print(f"Passed: {passed}, p-value: {p_val}")

    print("\nRunning Runs Test:")
    passed, p_val = runs_test(bits)
    print(f"Passed: {passed}, p-value: {p_val}")

    print("\nRunning Serial Test:")
    passed, chi_sq = serial_test(bits)
    print(f"Passed: {passed}, chi-square: {chi_sq}")