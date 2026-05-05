import os
import random

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def owf_dlp(x, p, g):
    if p is None or g is None:
        raise ValueError("DLP method requires prime 'p' and generator 'g'.")
    return mod_exp(g, x, p)

def owf_aes(k):
    raise NotImplementedError("AES OWF path not yet implemented (Due PA#4).")

def owf_evaluate(x, method="dlp", **kwargs):
    if method == "dlp":
        p = kwargs.get("p")
        g = kwargs.get("g")
        return owf_dlp(x, p, g)
    elif method == "aes":
        return owf_aes(x)
    else:
        raise ValueError(f"Unknown OWF method: {method}")

def owf_verify_hardness(method="dlp", trials=1000, **kwargs):
    if method == "dlp":
        p = kwargs.get("p", 65537)
        g = kwargs.get("g", 3)

        target_x = random.randint(2, p - 2)
        target_y = owf_dlp(target_x, p, g)

        print(f"Target y = {target_y}. Attempting {trials} random guesses...")

        for i in range(trials):
            guess_x = random.randint(2, p - 2)
            guess_y = owf_dlp(guess_x, p, g)
            if guess_y == target_y:
                return f"BROKEN! Inverse found in {i} trials: x={guess_x}"

        return f"SECURE. Failed to invert after {trials} random trials."

    elif method == "aes":
        return owf_aes(0)

def main():
    print("Testing DLP-based OWF hardness...")
    result = owf_verify_hardness(method="dlp", trials=10000)
    print(result)

if __name__ == "__main__":
    main()