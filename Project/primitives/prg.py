import random

try:
    from primitives.owf import owf_evaluate
except ImportError:
    from owf import owf_evaluate


class PRG:
    def __init__(self):
        self._state = None
        self._method = "dlp"
        self._kwargs = {}

    def seed(self, s, method="dlp", **kwargs):
        self._state = s
        self._method = method
        self._kwargs = kwargs

    def next_bits(self, n):
        if self._state is None:
            raise ValueError("PRG must be seeded before calling next_bits")
        output_bits = []
        for _ in range(n):
            # Blum-Micali style extraction: output one hard-core predicate bit,
            # then advance the state with the OWF.
            bit = self._state & 1
            output_bits.append(str(bit))
            self._state = owf_evaluate(self._state, method=self._method, **self._kwargs)
        return "".join(output_bits)
    
_prg_instance = PRG()

def prg_seed(s, method="dlp", **kwargs):
    _prg_instance.seed(s, method=method, **kwargs)

def prg_next_bits(n):
    return _prg_instance.next_bits(n)

def prg_to_owf_demo(seed_val=32415, method="dlp", **kwargs):
    kwargs.setdefault("p", 65537)
    kwargs.setdefault("g", 3)

    demo_prg = PRG()
    demo_prg.seed(seed_val, method=method, **kwargs)
    pseudorandom_output = demo_prg.next_bits(64)

    return {
        "original_seed": seed_val,
        "prg_output": pseudorandom_output,
        "security_claim": (
            "Backward reduction: define f(s)=G(s). If an efficient adversary can invert "
            "f and recover s from G(s), then it also breaks PRG security because G(s) "
            "is no longer indistinguishable from random hidden-seed output."
        )
    }


def prg_as_owf_hardness(seed_val, trials=5000, method="dlp", **kwargs):
    kwargs.setdefault("p", 65537)
    kwargs.setdefault("g", 3)

    target_prg = PRG()
    target_prg.seed(seed_val, method=method, **kwargs)
    target_output = target_prg.next_bits(64)

    print(f"Target PRG output: {target_output}")
    print(f"Attempting {trials} random seed guesses...")

    p = kwargs["p"]
    for i in range(trials):
        guess = random.randint(2, p - 2)
        guess_prg = PRG()
        guess_prg.seed(guess, method=method, **kwargs)
        if guess_prg.next_bits(64) == target_output:
            return f"BROKEN: seed recovered in {i} trials: seed={guess}"

    return f"SECURE: seed not recovered after {trials} trials."


if __name__ == "__main__":
    demo_result = prg_to_owf_demo()
    print(demo_result)

    hardness_result = prg_as_owf_hardness(32415)
    print(hardness_result)
