from primitives.prg import PRG
import os
import random

def _validate_binary_string(name, value):
    if not value:
        raise ValueError(f"{name} must be a non-empty binary string.")
    if any(bit not in "01" for bit in value):
        raise ValueError(f"{name} must be a binary string (0s and 1s).")

def _validate_prf_inputs(k, x):
    _validate_binary_string("Key k", k)
    _validate_binary_string("Input x", x)
    if len(k) != len(x):
        raise ValueError("GGM PRF requires len(x) == len(k), with x in {0,1}^n.")

def _random_bits(n):
    return bin(int.from_bytes(os.urandom(max(1, (n + 7) // 8)), "big"))[2:].zfill(n)[-n:]

def _random_function_oracle(n):
    table = {}

    def oracle(x):
        if x not in table:
            table[x] = _random_bits(n)
        return table[x]

    return oracle

def prf_eval(k, x, method="dlp", **kwargs):
    if method == "aes":
        raise NotImplementedError("AES PRF path bypassed GGM tree but is not yet implemented (Due PA#4).")

    _validate_prf_inputs(k, x)
    n = len(k)
    state = k
    
    for bit in x:
        prg = PRG()
        prg.seed(int(state, 2), method=method, **kwargs) #int(state, 2) converts the binary string state to an decimal integer.
        expanded_bits = prg.next_bits(2 * n)
        
        left_half = expanded_bits[:n]
        right_half = expanded_bits[n:]
        
        if bit == '0':
            state = left_half
        elif bit == '1':
            state = right_half
    return state

def prf_to_prg(s, method="dlp", **kwargs):
    _validate_binary_string("Seed s", s)
    n = len(s)
    
    input_0 = "0" * n
    input_1 = "1" * n
    
    left_expansion = prf_eval(k=s, x=input_0, method=method, **kwargs)
    right_expansion = prf_eval(k=s, x=input_1, method=method, **kwargs)
    
    return left_expansion + right_expansion

def ggm_trace(k, x, method="dlp", **kwargs):
    _validate_prf_inputs(k, x)
    n = len(k)
    state = k
    trace_log = [{"level": 0, "path_taken": "root", "value": state}]
    
    for i, bit in enumerate(x):
        prg = PRG()
        prg.seed(int(state, 2), method=method, **kwargs)
        expanded_bits = prg.next_bits(2 * n)

        left_half = expanded_bits[:n]
        right_half = expanded_bits[n:]
        
        if bit == '0':
            state = left_half
        else:
            state = right_half
            
        trace_log.append({
            "level": i + 1,
            "bit_read": bit,
            "left_node": left_half,
            "right_node": right_half,
            "chosen_state": state
        })
        
    return {"final_output": state, "trace": trace_log}

def prf_distinguish_game(k, q=100, method="dlp", **kwargs):
    _validate_binary_string("Key k", k)
    n = len(k)

    secret_bit = random.choice([0, 1])
    random_oracle = _random_function_oracle(n)
    
    outputs = []
    for _ in range(q):
        x = _random_bits(n)
        
        if secret_bit == 0:
            out = random_oracle(x)
        else:
            out = prf_eval(k, x, method=method, **kwargs)
            
        outputs.append((x, out))

    ones = sum(out.count("1") for _, out in outputs)
    total_bits = q * n
        
    return {
        "queries": outputs,
        "true_source": "PRF" if secret_bit == 1 else "Random Oracle",
        "q": q,
        "output_one_ratio": ones / total_bits if total_bits else 0.0,
        "unique_outputs": len({out for _, out in outputs}),
        "message": "Challenge complete. Can the adversary guess the source?"
    }

def prf_distinguishing_experiment(k, rounds=100, q=100, method="dlp", **kwargs):
    _validate_binary_string("Key k", k)
    correct = 0

    for _ in range(rounds):
        game = prf_distinguish_game(k, q=q, method=method, **kwargs)
        dummy_guess = random.choice(["PRF", "Random Oracle"])
        if dummy_guess == game["true_source"]:
            correct += 1

    success_rate = correct / rounds if rounds else 0.0
    advantage = abs(success_rate - 0.5)
    return {
        "rounds": rounds,
        "queries_per_round": q,
        "dummy_adversary_success_rate": success_rate,
        "empirical_advantage": advantage,
        "security_claim": "A dummy adversary should stay near 50% success, so advantage should be close to 0."
    }

def main():
    print("=== Testing PA#2: PRF via GGM Tree ===")
    
    toy_p = 65537 
    toy_g = 3
    
    test_key = "1011"  
    test_query = "0101" 

    print(f"\n--- Evaluating PRF ---")
    print(f"Key: {test_key} | Query: {test_query}")
    try:
        result = prf_eval(k=test_key, x=test_query, method="dlp", p=toy_p, g=toy_g)
        print(f"Final Leaf Node (Output): {result}")
    except Exception as e:
        print(f"Error in prf_eval: {e}")

    print("\n--- GGM Tree Trace ---")
    try:
        trace_result = ggm_trace(k=test_key, x=test_query, method="dlp", p=toy_p, g=toy_g)
        for step in trace_result["trace"]:
            print(f"Level {step['level']}: {step}")
    except Exception as e:
         print(f"Error in ggm_trace: {e}")

    print("\n--- PRF Distinguishing Game (100 Queries) ---")
    try:
        game_result = prf_distinguish_game(k=test_key, q=100, method="dlp", p=toy_p, g=toy_g)
        print(f"Secret Box was actually: {game_result['true_source']}")
        print(f"Output one ratio: {game_result['output_one_ratio']:.3f}")
        print("Sample Outputs:")
        for query, output in game_result["queries"][:3]:
            print(f"  Input: {query} -> Output: {output}")

        experiment = prf_distinguishing_experiment(k=test_key, rounds=100, q=100, method="dlp", p=toy_p, g=toy_g)
        print(f"Dummy adversary success: {experiment['dummy_adversary_success_rate']:.3f}")
        print(f"Empirical advantage: {experiment['empirical_advantage']:.3f}")
    except Exception as e:
         print(f"Error in distinguishing game: {e}")

if __name__ == "__main__":
    main()
