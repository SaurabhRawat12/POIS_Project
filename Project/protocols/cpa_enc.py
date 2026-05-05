import os
import random

from primitives.prf import prf_eval

def _validate_binary_string(name, value):
    if not value:
        raise ValueError(f"{name} must be a non-empty binary string.")
    if any(bit not in "01" for bit in value):
        raise ValueError(f"{name} must be a binary string (0s and 1s).")

def _xor_bits(bit_str_1, bit_str_2):
    length = max(len(bit_str_1), len(bit_str_2))
    val_1 = int(bit_str_1, 2) if bit_str_1 else 0
    val_2 = int(bit_str_2, 2) if bit_str_2 else 0
    return bin(val_1 ^ val_2)[2:].zfill(length)

def _random_bits(n):
    return bin(int.from_bytes(os.urandom(max(1, (n + 7) // 8)), "big"))[2:].zfill(n)[-n:]

def _cpa_enc_with_r(k, m, r, method="dlp", **kwargs):
    _validate_binary_string("Key k", k)
    _validate_binary_string("Message m", m)
    _validate_binary_string("Nonce r", r)
    n = len(k)
    if len(r) != n:
        raise ValueError("Nonce r must have the same length as key k.")
    
    ciphertext_blocks = []
    r_int = int(r, 2)
    
    for i in range(0, len(m), n):
        m_block = m[i:i+n]
        actual_block_length = len(m_block)
        current_r = bin((r_int + (i // n)) % (2**n))[2:].zfill(n)
        mask = prf_eval(k=k, x=current_r, method=method, **kwargs)
        mask = mask[:actual_block_length]
        
        c_block = _xor_bits(m_block, mask)
        ciphertext_blocks.append(c_block)
        
    return r, "".join(ciphertext_blocks)

def cpa_enc(k, m, method="dlp", **kwargs):
    n = len(k)
    return _cpa_enc_with_r(k, m, _random_bits(n), method=method, **kwargs)

def cpa_dec(k, r, c, method="dlp", **kwargs):
    _validate_binary_string("Key k", k)
    _validate_binary_string("Nonce r", r)
    _validate_binary_string("Ciphertext c", c)
    n = len(k)
    if len(r) != n:
        raise ValueError("Nonce r must have the same length as key k.")
    plaintext_blocks = []
    r_int = int(r, 2)
    
    for i in range(0, len(c), n):
        c_block = c[i:i+n]
        actual_block_length = len(c_block)
        
        current_r = bin((r_int + (i // n)) % (2**n))[2:].zfill(n)
        
        mask = prf_eval(k=k, x=current_r, method=method, **kwargs)
        mask = mask[:actual_block_length]
        
        m_block = _xor_bits(c_block, mask)
        plaintext_blocks.append(m_block)
        
    return "".join(plaintext_blocks)

def ind_cpa_game(k, m0, m1, reuse_nonce=False, method="dlp", **kwargs):
    if len(m0) != len(m1):
        raise ValueError("IND-CPA game requires m0 and m1 to be the exact same length.")
    _validate_binary_string("m0", m0)
    _validate_binary_string("m1", m1)
        
    b = random.choice([0, 1])
    target_m = m1 if b == 1 else m0
    
    if reuse_nonce:
        n = len(k)
        static_r = "0" * n
        r, c = _cpa_enc_with_r(k, target_m, static_r, method=method, **kwargs)
    else:
        r, c = cpa_enc(k, target_m, method=method, **kwargs)
        
    return {
        "challenge_r": r,
        "challenge_c": c,
        "secret_bit": b,
        "message": f"I have encrypted m{b}. Can you guess which one it is?"
    }

def _encryption_oracle(k, reuse_nonce=False, method="dlp", **kwargs):
    static_r = "0" * len(k)

    def oracle(message):
        if reuse_nonce:
            return _cpa_enc_with_r(k, message, static_r, method=method, **kwargs)
        return cpa_enc(k, message, method=method, **kwargs)

    return oracle

def ind_cpa_dummy_adversary_experiment(
    k,
    m0,
    m1,
    rounds=100,
    oracle_queries=50,
    method="dlp",
    **kwargs
):
    if len(m0) != len(m1):
        raise ValueError("IND-CPA game requires m0 and m1 to be the exact same length.")

    correct = 0
    for _ in range(rounds):
        oracle = _encryption_oracle(k, reuse_nonce=False, method=method, **kwargs)
        for _ in range(oracle_queries):
            oracle(random.choice([m0, m1]))

        challenge = ind_cpa_game(k, m0, m1, reuse_nonce=False, method=method, **kwargs)
        guess = random.choice([0, 1])
        if guess == challenge["secret_bit"]:
            correct += 1

    success_rate = correct / rounds if rounds else 0.0
    return {
        "rounds": rounds,
        "oracle_queries_per_round": oracle_queries,
        "success_rate": success_rate,
        "empirical_advantage": abs(success_rate - 0.5),
        "security_claim": "A dummy adversary with encryption-oracle access should stay near 50% success."
    }

def ind_cpa_nonce_reuse_attack_experiment(
    k,
    m0,
    m1,
    rounds=100,
    reuse_nonce=True,
    method="dlp",
    **kwargs
):
    if len(m0) != len(m1):
        raise ValueError("IND-CPA game requires m0 and m1 to be the exact same length.")

    correct = 0
    for _ in range(rounds):
        oracle = _encryption_oracle(k, reuse_nonce=reuse_nonce, method=method, **kwargs)
        r0, c0 = oracle(m0)
        r1, c1 = oracle(m1)

        challenge = ind_cpa_game(k, m0, m1, reuse_nonce=reuse_nonce, method=method, **kwargs)
        challenge_pair = (challenge["challenge_r"], challenge["challenge_c"])

        if challenge_pair == (r0, c0):
            guess = 0
        elif challenge_pair == (r1, c1):
            guess = 1
        else:
            guess = random.choice([0, 1])

        if guess == challenge["secret_bit"]:
            correct += 1

    success_rate = correct / rounds if rounds else 0.0
    return {
        "rounds": rounds,
        "reuse_nonce": reuse_nonce,
        "attack_success_rate": success_rate,
        "empirical_advantage": abs(success_rate - 0.5),
        "attack": "Query Enc(m0), Enc(m1), then match the challenge ciphertext when nonce reuse makes encryption deterministic."
    }

def main():
    print("=== Testing PA#3: CPA-Secure Symmetric Encryption ===")
    
    toy_p = 65537 
    toy_g = 3
    test_key = "1011" 
    
    test_message = "1100101011" 
    
    print(f"\n--- Encrypt / Decrypt Cycle ---")
    print(f"Original Message: {test_message}")
    
    try:
        r, ciphertext = cpa_enc(k=test_key, m=test_message, method="dlp", p=toy_p, g=toy_g)
        print(f"Ciphertext: <r: {r}, c: {ciphertext}>")
        
        recovered_m = cpa_dec(k=test_key, r=r, c=ciphertext, method="dlp", p=toy_p, g=toy_g)
        print(f"Recovered Msg:    {recovered_m}")
        print(f"Success: {test_message == recovered_m}")
    except Exception as e:
        print(f"Error during encryption cycle: {e}")

    print("\n--- IND-CPA Game (Secure Mode) ---")
    m0 = "1111"
    m1 = "0000"
    print(f"Adversary submits m0={m0}, m1={m1}")
    game_secure = ind_cpa_game(test_key, m0, m1, reuse_nonce=False, method="dlp", p=toy_p, g=toy_g)
    print(f"Challenger returns: <r: {game_secure['challenge_r']}, c: {game_secure['challenge_c']}>")
    print(f"(Secret bit was {game_secure['secret_bit']})")

    secure_experiment = ind_cpa_dummy_adversary_experiment(
        test_key, m0, m1, rounds=100, oracle_queries=50, method="dlp", p=toy_p, g=toy_g
    )
    print(f"Dummy adversary success over 100 rounds: {secure_experiment['success_rate']:.3f}")
    print(f"Empirical advantage: {secure_experiment['empirical_advantage']:.3f}")

    print("\n--- IND-CPA Game (Broken Nonce-Reuse Mode) ---")
    print("Encrypting m0 twice with the same nonce...")
    game_broken_1 = ind_cpa_game(test_key, m0, m0, reuse_nonce=True, method="dlp", p=toy_p, g=toy_g)
    game_broken_2 = ind_cpa_game(test_key, m0, m0, reuse_nonce=True, method="dlp", p=toy_p, g=toy_g)
    
    print(f"Ciphertext 1: {game_broken_1['challenge_c']}")
    print(f"Ciphertext 2: {game_broken_2['challenge_c']}")
    if game_broken_1['challenge_c'] == game_broken_2['challenge_c']:
        print("VULNERABILITY CONFIRMED: Identical ciphertexts detected! Adversary wins 100% of the time.")

    broken_experiment = ind_cpa_nonce_reuse_attack_experiment(
        test_key, m0, m1, rounds=100, reuse_nonce=True, method="dlp", p=toy_p, g=toy_g
    )
    print(f"Nonce-reuse attack success over 100 rounds: {broken_experiment['attack_success_rate']:.3f}")
    print(f"Empirical advantage: {broken_experiment['empirical_advantage']:.3f}")

if __name__ == "__main__":
    main()
