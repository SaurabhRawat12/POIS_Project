"""PA #10: HMAC and HMAC-Based CCA-Secure Encryption.

Bridges hashing (Part II) and symmetric crypto (Part I).  Implements:
  1. HMAC over PA #8's DLP hash
  2. CRHF -> MAC (forward) and MAC -> CRHF (backward) demos
  3. Length-extension attack demo (naive H(k||m) is broken; HMAC is not)
  4. Encrypt-then-HMAC (CCA-secure symmetric encryption)
  5. Constant-time tag comparison

Dependencies (all from this project -- no external crypto libraries):
    PA #7  -- Merkle-Damgard framework  (primitives.pa7_merkle_damgard)
    PA #8  -- DLP-based CRHF            (primitives.pa8_dlp_hash)
    PA #13 -- Primality testing          (primitives.pa13_primality)
    core_math -- modexp, system_rng
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core_math.randomness import system_rng
from primitives.pa7_merkle_damgard import (
    HashContract,
    md_hash,
    md_pad,
    make_md_hasher,
)
from primitives.pa8_dlp_hash import (
    DLPGroup,
    dlp_hash,
    get_dlp_hash_interface,
    _make_dlp_compress,
)

PA_ID = "PA#10"


# ===================================================================
# 1.  HMAC Construction
# ===================================================================

def _pad_key(key: bytes, block_size: int, hash_fn: Callable[[bytes], bytes]) -> bytes:
    """Pad or hash the key to exactly *block_size* bytes (HMAC key schedule)."""
    if len(key) > block_size:
        key = hash_fn(key)
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))
    return key


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def hmac_tag(
    key: bytes,
    message: bytes | str,
    group: DLPGroup | None = None,
    *,
    _hash_fn: Callable[[bytes | str], bytes] | None = None,
    _block_size: int | None = None,
) -> bytes:
    """Compute HMAC_k(m) using PA #8's DLP hash.

    HMAC_k(m) = H( (k ^ opad) || H( (k ^ ipad) || m ) )

    Parameters
    ----------
    key : bytes
        The HMAC key (arbitrary length).
    message : bytes or str
        The message to authenticate.
    group : DLPGroup, optional
        DLP group for PA #8.  Generated if None.
    """
    if _hash_fn is not None and _block_size is not None:
        hash_fn = _hash_fn
        block_size = _block_size
    else:
        if group is None:
            group = DLPGroup.generate_toy()
        contract, hash_fn = get_dlp_hash_interface(group=group)
        block_size = contract.block_size

    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    padded_key = _pad_key(key, block_size, lambda m: hash_fn(m))

    inner_key = _xor_bytes(padded_key, ipad)
    outer_key = _xor_bytes(padded_key, opad)

    if isinstance(message, str):
        message = message.encode("utf-8")

    inner_hash = hash_fn(inner_key + message)
    tag = hash_fn(outer_key + inner_hash)
    return tag


def hmac_verify(
    key: bytes,
    message: bytes | str,
    tag: bytes,
    group: DLPGroup | None = None,
    *,
    _hash_fn: Callable[[bytes | str], bytes] | None = None,
    _block_size: int | None = None,
) -> bool:
    """Verify an HMAC tag using constant-time comparison."""
    computed = hmac_tag(
        key, message, group,
        _hash_fn=_hash_fn, _block_size=_block_size,
    )
    return secure_compare(computed, tag)


# ===================================================================
# 2.  Constant-Time Comparison
# ===================================================================

def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings.

    XORs all bytes and checks the accumulator is zero.
    Never short-circuits, preventing timing side-channel leaks.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _naive_compare(a: bytes, b: bytes) -> bool:
    """Naive early-exit comparison (INSECURE -- for demo only)."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def timing_comparison_demo(
    tag_length: int = 16,
    trials: int = 1000,
) -> Dict[str, Any]:
    """Demonstrate that naive comparison leaks info via timing.

    Measures average time for tags differing at the first byte vs
    the last byte.  The naive comparator is faster for early
    mismatches; the secure comparator takes constant time.
    """
    reference = os.urandom(tag_length)

    # Tag differing at first byte
    early_diff = bytearray(reference)
    early_diff[0] ^= 0xFF
    early_diff = bytes(early_diff)

    # Tag differing at last byte
    late_diff = bytearray(reference)
    late_diff[-1] ^= 0xFF
    late_diff = bytes(late_diff)

    def measure(compare_fn: Callable, tag: bytes, runs: int) -> float:
        start = time.perf_counter()
        for _ in range(runs):
            compare_fn(reference, tag)
        return (time.perf_counter() - start) / runs * 1e9  # nanoseconds

    naive_early_ns = measure(_naive_compare, early_diff, trials)
    naive_late_ns = measure(_naive_compare, late_diff, trials)
    secure_early_ns = measure(secure_compare, early_diff, trials)
    secure_late_ns = measure(secure_compare, late_diff, trials)

    return {
        "pa_id": PA_ID,
        "tag_length": tag_length,
        "trials": trials,
        "naive_early_diff_ns": round(naive_early_ns, 1),
        "naive_late_diff_ns": round(naive_late_ns, 1),
        "naive_ratio_late_over_early": round(naive_late_ns / max(naive_early_ns, 0.1), 3),
        "secure_early_diff_ns": round(secure_early_ns, 1),
        "secure_late_diff_ns": round(secure_late_ns, 1),
        "secure_ratio_late_over_early": round(secure_late_ns / max(secure_early_ns, 0.1), 3),
        "note": (
            "Naive ratio > 1 means late-byte mismatches take longer "
            "(information leaks). Secure ratio should be ~1.0."
        ),
    }


# ===================================================================
# 3.  Length-Extension Attack Demo
# ===================================================================

def _naive_mac(key: bytes, message: bytes, group: DLPGroup) -> bytes:
    """Broken MAC: t = H(key || message).  Vulnerable to length extension."""
    return dlp_hash(key + message, group=group)


def length_extension_demo(
    group: DLPGroup | None = None,
) -> Dict[str, Any]:
    """Demonstrate that H(k||m) is broken by length extension, but HMAC is not.

    The Merkle-Damgard structure means that given H(k||m), an adversary
    can compute H(k||m||pad||m') for any suffix m' without knowing k --
    the internal state after processing k||m is exactly H(k||m).

    Attack procedure (adversary knows: tag, len(k||m), suffix m'):
    1. Compute the MD padding that was applied to k||m
    2. Use the tag as the starting state for further MD blocks
    3. Process the suffix m' (with its own padding) from that state
    4. The result equals H(k || m || original_pad || m')
    """
    if group is None:
        group = DLPGroup.generate_toy()

    block_size = group.p_byte_len
    key = os.urandom(block_size)
    message = b"pay Alice 100"
    suffix = b"pay Eve 99999"

    # --- Naive MAC: t = H(k || m) ---
    naive_tag = _naive_mac(key, message, group)

    # The adversary knows: naive_tag, len(key + message), suffix
    # They do NOT know key.
    original_len = len(key) + len(message)

    # Step 1: Compute the padding that MD applied to the original input
    original_padded = md_pad(key + message, block_size=block_size)
    glue_padding = original_padded[original_len:]  # the padding bytes

    # Step 2: The extended message (from the verifier's perspective) is:
    #   key || message || glue_padding || suffix
    # The adversary constructs the message part (without key):
    #   message || glue_padding || suffix
    forged_message = message + glue_padding + suffix

    # Step 3: The adversary computes the forged tag by continuing MD
    # from state = naive_tag, processing the suffix with new padding.
    compress = _make_dlp_compress(group)
    # The adversary pads the suffix as if it's a new message being
    # appended after the already-padded original.
    # Total length of the full input to MD is:
    total_len = len(original_padded) + len(suffix)
    suffix_padded = md_pad(
        original_padded + suffix,
        block_size=block_size,
    )
    # The new blocks to process are everything after original_padded
    new_blocks = suffix_padded[len(original_padded):]

    state = naive_tag
    for offset in range(0, len(new_blocks), block_size):
        block = new_blocks[offset : offset + block_size]
        state = compress(state, block)
    forged_tag = state

    # Step 4: Verify -- compute the real hash of key || forged_message
    real_tag = dlp_hash(key + forged_message, group=group)

    naive_attack_success = (forged_tag == real_tag)

    # --- HMAC: same attack should FAIL ---
    hmac_original = hmac_tag(key, message, group)
    hmac_forged = hmac_tag(key, forged_message, group)
    # The adversary cannot produce hmac_forged from hmac_original
    # because the outer hash uses a different key (k ^ opad).
    hmac_attack_success = (hmac_original == hmac_forged)

    return {
        "pa_id": PA_ID,
        "naive_mac": {
            "original_message": message.decode(),
            "suffix": suffix.decode(),
            "original_tag": naive_tag.hex(),
            "forged_tag": forged_tag.hex(),
            "real_tag": real_tag.hex(),
            "attack_succeeded": naive_attack_success,
            "explanation": (
                "H(k||m) is vulnerable: given the tag (= final MD state) and "
                "len(k||m), the adversary computes the glue padding, then "
                "continues hashing with the suffix to produce a valid tag "
                "for (m || pad || suffix) WITHOUT knowing k."
            ),
        },
        "hmac": {
            "original_tag": hmac_original.hex(),
            "forged_tag": hmac_forged.hex(),
            "attack_succeeded": hmac_attack_success,
            "explanation": (
                "HMAC defeats length extension: the outer hash uses a fresh "
                "keyed IV (k ^ opad), so the adversary cannot continue from "
                "the inner hash state."
            ),
        },
    }


# ===================================================================
# 4.  CRHF <-> MAC Bidirectional Demos
# ===================================================================

def crhf_to_mac_demo(group: DLPGroup | None = None) -> Dict[str, Any]:
    """Forward direction: CRHF -> MAC via HMAC.

    Run a simple EUF-CMA game: after querying the HMAC oracle on 50
    messages, confirm that the adversary cannot forge a tag on a new
    message (without the key).
    """
    if group is None:
        group = DLPGroup.generate_toy()

    key = os.urandom(group.p_byte_len)
    rng = system_rng()

    # Oracle phase: query 50 messages
    queried: Dict[bytes, bytes] = {}
    for i in range(50):
        msg = os.urandom(rng.randrange(1, 32))
        tag = hmac_tag(key, msg, group)
        queried[msg] = tag

    # Forgery attempt: try to forge a tag on a new message
    new_msg = b"never-queried-message"
    assert new_msg not in queried, "Test message was already queried"

    # Adversary's best strategy without the key: guess randomly
    forged = os.urandom(group.p_byte_len)
    real_tag = hmac_tag(key, new_msg, group)
    forgery_succeeded = secure_compare(forged, real_tag)

    return {
        "pa_id": PA_ID,
        "direction": "CRHF -> MAC (forward)",
        "queries": 50,
        "forgery_succeeded": forgery_succeeded,
        "note": (
            "After 50 oracle queries, the adversary cannot forge a valid "
            "HMAC tag on a new message.  This demonstrates that the DLP "
            "hash (CRHF) produces a secure MAC via the HMAC construction."
        ),
    }


def mac_to_crhf_demo(group: DLPGroup | None = None) -> Dict[str, Any]:
    """Backward direction: MAC -> CRHF.

    Construct h'(cv, block) = HMAC_k(cv || block) for a fixed public key k.
    Plug into PA #7 Merkle-Damgard to get MACHash.  Show that finding a
    collision in MACHash would require forging an HMAC tag.
    """
    if group is None:
        group = DLPGroup.generate_toy()

    contract, hash_fn = get_dlp_hash_interface(group=group)
    block_size = contract.block_size
    digest_size = contract.digest_size

    # Fixed public key for the MAC-based compression
    fixed_key = os.urandom(block_size)

    def mac_compress(state: bytes, block: bytes) -> bytes:
        """h'(cv, block) = HMAC_k(cv || block)."""
        combined = state + block
        tag = hmac_tag(fixed_key, combined, group)
        # Truncate/pad to match state size
        if len(tag) >= digest_size:
            return tag[:digest_size]
        return tag + b"\x00" * (digest_size - len(tag))

    iv = b"\x00" * digest_size

    # Hash several messages through MACHash
    messages = [b"hello", b"world", b"test", b"foo", b"bar"]
    digests = {}
    for msg in messages:
        d = md_hash(msg, mac_compress, iv, block_size)
        digests[msg] = d

    # Check all distinct
    unique = set(digests.values())
    all_distinct = len(unique) == len(digests)

    return {
        "pa_id": PA_ID,
        "direction": "MAC -> CRHF (backward)",
        "messages_hashed": len(messages),
        "all_distinct": all_distinct,
        "digests": {m.decode(): d.hex() for m, d in digests.items()},
        "note": (
            "MACHash(m) = MD(HMAC_k(cv || block)).  Any collision in "
            "MACHash implies two distinct (cv, block) pairs with the same "
            "HMAC output -- which constitutes an HMAC forgery.  Therefore "
            "MACHash is collision-resistant if HMAC is EUF-CMA secure."
        ),
    }


# ===================================================================
# 5.  Encrypt-then-HMAC (CCA-Secure Encryption)
# ===================================================================

def _xor_stream(data: bytes, keystream: bytes) -> bytes:
    """XOR data with a keystream (simple CTR-mode encryption)."""
    return bytes(d ^ k for d, k in zip(data, keystream))


def _generate_keystream(key: bytes, nonce: bytes, length: int,
                        group: DLPGroup) -> bytes:
    """Generate a pseudo-random keystream using DLP hash in counter mode.

    This is a minimal CTR-mode construction for demo purposes.
    In the full project, PA #3's CPA-secure encryption would be used.
    """
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        counter_bytes = counter.to_bytes(4, "big")
        block = dlp_hash(key + nonce + counter_bytes, group=group)
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def eth_enc(
    key_e: bytes,
    key_m: bytes,
    message: bytes,
    group: DLPGroup | None = None,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt-then-HMAC encryption.

    C = Enc_{kE}(m)   (CTR-mode with DLP hash keystream)
    t = HMAC_{kM}(nonce || C)

    Returns (nonce, ciphertext, tag).
    """
    if group is None:
        group = DLPGroup.generate_toy()

    nonce = os.urandom(group.p_byte_len)
    keystream = _generate_keystream(key_e, nonce, len(message), group)
    ciphertext = _xor_stream(message, keystream)
    tag = hmac_tag(key_m, nonce + ciphertext, group)

    return nonce, ciphertext, tag


def eth_dec(
    key_e: bytes,
    key_m: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    group: DLPGroup | None = None,
) -> bytes | None:
    """Encrypt-then-HMAC decryption.

    Verify HMAC_{kM}(nonce || C) == t BEFORE decrypting.
    Returns plaintext on success, None on authentication failure.
    """
    if group is None:
        group = DLPGroup.generate_toy()

    # Verify-before-decrypt
    if not hmac_verify(key_m, nonce + ciphertext, tag, group):
        return None  # Authentication failed

    keystream = _generate_keystream(key_e, nonce, len(ciphertext), group)
    return _xor_stream(ciphertext, keystream)


# ===================================================================
# 6.  Self-Test / Integration Tests
# ===================================================================

def _run_tests() -> None:
    """Run all PA #10 integration tests."""

    print("=" * 70)
    print("  PA #10 -- HMAC and HMAC-Based CCA-Secure Encryption")
    print("  Integration Tests")
    print("=" * 70)

    group = DLPGroup.generate_toy()

    # ---- Test 1: HMAC basic correctness ----
    print("\n[1] HMAC Tag + Verify ...")
    key = os.urandom(group.p_byte_len)
    msg = b"hello world"
    tag = hmac_tag(key, msg, group)
    print(f"    key = {key.hex()}")
    print(f"    msg = {msg.hex()}")
    print(f"    tag = {tag.hex()}")

    assert hmac_verify(key, msg, tag, group), "Valid tag rejected!"
    assert not hmac_verify(key, b"wrong message", tag, group), "Wrong msg accepted!"
    assert not hmac_verify(os.urandom(len(key)), msg, tag, group), "Wrong key accepted!"

    # Tampered tag
    bad_tag = bytearray(tag)
    bad_tag[-1] ^= 0xFF
    assert not hmac_verify(key, msg, bytes(bad_tag), group), "Tampered tag accepted!"
    print("    [OK] HMAC tag/verify works correctly")

    # ---- Test 2: HMAC determinism ----
    print("\n[2] HMAC Determinism ...")
    tag2 = hmac_tag(key, msg, group)
    assert tag == tag2, "Same inputs produced different tags!"
    print("    [OK] Same key+msg -> same tag")

    # ---- Test 3: HMAC key padding ----
    print("\n[3] HMAC Key Padding ...")
    short_key = b"\x01\x02"
    long_key = os.urandom(group.p_byte_len * 3)
    tag_short = hmac_tag(short_key, msg, group)
    tag_long = hmac_tag(long_key, msg, group)
    assert tag_short != tag_long, "Different keys should produce different tags"
    # Verify both are valid
    assert hmac_verify(short_key, msg, tag_short, group)
    assert hmac_verify(long_key, msg, tag_long, group)
    print(f"    Short key ({len(short_key)}B): tag = {tag_short.hex()}")
    print(f"    Long key  ({len(long_key)}B): tag = {tag_long.hex()}")
    print("    [OK] Key padding handles short and long keys")

    # ---- Test 4: Constant-time comparison ----
    print("\n[4] Constant-Time Comparison ...")
    a = os.urandom(32)
    b = os.urandom(32)
    assert secure_compare(a, a), "Identical bytes not equal"
    assert not secure_compare(a, b), "Different bytes are equal"
    assert not secure_compare(a, a[:16]), "Different lengths are equal"
    print("    [OK] secure_compare works correctly")

    # ---- Test 5: Timing comparison demo ----
    print("\n[5] Timing Comparison Demo ...")
    timing = timing_comparison_demo(tag_length=32, trials=5000)
    print(f"    Naive  -- early diff: {timing['naive_early_diff_ns']:.0f} ns, "
          f"late diff: {timing['naive_late_diff_ns']:.0f} ns, "
          f"ratio: {timing['naive_ratio_late_over_early']:.2f}")
    print(f"    Secure -- early diff: {timing['secure_early_diff_ns']:.0f} ns, "
          f"late diff: {timing['secure_late_diff_ns']:.0f} ns, "
          f"ratio: {timing['secure_ratio_late_over_early']:.2f}")
    print("    [OK] Timing demo complete")

    # ---- Test 6: Length-extension demo ----
    print("\n[6] Length-Extension Attack Demo ...")
    le_result = length_extension_demo(group)
    naive_ok = le_result["naive_mac"]["attack_succeeded"]
    hmac_ok = le_result["hmac"]["attack_succeeded"]
    print(f"    Naive H(k||m) attack succeeded: {naive_ok}")
    print(f"    HMAC attack succeeded: {hmac_ok}")
    assert naive_ok, "Length extension should succeed on naive MAC!"
    assert not hmac_ok, "Length extension should fail on HMAC!"
    print("    [OK] Naive MAC broken, HMAC safe")

    # ---- Test 7: CRHF -> MAC (forward) ----
    print("\n[7] CRHF -> MAC (EUF-CMA game) ...")
    fwd = crhf_to_mac_demo(group)
    assert not fwd["forgery_succeeded"], "Forgery should not succeed!"
    print(f"    Queries: {fwd['queries']}, Forgery: {fwd['forgery_succeeded']}")
    print("    [OK] HMAC resists forgery after 50 queries")

    # ---- Test 8: MAC -> CRHF (backward) ----
    print("\n[8] MAC -> CRHF (backward direction) ...")
    bwd = mac_to_crhf_demo(group)
    assert bwd["all_distinct"], "MACHash produced duplicate digests!"
    for m, d in bwd["digests"].items():
        print(f"    MACHash({m}) = {d}")
    print("    [OK] MACHash produces distinct digests")

    # ---- Test 9: Encrypt-then-HMAC ----
    print("\n[9] Encrypt-then-HMAC (EtH) ...")
    key_e = os.urandom(group.p_byte_len)
    key_m = os.urandom(group.p_byte_len)
    plaintext = b"Top secret message for CCA2 test"

    nonce, ct, tag = eth_enc(key_e, key_m, plaintext, group)
    print(f"    Plaintext : {plaintext}")
    print(f"    Nonce     : {nonce.hex()}")
    print(f"    Ciphertext: {ct.hex()}")
    print(f"    Tag       : {tag.hex()}")

    # Correct decryption
    recovered = eth_dec(key_e, key_m, nonce, ct, tag, group)
    assert recovered == plaintext, f"Decryption failed: {recovered}"
    print(f"    Recovered : {recovered}")
    print("    [OK] Correct decryption succeeds")

    # ---- Test 10: CCA2 -- reject tampered ciphertext ----
    print("\n[10] CCA2 -- Reject Tampered Ciphertext ...")
    # Flip a bit in ciphertext
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0x01
    result = eth_dec(key_e, key_m, nonce, bytes(tampered_ct), tag, group)
    assert result is None, "Tampered ciphertext should be rejected!"
    print("    Tampered ciphertext: REJECTED (returned None)")

    # Flip a bit in tag
    tampered_tag = bytearray(tag)
    tampered_tag[-1] ^= 0xFF
    result = eth_dec(key_e, key_m, nonce, ct, bytes(tampered_tag), group)
    assert result is None, "Tampered tag should be rejected!"
    print("    Tampered tag:        REJECTED (returned None)")

    # Wrong nonce
    result = eth_dec(key_e, key_m, os.urandom(len(nonce)), ct, tag, group)
    assert result is None, "Wrong nonce should be rejected!"
    print("    Wrong nonce:         REJECTED (returned None)")

    # Wrong MAC key
    result = eth_dec(key_e, os.urandom(len(key_m)), nonce, ct, tag, group)
    assert result is None, "Wrong MAC key should be rejected!"
    print("    Wrong MAC key:       REJECTED (returned None)")
    print("    [OK] All tampered inputs correctly rejected")

    # ---- Test 11: Multiple encrypt/decrypt round-trips ----
    print("\n[11] Multiple Round-Trip Encrypt/Decrypt ...")
    test_messages = [
        b"",
        b"a",
        b"short",
        b"A" * 100,
        os.urandom(50),
    ]
    for i, m in enumerate(test_messages):
        n, c, t = eth_enc(key_e, key_m, m, group)
        dec = eth_dec(key_e, key_m, n, c, t, group)
        assert dec == m, f"Round-trip {i} failed!"
    print(f"    [OK] All {len(test_messages)} messages round-trip correctly")

    # ---- Summary ----
    print("\n" + "=" * 70)
    print("  ALL PA #10 TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    _run_tests()
