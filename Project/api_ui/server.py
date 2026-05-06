"""FastAPI server exposing every PA endpoint as an HTTP route.

This file is the single entry point for the React frontend. Every
api_ui/paN_api.py function (or paN_hooks.py hook) is mounted as a
POST route under /pa{N}/{action}.

Run locally:
    uvicorn api_ui.server:app --reload --port 8000

Then open http://localhost:8000/docs for interactive Swagger UI
where every endpoint can be tested directly in the browser.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---- import every PA endpoint ----------------------------------------------

# Friends' existing _api endpoints
from api_ui.pa11_api import (
    dh_exchange_endpoint,
    dh_group_endpoint,
    dh_mitm_demo_endpoint,
)
from api_ui.pa12_api import (
    pkcs15_roundtrip_endpoint,
    rsa_determinism_demo_endpoint,
    rsa_keygen_endpoint,
    rsa_roundtrip_endpoint,
)
from api_ui.pa13_api import primality_check_endpoint, prime_generation_endpoint
from api_ui.pa14_api import crt_endpoint, hastad_demo_endpoint, rsa_dec_crt_endpoint
from api_ui.pa16_api import (
    elgamal_ind_cpa_endpoint,
    elgamal_keygen_endpoint,
    elgamal_malleability_demo_endpoint,
    elgamal_roundtrip_endpoint,
)

# Friends' _hooks endpoints (different argument style: take a payload dict)
from api_ui.pa4_hooks import (
    pa4_cbc_iv_reuse_demo_hook,
    pa4_decrypt_hook,
    pa4_encrypt_hook,
    pa4_ofb_reuse_demo_hook,
)
from api_ui.pa5_hooks import (
    pa5_euf_cma_demo_hook,
    pa5_length_extension_demo_hook,
    pa5_mac_hook,
    pa5_prf_distinguish_demo_hook,
    pa5_verify_hook,
)
from api_ui.pa6_hooks import (
    pa6_cca_decrypt_hook,
    pa6_cca_encrypt_hook,
    pa6_cca_game_hook,
    pa6_key_separation_demo_hook,
    pa6_malleability_demo_hook,
)
from api_ui.pa7_hooks import pa7_collision_demo_hook, pa7_md_hash_hook

# My new endpoints (PA #15, #17, #18, #19, #20)
from api_ui.pa15_api import (
    euf_cma_endpoint as pa15_euf_cma_endpoint,
    multiplicative_forgery_endpoint,
    sign_endpoint as pa15_sign_endpoint,
    verify_endpoint as pa15_verify_endpoint,
)
from api_ui.pa17_api import (
    decrypt_endpoint as pa17_decrypt_endpoint,
    encrypt_endpoint as pa17_encrypt_endpoint,
    ind_cca2_endpoint,
    keygen_endpoint as pa17_keygen_endpoint,
    lineage_endpoint as pa17_lineage_endpoint,
    malleability_blocked_endpoint,
)
from api_ui.pa18_api import (
    ot_run_endpoint,
    ot_setup_endpoint,
    receiver_privacy_endpoint,
    sender_privacy_endpoint,
)
from api_ui.pa19_api import (
    privacy_endpoint,
    secure_and_endpoint,
    secure_not_endpoint,
    secure_xor_endpoint,
    truth_table_endpoint,
)
from api_ui.pa20_api import (
    addition_endpoint,
    benchmark_endpoint,
    equality_endpoint,
    lineage_endpoint as pa20_lineage_endpoint,
    millionaire_endpoint,
)


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="POIS Cryptography Lab",
    version="1.0.0",
    description=(
        "HTTP interface to every cryptographic primitive in the POIS_Project. "
        "Every PA exposes its construction, attack demo, and security-game "
        "endpoints. The React frontend (PA#0) consumes this API."
    ),
)

# Permissive CORS for local development (React dev server runs on a different port).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["meta"])
def root() -> Dict[str, Any]:
    """Health check + endpoint summary."""
    return {
        "service": "POIS Cryptography Lab",
        "version": "1.0.0",
        "status": "ok",
        "docs": "/docs",
        "supported_pas": [
            "PA#4 (Modes)", "PA#5 (MAC)", "PA#6 (CCA-Sym)",
            "PA#7 (Merkle-Damgard)",
            "PA#11 (DH)", "PA#12 (RSA)", "PA#13 (Miller-Rabin)",
            "PA#14 (CRT/Hastad)", "PA#15 (Signatures)",
            "PA#16 (ElGamal)", "PA#17 (CCA-PKC)", "PA#18 (OT)",
            "PA#19 (Secure Gates)", "PA#20 (MPC)",
        ],
    }


# ---------------------------------------------------------------------------
# Pydantic request bodies (one per endpoint family)
# ---------------------------------------------------------------------------
# Bigints arrive as Python int; FastAPI/Pydantic handle these natively.

class PA13PrimalityRequest(BaseModel):
    n: int
    k: int = 40
    trace: bool = False


class PA13GenPrimeRequest(BaseModel):
    bits: int = 64
    k: int = 40
    seed: Optional[int] = None


class PA11GroupRequest(BaseModel):
    q_bits: int = 255
    k: int = 40


class PA11ExchangeRequest(BaseModel):
    params: Dict[str, int]


class PA11MITMRequest(BaseModel):
    params: Optional[Dict[str, int]] = None


class PA12KeyGenRequest(BaseModel):
    bits: int = 512
    seed: Optional[int] = None


class PA12RoundtripRequest(BaseModel):
    message: int
    bits: int = 512
    seed: Optional[int] = None


class PA12DemoRequest(BaseModel):
    message: str = "yes"
    bits: int = 512
    seed: Optional[int] = None


class PA14CRTRequest(BaseModel):
    residues: List[int]
    moduli: List[int]


class PA14RSADecCRTRequest(BaseModel):
    bits: int = 512
    message: int = 12345
    seed: Optional[int] = None


class PA14HastadRequest(BaseModel):
    message: int
    bits: int = 64
    e: int = 3
    seed: Optional[int] = None


class PA16KeyGenRequest(BaseModel):
    q_bits: int = 255
    k: int = 40


class PA16RoundtripRequest(BaseModel):
    message_int: int
    q_bits: int = 63
    k: int = 20


class PA16MalleabilityRequest(BaseModel):
    message: Optional[int] = None
    factor: int = 2
    q_bits: int = 31
    k: int = 20


class PA16IndCpaRequest(BaseModel):
    rounds: int = 50
    q_bits: int = 31
    k: int = 20
    strategy: str = "random"
    seed: Optional[int] = None


# Hook-style PAs (PA#4, 5, 6, 7) take a flexible payload dict
class HookPayload(BaseModel):
    payload: Dict[str, Any] = {}


# PA#15
class PA15SignRequest(BaseModel):
    message: str
    bits: int = 512
    q_bits: int = 31
    seed: Optional[int] = None


class PA15VerifyRequest(BaseModel):
    message: str
    signature: int
    public_key: Dict[str, Any]
    group_params: Dict[str, Any]


class PA15ForgeryRequest(BaseModel):
    bits: int = 512
    seed: Optional[int] = None


class PA15EUFCMARequest(BaseModel):
    queries: int = 50
    bits: int = 512
    q_bits: int = 31
    seed: Optional[int] = None


# PA#17
class PA17KeyGenRequest(BaseModel):
    elgamal_q_bits: int = 63
    rsa_bits: int = 512
    hash_q_bits: int = 31
    seed: Optional[int] = None


class PA17EncryptRequest(BaseModel):
    pk_enc: Dict[str, Any]
    sk_sign: Dict[str, Any]
    message: int
    hash_group: Dict[str, Any]
    seed: Optional[int] = None


class PA17DecryptRequest(BaseModel):
    sk_enc: Dict[str, Any]
    pk_enc: Dict[str, Any]
    vk_sign: Dict[str, Any]
    CE: Dict[str, int]
    sigma: int
    hash_group: Dict[str, Any]


class PA17DemoRequest(BaseModel):
    message: Optional[int] = None
    factor: int = 2
    elgamal_q_bits: int = 63
    rsa_bits: int = 512
    hash_q_bits: int = 31
    seed: Optional[int] = None


class PA17GameRequest(BaseModel):
    rounds: int = 20
    elgamal_q_bits: int = 63
    rsa_bits: int = 512
    hash_q_bits: int = 31
    seed: Optional[int] = None


# PA#18
class PA18SetupRequest(BaseModel):
    q_bits: int = 63
    k: int = 20
    seed: Optional[int] = None


class PA18RunRequest(BaseModel):
    b: int
    m_0: int
    m_1: int
    q_bits: int = 63
    k: int = 20
    seed: Optional[int] = None


class PA18DemoRequest(BaseModel):
    q_bits: int = 63
    k: int = 20
    seed: Optional[int] = None


# PA#19
class PA19GateRequest(BaseModel):
    a: int
    b: Optional[int] = None
    q_bits: int = 63
    k: int = 20
    seed: Optional[int] = None


class PA19TruthTableRequest(BaseModel):
    runs_per_combo: int = 10
    q_bits: int = 63
    k: int = 20
    seed: Optional[int] = None


class PA19PrivacyRequest(BaseModel):
    q_bits: int = 63
    k: int = 20
    seed: Optional[int] = None


# PA#20
class PA20CircuitRequest(BaseModel):
    x: int
    y: int
    n: int = 8
    seed: Optional[int] = None


# ---------------------------------------------------------------------------
# PA #4 -- Modes (CBC / OFB / CTR)
# ---------------------------------------------------------------------------

@app.post("/pa4/encrypt", tags=["PA#4 Modes"])
def pa4_encrypt(req: HookPayload) -> Dict[str, Any]:
    return pa4_encrypt_hook(req.payload)


@app.post("/pa4/decrypt", tags=["PA#4 Modes"])
def pa4_decrypt(req: HookPayload) -> Dict[str, Any]:
    return pa4_decrypt_hook(req.payload)


@app.post("/pa4/cbc-iv-reuse-demo", tags=["PA#4 Modes"])
def pa4_cbc_iv_reuse_demo(req: HookPayload) -> Dict[str, Any]:
    return pa4_cbc_iv_reuse_demo_hook(req.payload)


@app.post("/pa4/ofb-reuse-demo", tags=["PA#4 Modes"])
def pa4_ofb_reuse_demo(req: HookPayload) -> Dict[str, Any]:
    return pa4_ofb_reuse_demo_hook(req.payload)


# ---------------------------------------------------------------------------
# PA #5 -- MACs
# ---------------------------------------------------------------------------

@app.post("/pa5/mac", tags=["PA#5 MAC"])
def pa5_mac(req: HookPayload) -> Dict[str, Any]:
    return pa5_mac_hook(req.payload)


@app.post("/pa5/verify", tags=["PA#5 MAC"])
def pa5_verify(req: HookPayload) -> Dict[str, Any]:
    return pa5_verify_hook(req.payload)


@app.post("/pa5/euf-cma-demo", tags=["PA#5 MAC"])
def pa5_euf_cma_demo(req: HookPayload) -> Dict[str, Any]:
    return pa5_euf_cma_demo_hook(req.payload)


@app.post("/pa5/length-extension-demo", tags=["PA#5 MAC"])
def pa5_length_extension_demo(req: HookPayload) -> Dict[str, Any]:
    return pa5_length_extension_demo_hook(req.payload)


@app.post("/pa5/prf-distinguish-demo", tags=["PA#5 MAC"])
def pa5_prf_distinguish_demo(req: HookPayload) -> Dict[str, Any]:
    return pa5_prf_distinguish_demo_hook(req.payload)


# ---------------------------------------------------------------------------
# PA #6 -- CCA Symmetric
# ---------------------------------------------------------------------------

@app.post("/pa6/cca-encrypt", tags=["PA#6 CCA-Sym"])
def pa6_cca_encrypt(req: HookPayload) -> Dict[str, Any]:
    return pa6_cca_encrypt_hook(req.payload)


@app.post("/pa6/cca-decrypt", tags=["PA#6 CCA-Sym"])
def pa6_cca_decrypt(req: HookPayload) -> Dict[str, Any]:
    return pa6_cca_decrypt_hook(req.payload)


@app.post("/pa6/cca-game", tags=["PA#6 CCA-Sym"])
def pa6_cca_game(req: HookPayload) -> Dict[str, Any]:
    return pa6_cca_game_hook(req.payload)


@app.post("/pa6/malleability-demo", tags=["PA#6 CCA-Sym"])
def pa6_malleability_demo(req: HookPayload) -> Dict[str, Any]:
    return pa6_malleability_demo_hook(req.payload)


@app.post("/pa6/key-separation-demo", tags=["PA#6 CCA-Sym"])
def pa6_key_separation_demo(req: HookPayload) -> Dict[str, Any]:
    return pa6_key_separation_demo_hook(req.payload)


# ---------------------------------------------------------------------------
# PA #7 -- Merkle-Damgard
# ---------------------------------------------------------------------------

@app.post("/pa7/md-hash", tags=["PA#7 Merkle-Damgard"])
def pa7_md_hash(req: HookPayload) -> Dict[str, Any]:
    return pa7_md_hash_hook(req.payload)


@app.post("/pa7/collision-demo", tags=["PA#7 Merkle-Damgard"])
def pa7_collision_demo(req: HookPayload) -> Dict[str, Any]:
    return pa7_collision_demo_hook(req.payload)


# ---------------------------------------------------------------------------
# PA #11 -- Diffie-Hellman
# ---------------------------------------------------------------------------

@app.post("/pa11/group", tags=["PA#11 Diffie-Hellman"])
def pa11_group(req: PA11GroupRequest) -> Dict[str, Any]:
    return dh_group_endpoint(q_bits=req.q_bits, k=req.k)


@app.post("/pa11/exchange", tags=["PA#11 Diffie-Hellman"])
def pa11_exchange(req: PA11ExchangeRequest) -> Dict[str, Any]:
    return dh_exchange_endpoint(req.params)


@app.post("/pa11/mitm-demo", tags=["PA#11 Diffie-Hellman"])
def pa11_mitm_demo(req: PA11MITMRequest) -> Dict[str, Any]:
    return dh_mitm_demo_endpoint(req.params)


# ---------------------------------------------------------------------------
# PA #12 -- RSA
# ---------------------------------------------------------------------------

@app.post("/pa12/keygen", tags=["PA#12 RSA"])
def pa12_keygen(req: PA12KeyGenRequest) -> Dict[str, Any]:
    return rsa_keygen_endpoint(bits=req.bits, seed=req.seed)


@app.post("/pa12/roundtrip", tags=["PA#12 RSA"])
def pa12_roundtrip(req: PA12RoundtripRequest) -> Dict[str, Any]:
    return rsa_roundtrip_endpoint(message=req.message, bits=req.bits, seed=req.seed)


@app.post("/pa12/pkcs15-roundtrip", tags=["PA#12 RSA"])
def pa12_pkcs15_roundtrip(req: PA12DemoRequest) -> Dict[str, Any]:
    return pkcs15_roundtrip_endpoint(
        message=req.message.encode("utf-8"), bits=req.bits, seed=req.seed
    )


@app.post("/pa12/determinism-demo", tags=["PA#12 RSA"])
def pa12_determinism_demo(req: PA12DemoRequest) -> Dict[str, Any]:
    return rsa_determinism_demo_endpoint(
        message=req.message.encode("utf-8"), bits=req.bits, seed=req.seed
    )


# ---------------------------------------------------------------------------
# PA #13 -- Miller-Rabin Primality
# ---------------------------------------------------------------------------

@app.post("/pa13/check", tags=["PA#13 Primality"])
def pa13_check(req: PA13PrimalityRequest) -> Dict[str, Any]:
    return primality_check_endpoint(n=req.n, k=req.k, trace=req.trace)


@app.post("/pa13/generate", tags=["PA#13 Primality"])
def pa13_generate(req: PA13GenPrimeRequest) -> Dict[str, Any]:
    return prime_generation_endpoint(bits=req.bits, k=req.k, seed=req.seed)


# ---------------------------------------------------------------------------
# PA #14 -- CRT + Hastad
# ---------------------------------------------------------------------------

@app.post("/pa14/crt", tags=["PA#14 CRT"])
def pa14_crt(req: PA14CRTRequest) -> Dict[str, Any]:
    return crt_endpoint(residues=req.residues, moduli=req.moduli)


@app.post("/pa14/rsa-dec-crt", tags=["PA#14 CRT"])
def pa14_rsa_dec_crt(req: PA14RSADecCRTRequest) -> Dict[str, Any]:
    return rsa_dec_crt_endpoint(bits=req.bits, message=req.message, seed=req.seed)


@app.post("/pa14/hastad-demo", tags=["PA#14 CRT"])
def pa14_hastad_demo(req: PA14HastadRequest) -> Dict[str, Any]:
    return hastad_demo_endpoint(
        message=req.message, bits=req.bits, e=req.e, seed=req.seed
    )


# ---------------------------------------------------------------------------
# PA #15 -- Digital Signatures
# ---------------------------------------------------------------------------

@app.post("/pa15/sign", tags=["PA#15 Signatures"])
def pa15_sign(req: PA15SignRequest) -> Dict[str, Any]:
    return pa15_sign_endpoint(
        message=req.message, bits=req.bits, q_bits=req.q_bits, seed=req.seed
    )


@app.post("/pa15/verify", tags=["PA#15 Signatures"])
def pa15_verify(req: PA15VerifyRequest) -> Dict[str, Any]:
    return pa15_verify_endpoint(
        message=req.message,
        signature=req.signature,
        public_key=req.public_key,
        group_params=req.group_params,
    )


@app.post("/pa15/multiplicative-forgery", tags=["PA#15 Signatures"])
def pa15_forgery(req: PA15ForgeryRequest) -> Dict[str, Any]:
    return multiplicative_forgery_endpoint(bits=req.bits, seed=req.seed)


@app.post("/pa15/euf-cma-game", tags=["PA#15 Signatures"])
def pa15_euf_cma(req: PA15EUFCMARequest) -> Dict[str, Any]:
    return pa15_euf_cma_endpoint(
        queries=req.queries, bits=req.bits, q_bits=req.q_bits, seed=req.seed
    )


# ---------------------------------------------------------------------------
# PA #16 -- ElGamal
# ---------------------------------------------------------------------------

@app.post("/pa16/keygen", tags=["PA#16 ElGamal"])
def pa16_keygen(req: PA16KeyGenRequest) -> Dict[str, Any]:
    return elgamal_keygen_endpoint(q_bits=req.q_bits, k=req.k)


@app.post("/pa16/roundtrip", tags=["PA#16 ElGamal"])
def pa16_roundtrip(req: PA16RoundtripRequest) -> Dict[str, Any]:
    return elgamal_roundtrip_endpoint(
        message_int=req.message_int, q_bits=req.q_bits, k=req.k
    )


@app.post("/pa16/malleability-demo", tags=["PA#16 ElGamal"])
def pa16_malleability(req: PA16MalleabilityRequest) -> Dict[str, Any]:
    return elgamal_malleability_demo_endpoint(
        message=req.message, factor=req.factor, q_bits=req.q_bits, k=req.k
    )


@app.post("/pa16/ind-cpa-game", tags=["PA#16 ElGamal"])
def pa16_ind_cpa(req: PA16IndCpaRequest) -> Dict[str, Any]:
    return elgamal_ind_cpa_endpoint(
        rounds=req.rounds, q_bits=req.q_bits, k=req.k,
        strategy=req.strategy, seed=req.seed,
    )


# ---------------------------------------------------------------------------
# PA #17 -- CCA-Secure PKC
# ---------------------------------------------------------------------------

@app.post("/pa17/keygen", tags=["PA#17 CCA-PKC"])
def pa17_keygen(req: PA17KeyGenRequest) -> Dict[str, Any]:
    return pa17_keygen_endpoint(
        elgamal_q_bits=req.elgamal_q_bits,
        rsa_bits=req.rsa_bits,
        hash_q_bits=req.hash_q_bits,
        seed=req.seed,
    )


@app.post("/pa17/encrypt", tags=["PA#17 CCA-PKC"])
def pa17_encrypt(req: PA17EncryptRequest) -> Dict[str, Any]:
    return pa17_encrypt_endpoint(
        pk_enc=req.pk_enc,
        sk_sign=req.sk_sign,
        message=req.message,
        hash_group=req.hash_group,
        seed=req.seed,
    )


@app.post("/pa17/decrypt", tags=["PA#17 CCA-PKC"])
def pa17_decrypt(req: PA17DecryptRequest) -> Dict[str, Any]:
    return pa17_decrypt_endpoint(
        sk_enc=req.sk_enc,
        pk_enc=req.pk_enc,
        vk_sign=req.vk_sign,
        CE=req.CE,
        sigma=req.sigma,
        hash_group=req.hash_group,
    )


@app.post("/pa17/malleability-blocked-demo", tags=["PA#17 CCA-PKC"])
def pa17_malleability(req: PA17DemoRequest) -> Dict[str, Any]:
    return malleability_blocked_endpoint(
        message=req.message,
        factor=req.factor,
        elgamal_q_bits=req.elgamal_q_bits,
        rsa_bits=req.rsa_bits,
        hash_q_bits=req.hash_q_bits,
        seed=req.seed,
    )


@app.post("/pa17/ind-cca2-game", tags=["PA#17 CCA-PKC"])
def pa17_ind_cca2(req: PA17GameRequest) -> Dict[str, Any]:
    return ind_cca2_endpoint(
        rounds=req.rounds,
        elgamal_q_bits=req.elgamal_q_bits,
        rsa_bits=req.rsa_bits,
        hash_q_bits=req.hash_q_bits,
        seed=req.seed,
    )


@app.get("/pa17/lineage", tags=["PA#17 CCA-PKC"])
def pa17_lineage() -> Dict[str, Any]:
    return pa17_lineage_endpoint()


# ---------------------------------------------------------------------------
# PA #18 -- Oblivious Transfer
# ---------------------------------------------------------------------------

@app.post("/pa18/setup", tags=["PA#18 OT"])
def pa18_setup(req: PA18SetupRequest) -> Dict[str, Any]:
    return ot_setup_endpoint(q_bits=req.q_bits, k=req.k, seed=req.seed)


@app.post("/pa18/run", tags=["PA#18 OT"])
def pa18_run(req: PA18RunRequest) -> Dict[str, Any]:
    return ot_run_endpoint(
        b=req.b, m_0=req.m_0, m_1=req.m_1,
        q_bits=req.q_bits, k=req.k, seed=req.seed,
    )


@app.post("/pa18/receiver-privacy-demo", tags=["PA#18 OT"])
def pa18_receiver_privacy(req: PA18DemoRequest) -> Dict[str, Any]:
    return receiver_privacy_endpoint(q_bits=req.q_bits, k=req.k, seed=req.seed)


@app.post("/pa18/sender-privacy-demo", tags=["PA#18 OT"])
def pa18_sender_privacy(req: PA18DemoRequest) -> Dict[str, Any]:
    return sender_privacy_endpoint(q_bits=req.q_bits, k=req.k, seed=req.seed)


# ---------------------------------------------------------------------------
# PA #19 -- Secure Gates
# ---------------------------------------------------------------------------

@app.post("/pa19/and", tags=["PA#19 Secure Gates"])
def pa19_and(req: PA19GateRequest) -> Dict[str, Any]:
    if req.b is None:
        raise ValueError("AND requires both a and b")
    return secure_and_endpoint(
        a=req.a, b=req.b, q_bits=req.q_bits, k=req.k, seed=req.seed
    )


@app.post("/pa19/xor", tags=["PA#19 Secure Gates"])
def pa19_xor(req: PA19GateRequest) -> Dict[str, Any]:
    if req.b is None:
        raise ValueError("XOR requires both a and b")
    return secure_xor_endpoint(a=req.a, b=req.b)


@app.post("/pa19/not", tags=["PA#19 Secure Gates"])
def pa19_not(req: PA19GateRequest) -> Dict[str, Any]:
    return secure_not_endpoint(a=req.a)


@app.post("/pa19/truth-table", tags=["PA#19 Secure Gates"])
def pa19_truth_table(req: PA19TruthTableRequest) -> Dict[str, Any]:
    return truth_table_endpoint(
        runs_per_combo=req.runs_per_combo,
        q_bits=req.q_bits, k=req.k, seed=req.seed,
    )


@app.post("/pa19/privacy-demo", tags=["PA#19 Secure Gates"])
def pa19_privacy(req: PA19PrivacyRequest) -> Dict[str, Any]:
    return privacy_endpoint(q_bits=req.q_bits, k=req.k, seed=req.seed)


# ---------------------------------------------------------------------------
# PA #20 -- 2-Party MPC
# ---------------------------------------------------------------------------

@app.post("/pa20/equality", tags=["PA#20 MPC"])
def pa20_equality(req: PA20CircuitRequest) -> Dict[str, Any]:
    return equality_endpoint(x=req.x, y=req.y, n=req.n, seed=req.seed)


@app.post("/pa20/addition", tags=["PA#20 MPC"])
def pa20_addition(req: PA20CircuitRequest) -> Dict[str, Any]:
    return addition_endpoint(x=req.x, y=req.y, n=req.n, seed=req.seed)


@app.post("/pa20/millionaire", tags=["PA#20 MPC"])
def pa20_millionaire(req: PA20CircuitRequest) -> Dict[str, Any]:
    return millionaire_endpoint(x=req.x, y=req.y, n=req.n, seed=req.seed)


@app.post("/pa20/benchmark", tags=["PA#20 MPC"])
def pa20_benchmark(seed: Optional[int] = None) -> Dict[str, Any]:
    return benchmark_endpoint(seed=seed)


@app.get("/pa20/lineage", tags=["PA#20 MPC"])
def pa20_lineage() -> Dict[str, Any]:
    return pa20_lineage_endpoint()
