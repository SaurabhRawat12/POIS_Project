"""API/UI subsystem hooks."""

from .pa11_api import dh_exchange_endpoint, dh_group_endpoint, dh_mitm_demo_endpoint
from .pa12_api import (
    pkcs15_roundtrip_endpoint,
    rsa_determinism_demo_endpoint,
    rsa_keygen_endpoint,
    rsa_roundtrip_endpoint,
)
from .pa13_api import prime_generation_endpoint, primality_check_endpoint
from .pa14_api import crt_endpoint, hastad_demo_endpoint, rsa_dec_crt_endpoint
from .pa16_api import (
    elgamal_ind_cpa_endpoint,
    elgamal_keygen_endpoint,
    elgamal_malleability_demo_endpoint,
    elgamal_roundtrip_endpoint,
)

__all__ = [
    "primality_check_endpoint",
    "prime_generation_endpoint",
    "dh_group_endpoint",
    "dh_exchange_endpoint",
    "dh_mitm_demo_endpoint",
    "rsa_keygen_endpoint",
    "rsa_roundtrip_endpoint",
    "pkcs15_roundtrip_endpoint",
    "rsa_determinism_demo_endpoint",
    "crt_endpoint",
    "rsa_dec_crt_endpoint",
    "hastad_demo_endpoint",
    "elgamal_keygen_endpoint",
    "elgamal_roundtrip_endpoint",
    "elgamal_malleability_demo_endpoint",
    "elgamal_ind_cpa_endpoint",
]
