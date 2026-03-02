"""
ML-KEM: Module-Lattice-Based Key Encapsulation Mechanism  (FIPS 203).

Wraps the K-PKE inner scheme with the Fujisaki–Okamoto transform to
achieve IND-CCA2 security (ciphertext integrity + implicit rejection).

Implements Algorithms 19–21 of FIPS 203:
    - ML-KEM.KeyGen()         →  (encapsulation_key, decapsulation_key)
    - ML-KEM.Encaps(ek)       →  (shared_secret, ciphertext)
    - ML-KEM.Decaps(dk, c)    →  shared_secret
"""

from __future__ import annotations
import os
from typing import Tuple

from kyber.params import KyberParams, KYBER_512
from kyber.kpke import kpke_keygen, kpke_encrypt, kpke_decrypt
from kyber.utils import H, G, J


# ══════════════════════════════════════════════════════════════════════════════
# ML-KEM.KeyGen — FIPS 203 Algorithm 19
# ══════════════════════════════════════════════════════════════════════════════

def KeyGen(params: KyberParams = KYBER_512) -> Tuple[bytes, bytes]:
    """
    Generate an ML-KEM key pair.

    Returns:
        (ek, dk):
            ek — encapsulation (public) key.
            dk — decapsulation (private) key, containing:
                 dk_pke ‖ ek ‖ H(ek) ‖ z
    """
    # Random seeds
    d = os.urandom(32)
    z = os.urandom(32)

    # Inner K-PKE key generation
    ek, dk_pke = kpke_keygen(d, params)

    # Pack decapsulation key  (FIPS 203: dk = dk_pke ‖ ek ‖ H(ek) ‖ z)
    dk = dk_pke + ek + H(ek) + z

    return ek, dk


# ══════════════════════════════════════════════════════════════════════════════
# ML-KEM.Encaps — FIPS 203 Algorithm 20
# ══════════════════════════════════════════════════════════════════════════════

def Encaps(ek: bytes, params: KyberParams = KYBER_512) -> Tuple[bytes, bytes]:
    """
    Encapsulate: generate a shared secret and ciphertext from the public key.

    Args:
        ek: Encapsulation (public) key.
        params: Kyber parameter set.

    Returns:
        (shared_secret, ciphertext):
            shared_secret — 32 bytes, the KEM shared key K.
            ciphertext    — the encapsulated ciphertext c.
    """
    # Step 1: Random message
    m = os.urandom(32)

    # Step 2: (K, r) = G(m ‖ H(ek))
    K, r = G(m + H(ek))

    # Step 3: Encrypt with deterministic randomness
    c = kpke_encrypt(ek, m, r, params)

    return K, c


# ══════════════════════════════════════════════════════════════════════════════
# ML-KEM.Decaps — FIPS 203 Algorithm 21
# ══════════════════════════════════════════════════════════════════════════════

def Decaps(dk: bytes, c: bytes, params: KyberParams = KYBER_512) -> bytes:
    """
    Decapsulate: recover the shared secret from the ciphertext and private key.

    Includes implicit rejection — if the ciphertext is invalid, returns
    a pseudorandom value derived from z and c (rather than an error),
    preventing chosen-ciphertext attacks.

    Args:
        dk: Decapsulation (private) key.
        c: Ciphertext from Encaps.
        params: Kyber parameter set.

    Returns:
        32-byte shared secret K.
    """
    k = params.k

    # Step 1: Parse decapsulation key  (dk = dk_pke ‖ ek ‖ H(ek) ‖ z)
    dk_pke_len = 384 * k            # ByteEncode_12 of s_hat vector
    ek_len = 384 * k + 32           # ByteEncode_12 of t_hat vector + rho

    dk_pke = dk[:dk_pke_len]
    ek = dk[dk_pke_len:dk_pke_len + ek_len]
    h_ek = dk[dk_pke_len + ek_len:dk_pke_len + ek_len + 32]
    z = dk[dk_pke_len + ek_len + 32:]

    # Step 2: Decrypt to recover m'
    m_prime = kpke_decrypt(dk_pke, c, params)

    # Step 3: Re-derive (K', r') = G(m' ‖ H(ek))
    K_prime, r_prime = G(m_prime + h_ek)

    # Step 4: Re-encrypt to get c'
    c_prime = kpke_encrypt(ek, m_prime, r_prime, params)

    # Step 5: Implicit rejection — constant-time comparison is ideal,
    #         but for this educational implementation we use equality check.
    if c == c_prime:
        return K_prime
    else:
        # Return pseudorandom rejection value
        return J(z + c)
