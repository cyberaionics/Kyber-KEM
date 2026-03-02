"""
K-PKE: The inner IND-CPA-secure public-key encryption scheme used by ML-KEM.

Implements Algorithms 13–15 of FIPS 203:
    - K-PKE.KeyGen(d)      →  (encryption_key, decryption_key)
    - K-PKE.Encrypt(ek, m, r)  →  ciphertext
    - K-PKE.Decrypt(dk, c)     →  message

All polynomial multiplications use the NTT for O(n log n) performance.
"""

from __future__ import annotations
import os
from typing import Tuple, List

from kyber.params import N, Q, KyberParams, KYBER_512
from kyber.polynomials import Polynomial, poly_vec_add, mat_vec_mul, poly_inner_product
from kyber.ntt import ntt, ntt_inv, ntt_base_mul
from kyber.utils import (
    G, H, PRF, XOF,
    byte_encode, byte_decode,
    compress, decompress,
    encode_poly_vector, decode_poly_vector,
    sample_ntt, sample_poly_cbd,
)


# ══════════════════════════════════════════════════════════════════════════════
# K-PKE.KeyGen — FIPS 203 Algorithm 13
# ══════════════════════════════════════════════════════════════════════════════

def kpke_keygen(d: bytes, params: KyberParams = KYBER_512) -> Tuple[bytes, bytes]:
    """
    Generate a K-PKE key pair from a 32-byte seed d.

    Returns:
        (ek, dk) — encryption key and decryption key, both as bytes.
    """
    k = params.k
    eta1 = params.eta1

    # Step 1: Expand seed
    rho, sigma = G(d + bytes([k]))

    # Step 2: Sample matrix  in NTT domain
    A_hat: List[List[Polynomial]] = []
    for i in range(k):
        row = []
        for j in range(k):
            xof_bytes = XOF(rho, i, j)
            row.append(sample_ntt(xof_bytes))
        A_hat.append(row)

    # Step 3: Sample secret vector s and error vector e
    N_counter = 0
    s: List[Polynomial] = []
    for i in range(k):
        prf_bytes = PRF(sigma, N_counter, 64 * eta1)
        s.append(sample_poly_cbd(prf_bytes, eta1))
        N_counter += 1

    e: List[Polynomial] = []
    for i in range(k):
        prf_bytes = PRF(sigma, N_counter, 64 * eta1)
        e.append(sample_poly_cbd(prf_bytes, eta1))
        N_counter += 1

    # Step 4: NTT(s) and NTT(e)
    s_hat = [ntt(si) for si in s]
    e_hat = [ntt(ei) for ei in e]

    # Step 5: t̂ = Â · ŝ + ê
    t_hat = poly_vec_add(mat_vec_mul(A_hat, s_hat), e_hat)

    # Step 6: Encode keys
    ek = encode_poly_vector(t_hat, 12) + rho         # public key
    dk = encode_poly_vector(s_hat, 12)                # private key

    return ek, dk


# ══════════════════════════════════════════════════════════════════════════════
# K-PKE.Encrypt — FIPS 203 Algorithm 14
# ══════════════════════════════════════════════════════════════════════════════

def kpke_encrypt(ek: bytes, m: bytes, randomness: bytes,
                 params: KyberParams = KYBER_512) -> bytes:
    """
    Encrypt a 32-byte message m under public key ek.

    Args:
        ek: Encryption key (from kpke_keygen).
        m: 32-byte plaintext message.
        randomness: 32-byte randomness (deterministic encryption for CCA transform).
        params: Kyber parameter set.

    Returns:
        Ciphertext as bytes.
    """
    k = params.k
    eta1 = params.eta1
    eta2 = params.eta2
    du = params.du
    dv = params.dv

    # Step 1: Decode public key
    t_hat = decode_poly_vector(ek[:384 * k], k, 12)
    rho = ek[384 * k:]

    # Step 2: Reconstruct matrix Â in NTT domain
    A_hat: List[List[Polynomial]] = []
    for i in range(k):
        row = []
        for j in range(k):
            xof_bytes = XOF(rho, i, j)
            row.append(sample_ntt(xof_bytes))
        A_hat.append(row)

    # Step 3: Sample r, e1, e2
    N_counter = 0
    r: List[Polynomial] = []
    for i in range(k):
        prf_bytes = PRF(randomness, N_counter, 64 * eta1)
        r.append(sample_poly_cbd(prf_bytes, eta1))
        N_counter += 1

    e1: List[Polynomial] = []
    for i in range(k):
        prf_bytes = PRF(randomness, N_counter, 64 * eta2)
        e1.append(sample_poly_cbd(prf_bytes, eta2))
        N_counter += 1

    prf_bytes = PRF(randomness, N_counter, 64 * eta2)
    e2 = sample_poly_cbd(prf_bytes, eta2)

    # Step 4: NTT(r)
    r_hat = [ntt(ri) for ri in r]

    # Step 5: u = NTT⁻¹(Âᵀ · r̂) + e1
    #   Âᵀ[i][j] = Â[j][i],  so we build the transpose
    A_hat_T: List[List[Polynomial]] = []
    for i in range(k):
        row = []
        for j in range(k):
            row.append(A_hat[j][i])
        A_hat_T.append(row)

    u = poly_vec_add(
        [ntt_inv(p) for p in mat_vec_mul(A_hat_T, r_hat)],
        e1
    )

    # Step 6: v = NTT⁻¹(t̂ᵀ · r̂) + e2 + Decompress₁(m)
    t_hat_dot_r_hat = poly_inner_product(t_hat, r_hat)
    v = ntt_inv(t_hat_dot_r_hat) + e2

    # Decode message as Decompress_1(m):  bit b → round(q/2) · b
    m_poly = byte_decode(m, 1)
    m_decompressed = decompress(m_poly, 1)
    v = v + m_decompressed

    # Step 7: Compress and encode ciphertext
    c1 = encode_poly_vector([compress(ui, du) for ui in u], du)
    c2 = byte_encode(compress(v, dv), dv)

    return c1 + c2


# ══════════════════════════════════════════════════════════════════════════════
# K-PKE.Decrypt — FIPS 203 Algorithm 15
# ══════════════════════════════════════════════════════════════════════════════

def kpke_decrypt(dk: bytes, c: bytes,
                 params: KyberParams = KYBER_512) -> bytes:
    """
    Decrypt a ciphertext c using decryption key dk.

    Returns:
        32-byte plaintext message.
    """
    k = params.k
    du = params.du
    dv = params.dv

    # Step 1: Split and decode ciphertext
    c1_len = 32 * du * k
    c1 = c[:c1_len]
    c2 = c[c1_len:]

    u_compressed = decode_poly_vector(c1, k, du)
    u = [decompress(ui, du) for ui in u_compressed]

    v_compressed = byte_decode(c2, dv)
    v = decompress(v_compressed, dv)

    # Step 2: Decode secret key
    s_hat = decode_poly_vector(dk, k, 12)

    # Step 3: m = Compress₁(v − NTT⁻¹(ŝᵀ · NTT(u)))
    u_hat = [ntt(ui) for ui in u]
    inner = poly_inner_product(s_hat, u_hat)
    w = v - ntt_inv(inner)

    # Compress to 1 bit = rounding to {0, 1}
    m_poly = compress(w, 1)
    m = byte_encode(m_poly, 1)

    return m
