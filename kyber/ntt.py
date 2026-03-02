"""
Number Theoretic Transform (NTT) for the ring R_q = Z_q[X] / (X^256 + 1).

Implements the Cooley-Tukey forward NTT and Gentleman-Sande inverse NTT
exactly as specified in FIPS 203 (ML-KEM), Algorithms 10 and 11.

Parameters:
    q = 3329        (prime modulus)
    n = 256         (polynomial degree)
    ζ = 17          (primitive 512-th root of unity mod q: 17^256 ≡ −1 mod q)
"""

from __future__ import annotations
from typing import List
from kyber.params import N, Q, ZETA
from kyber.polynomials import Polynomial


# ── Pre-computed table of powers of ζ ─────────────────────────────────────────
# Bit-reversed order as required by the in-place butterfly algorithms.
# zetas[i] = ζ^{BitRev_7(i)} mod q,  for i = 0 … 127.

def _precompute_zetas() -> List[int]:
    """
    Compute the 128 "zeta" values used in NTT / INTT.

    The ordering follows FIPS 203: the indices are bit-reversed within
    7-bit width, matching the layer structure of the butterfly network.
    """
    zetas = [0] * 128
    for i in range(128):
        # Bit-reverse i in 7 bits
        br = int(f"{i:07b}"[::-1], 2)
        zetas[i] = pow(ZETA, br, Q)
    return zetas


ZETAS: List[int] = _precompute_zetas()


# ── Forward NTT (Cooley-Tukey butterfly) ─ FIPS 203 Algorithm 10 ──────────────

def ntt(f: Polynomial) -> Polynomial:
    """
    Compute the Number Theoretic Transform of polynomial f  (in-place style).

    Input:  f  in coefficient representation  (256 coefficients in Z_q).
    Output: f̂  in NTT representation.

    This is Algorithm 10 from FIPS 203.
    """
    coeffs = list(f.coeffs)       # work on a copy
    k = 1                          # index into zetas table
    length = 128                   # half-size of current butterfly block

    while length >= 2:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * coeffs[j + length]) % Q
                coeffs[j + length] = (coeffs[j] - t) % Q
                coeffs[j] = (coeffs[j] + t) % Q
            start += 2 * length
        length //= 2

    return Polynomial(coeffs)


# ── Inverse NTT (Gentleman-Sande butterfly) ─ FIPS 203 Algorithm 11 ──────────

def ntt_inv(f_hat: Polynomial) -> Polynomial:
    """
    Compute the inverse NTT, converting from NTT domain back to coefficients.

    Input:  f̂  in NTT representation.
    Output: f  in coefficient representation.

    This is Algorithm 11 from FIPS 203.
    The final scaling by n⁻¹ mod q is folded into the last butterfly layer.
    """
    coeffs = list(f_hat.coeffs)
    k = 127                        # index into zetas table (descending)
    length = 2

    while length <= 128:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = coeffs[j]
                coeffs[j] = (t + coeffs[j + length]) % Q
                coeffs[j + length] = (zeta * (coeffs[j + length] - t)) % Q
            start += 2 * length
        length *= 2

    # Kyber's NTT is a 7-layer incomplete NTT (128 degree-1 components),
    # so the normalization factor is 128⁻¹ mod q, NOT 256⁻¹.
    n_inv = pow(128, -1, Q)        # 128⁻¹ mod 3329 = 3303
    coeffs = [(c * n_inv) % Q for c in coeffs]

    return Polynomial(coeffs)


# ── Base-case multiplication in NTT domain ────────────────────────────────────

def _base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple:
    """
    Multiply two degree-1 polynomials modulo (X² − γ) in Z_q.

    (a0 + a1·X) · (b0 + b1·X) mod (X² − γ)
    = (a0·b0 + a1·b1·γ) + (a0·b1 + a1·b0)·X

    Returns (c0, c1).
    """
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def ntt_base_mul(a_hat: Polynomial, b_hat: Polynomial) -> Polynomial:
    """
    Point-wise multiplication of two polynomials in NTT domain.

    In Kyber's NTT representation the 256 coefficients form 128 pairs,
    each pair living in a quotient ring Z_q[X]/(X² − ζ^{2·BitRev(i)+1}).
    We perform 128 base-case multiplications of degree-1 polynomials.

    This is Algorithm 12 from FIPS 203.
    """
    result = [0] * N

    for i in range(64):
        # Even block — gamma = ζ^{2·BitRev_7(i) + 1}
        z_idx = 64 + i
        gamma = ZETAS[z_idx]

        # First pair in this block
        idx = 4 * i
        c0, c1 = _base_case_multiply(
            a_hat.coeffs[idx], a_hat.coeffs[idx + 1],
            b_hat.coeffs[idx], b_hat.coeffs[idx + 1],
            gamma,
        )
        result[idx] = c0
        result[idx + 1] = c1

        # Second pair — gamma is negated
        c0, c1 = _base_case_multiply(
            a_hat.coeffs[idx + 2], a_hat.coeffs[idx + 3],
            b_hat.coeffs[idx + 2], b_hat.coeffs[idx + 3],
            (Q - gamma) % Q,
        )
        result[idx + 2] = c0
        result[idx + 3] = c1

    return Polynomial(result)
