"""
Polynomial ring arithmetic over R_q = Z_q[X] / (X^n + 1).

Each polynomial is represented as a list of n=256 integer coefficients in [0, q).
This module provides the Polynomial class with addition, subtraction,
scalar multiplication, and schoolbook multiplication (for testing / reference).
"""

from __future__ import annotations
from typing import List
from kyber.params import N, Q


class Polynomial:
    """
    An element of the ring R_q = Z_q[X] / (X^256 + 1).

    Coefficients are stored as a list of 256 integers, each in [0, q).
    """

    __slots__ = ("coeffs",)

    def __init__(self, coeffs: List[int] | None = None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            if len(coeffs) != N:
                raise ValueError(f"Expected {N} coefficients, got {len(coeffs)}.")
            self.coeffs = [c % Q for c in coeffs]

    # ── Arithmetic ────────────────────────────────────────────────────────

    def __add__(self, other: Polynomial) -> Polynomial:
        """Coefficient-wise addition mod q."""
        return Polynomial([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __sub__(self, other: Polynomial) -> Polynomial:
        """Coefficient-wise subtraction mod q."""
        return Polynomial([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __neg__(self) -> Polynomial:
        """Negate every coefficient mod q."""
        return Polynomial([(Q - c) % Q for c in self.coeffs])

    def scalar_mul(self, s: int) -> Polynomial:
        """Multiply every coefficient by scalar s mod q."""
        s_mod = s % Q
        return Polynomial([(c * s_mod) % Q for c in self.coeffs])

    def schoolbook_mul(self, other: Polynomial) -> Polynomial:
        """
        Schoolbook (naïve) polynomial multiplication in R_q.

        Reduction mod (X^256 + 1) is done by subtracting the coefficient
        whenever the degree exceeds n−1, since X^n ≡ −1 (mod X^n + 1).

        Complexity: O(n²).  Used only for testing against NTT multiply.
        """
        result = [0] * N
        for i in range(N):
            for j in range(N):
                idx = i + j
                prod = (self.coeffs[i] * other.coeffs[j]) % Q
                if idx < N:
                    result[idx] = (result[idx] + prod) % Q
                else:
                    # X^n ≡ −1  ⟹  X^{n+r} ≡ −X^r
                    result[idx - N] = (result[idx - N] - prod) % Q
        return Polynomial(result)

    # ── Comparison & utilities ────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self.coeffs == other.coeffs

    def __repr__(self) -> str:
        return f"Polynomial({self.coeffs[:4]}...)"

    def copy(self) -> Polynomial:
        return Polynomial(list(self.coeffs))


# ── Vector / Matrix helpers (lists of Polynomials) ────────────────────────────

def poly_vec_add(a: List[Polynomial], b: List[Polynomial]) -> List[Polynomial]:
    """Element-wise addition of two polynomial vectors."""
    return [ai + bi for ai, bi in zip(a, b)]


def poly_vec_sub(a: List[Polynomial], b: List[Polynomial]) -> List[Polynomial]:
    """Element-wise subtraction of two polynomial vectors."""
    return [ai - bi for ai, bi in zip(a, b)]


def poly_inner_product(a: List[Polynomial], b: List[Polynomial]) -> Polynomial:
    """
    Inner product of two polynomial vectors (in NTT domain).

    Returns sum of a[i] * b[i] for all i, where * is coefficient-wise
    multiplication (assumes inputs are already in NTT domain and uses
    point-wise multiply).
    """
    from kyber.ntt import ntt_base_mul
    acc = Polynomial()
    for ai, bi in zip(a, b):
        product = ntt_base_mul(ai, bi)
        acc = acc + product
    return acc


def mat_vec_mul(matrix: List[List[Polynomial]],
                vec: List[Polynomial]) -> List[Polynomial]:
    """
    Matrix–vector product A · v  (both in NTT domain).

    matrix[i][j] is the (i,j) entry of A.
    Returns a vector of length len(matrix).
    """
    return [poly_inner_product(row, vec) for row in matrix]
