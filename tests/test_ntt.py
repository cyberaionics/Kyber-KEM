"""Tests for the Number Theoretic Transform (NTT)."""

import random
import pytest
from kyber.params import N, Q
from kyber.polynomials import Polynomial
from kyber.ntt import ntt, ntt_inv, ntt_base_mul


class TestNTTRoundTrip:
    """NTT → INTT should return the original polynomial."""

    def test_roundtrip_zero(self):
        f = Polynomial()
        assert ntt_inv(ntt(f)) == f

    def test_roundtrip_one(self):
        f = Polynomial([1] + [0] * (N - 1))
        assert ntt_inv(ntt(f)) == f

    def test_roundtrip_random(self):
        random.seed(42)
        coeffs = [random.randint(0, Q - 1) for _ in range(N)]
        f = Polynomial(coeffs)
        assert ntt_inv(ntt(f)) == f

    def test_roundtrip_all_ones(self):
        f = Polynomial([1] * N)
        assert ntt_inv(ntt(f)) == f

    def test_roundtrip_max_coeffs(self):
        f = Polynomial([Q - 1] * N)
        assert ntt_inv(ntt(f)) == f


class TestNTTMultiply:
    """NTT-based multiplication should match schoolbook multiplication."""

    def _ntt_mul(self, a: Polynomial, b: Polynomial) -> Polynomial:
        """Multiply via NTT: NTT⁻¹(NTT(a) ⊙ NTT(b))."""
        return ntt_inv(ntt_base_mul(ntt(a), ntt(b)))

    def test_mul_identity(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        one = Polynomial([1] + [0] * (N - 1))
        assert self._ntt_mul(a, one) == a

    def test_mul_zero(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        zero = Polynomial()
        result = self._ntt_mul(a, zero)
        assert all(c == 0 for c in result.coeffs)

    def test_matches_schoolbook_small(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        b = Polynomial([4, 5, 6] + [0] * (N - 3))
        ntt_result = self._ntt_mul(a, b)
        school_result = a.schoolbook_mul(b)
        assert ntt_result == school_result

    def test_matches_schoolbook_random(self):
        random.seed(123)
        a = Polynomial([random.randint(0, Q - 1) for _ in range(N)])
        b = Polynomial([random.randint(0, Q - 1) for _ in range(N)])
        ntt_result = self._ntt_mul(a, b)
        school_result = a.schoolbook_mul(b)
        assert ntt_result == school_result

    def test_commutativity(self):
        random.seed(456)
        a = Polynomial([random.randint(0, Q - 1) for _ in range(N)])
        b = Polynomial([random.randint(0, Q - 1) for _ in range(N)])
        assert self._ntt_mul(a, b) == self._ntt_mul(b, a)
