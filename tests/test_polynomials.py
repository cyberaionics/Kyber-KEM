"""Tests for polynomial ring arithmetic."""

import pytest
from kyber.params import N, Q
from kyber.polynomials import Polynomial


class TestPolynomialBasics:
    """Basic polynomial construction and identity tests."""

    def test_zero_polynomial(self):
        p = Polynomial()
        assert all(c == 0 for c in p.coeffs)

    def test_construction_with_coefficients(self):
        coeffs = list(range(N))
        p = Polynomial(coeffs)
        assert p.coeffs == coeffs

    def test_mod_reduction_on_construction(self):
        """Coefficients should be reduced mod q on creation."""
        p = Polynomial([Q + 1] + [0] * (N - 1))
        assert p.coeffs[0] == 1

    def test_negative_coefficient_wraps(self):
        p = Polynomial([-1] + [0] * (N - 1))
        assert p.coeffs[0] == Q - 1

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2, 3])


class TestPolynomialArithmetic:
    """Addition, subtraction, and scalar multiplication."""

    def test_add_identity(self):
        p = Polynomial(list(range(N)))
        zero = Polynomial()
        assert p + zero == p

    def test_add_commutative(self):
        a = Polynomial(list(range(N)))
        b = Polynomial(list(range(N, 2 * N)))
        assert a + b == b + a

    def test_sub_self_is_zero(self):
        p = Polynomial(list(range(N)))
        result = p - p
        assert all(c == 0 for c in result.coeffs)

    def test_add_mod_q(self):
        a = Polynomial([Q - 1] + [0] * (N - 1))
        b = Polynomial([2] + [0] * (N - 1))
        result = a + b
        assert result.coeffs[0] == 1  # (3328 + 2) mod 3329 = 1

    def test_negation(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        neg_a = -a
        result = a + neg_a
        assert all(c == 0 for c in result.coeffs)

    def test_scalar_mul(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        result = a.scalar_mul(5)
        assert result.coeffs[0] == 5
        assert result.coeffs[1] == 10
        assert result.coeffs[2] == 15


class TestSchoolbookMultiply:
    """Schoolbook polynomial multiplication in R_q."""

    def test_mul_by_one(self):
        """X^0 = 1 as multiplicative identity."""
        a = Polynomial(list(range(N)))
        one = Polynomial([1] + [0] * (N - 1))
        assert a.schoolbook_mul(one) == a

    def test_mul_by_zero(self):
        a = Polynomial(list(range(N)))
        zero = Polynomial()
        result = a.schoolbook_mul(zero)
        assert all(c == 0 for c in result.coeffs)

    def test_mul_commutative(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        b = Polynomial([4, 5, 6] + [0] * (N - 3))
        assert a.schoolbook_mul(b) == b.schoolbook_mul(a)

    def test_x_times_x_is_x_squared(self):
        """X · X = X² (should have coefficient 1 at index 2)."""
        x = Polynomial([0, 1] + [0] * (N - 2))
        result = x.schoolbook_mul(x)
        expected = Polynomial([0, 0, 1] + [0] * (N - 3))
        assert result == expected

    def test_x_pow_n_is_minus_one(self):
        """X^{n/2} · X^{n/2} = X^n ≡ −1 mod (X^n + 1)."""
        x_half = Polynomial([0] * (N // 2) + [1] + [0] * (N // 2 - 1))
        result = x_half.schoolbook_mul(x_half)
        # X^256 ≡ -1, so coefficient at index 0 should be Q-1 = 3328
        assert result.coeffs[0] == Q - 1
        assert all(result.coeffs[i] == 0 for i in range(1, N))

    def test_copy(self):
        a = Polynomial([1, 2, 3] + [0] * (N - 3))
        b = a.copy()
        assert a == b
        b.coeffs[0] = 999
        assert a != b
