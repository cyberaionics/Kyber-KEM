"""
CRYSTALS-Kyber parameter sets per FIPS 203 (ML-KEM).

All three security levels share n=256 and q=3329.
The parameter 'k' controls the module dimension (and thus security level).
"""

from dataclasses import dataclass


# ── Global constants ──────────────────────────────────────────────────────────
N: int = 256          # Polynomial degree
Q: int = 3329         # Coefficient modulus (prime, NTT-friendly: 3329 = 13·256 + 1)
ZETA: int = 17        # Primitive 512-th root of unity mod Q  (17^256 ≡ −1 mod 3329)


@dataclass(frozen=True)
class KyberParams:
    """Immutable container for one Kyber / ML-KEM parameter set."""
    name: str
    k: int              # Module dimension
    eta1: int           # CBD parameter for secret / first noise
    eta2: int           # CBD parameter for second noise
    du: int             # Compression bits for ciphertext vector u
    dv: int             # Compression bits for ciphertext scalar v

    @property
    def n(self) -> int:
        return N

    @property
    def q(self) -> int:
        return Q


# ── Pre-defined parameter sets ────────────────────────────────────────────────
KYBER_512 = KyberParams(name="ML-KEM-512",  k=2, eta1=3, eta2=2, du=10, dv=4)
KYBER_768 = KyberParams(name="ML-KEM-768",  k=3, eta1=2, eta2=2, du=10, dv=4)
KYBER_1024 = KyberParams(name="ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5)

PARAM_SETS = {
    512:  KYBER_512,
    768:  KYBER_768,
    1024: KYBER_1024,
}


def get_params(security_level: int = 512) -> KyberParams:
    """
    Return the KyberParams for the requested security level.

    Args:
        security_level: One of 512, 768, or 1024.

    Returns:
        The corresponding KyberParams instance.

    Raises:
        ValueError: If the security level is not supported.
    """
    if security_level not in PARAM_SETS:
        raise ValueError(
            f"Unsupported security level {security_level}. "
            f"Choose from {sorted(PARAM_SETS.keys())}."
        )
    return PARAM_SETS[security_level]
