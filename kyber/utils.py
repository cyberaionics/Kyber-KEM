"""
Cryptographic utilities for CRYSTALS-Kyber / ML-KEM.

Implements the hash functions, XOF/PRF streams, byte encoding/decoding,
compression/decompression, and sampling routines specified in FIPS 203.

Uses only Python's built-in `hashlib` (which provides SHA-3 and SHAKE).
"""

from __future__ import annotations
import hashlib
from typing import List

from kyber.params import N, Q
from kyber.polynomials import Polynomial


# ══════════════════════════════════════════════════════════════════════════════
# Hash functions  (FIPS 203 §4.1)
# ══════════════════════════════════════════════════════════════════════════════

def H(data: bytes) -> bytes:
    """H : SHA3-256.  Returns 32 bytes."""
    return hashlib.sha3_256(data).digest()


def G(data: bytes) -> tuple:
    """G : SHA3-512.  Returns (first_32_bytes, last_32_bytes)."""
    digest = hashlib.sha3_512(data).digest()
    return digest[:32], digest[32:]


def J(data: bytes) -> bytes:
    """J : SHAKE-256 squeezed to 32 bytes."""
    return hashlib.shake_256(data).digest(32)


def XOF(seed: bytes, i: int, j: int) -> bytes:
    """
    Extendable Output Function for matrix sampling.

    XOF(ρ, i, j) = SHAKE-128(ρ ‖ j ‖ i)   (note: j first per FIPS 203)
    We squeeze enough bytes for SampleNTT (rejection sampling needs ≤ 3·256 ≈ 840 bytes
    in expectation, we squeeze a generous 4096 bytes).
    """
    hasher = hashlib.shake_128(seed + bytes([j, i]))
    return hasher.digest(4096)


def PRF(key: bytes, nonce: int, length: int) -> bytes:
    """
    Pseudorandom Function for noise sampling.

    PRF(σ, N) = SHAKE-256(σ ‖ N)  squeezed to `length` bytes.
    """
    return hashlib.shake_256(key + bytes([nonce])).digest(length)


# ══════════════════════════════════════════════════════════════════════════════
# Byte Encoding / Decoding  (FIPS 203 Algorithms 4 & 5)
# ══════════════════════════════════════════════════════════════════════════════

def byte_encode(poly: Polynomial, d: int) -> bytes:
    """
    ByteEncode_d : serialize 256 d-bit integers into 32·d bytes.

    Each coefficient is taken mod 2^d (for d < 12) or mod q (for d = 12).
    Bits are packed in little-endian order.
    """
    m = (1 << d) if d < 12 else Q
    bit_string = []
    for c in poly.coeffs:
        val = c % m
        for bit_idx in range(d):
            bit_string.append((val >> bit_idx) & 1)

    # Pack bits into bytes (little-endian, 8 bits per byte)
    out = bytearray(32 * d)
    for i, bit in enumerate(bit_string):
        out[i // 8] |= bit << (i % 8)

    return bytes(out)


def byte_decode(data: bytes, d: int) -> Polynomial:
    """
    ByteDecode_d : deserialize 32·d bytes into 256 d-bit integers.

    Reverses ByteEncode_d.
    """
    m = (1 << d) if d < 12 else Q
    # Unpack all bits
    bits = []
    for byte_val in data:
        for bit_idx in range(8):
            bits.append((byte_val >> bit_idx) & 1)

    coeffs = []
    for i in range(N):
        val = 0
        for bit_idx in range(d):
            val |= bits[i * d + bit_idx] << bit_idx
        coeffs.append(val % m)

    return Polynomial(coeffs)


# ══════════════════════════════════════════════════════════════════════════════
# Compress / Decompress  (FIPS 203 Algorithms 6 & 7)
# ══════════════════════════════════════════════════════════════════════════════

def compress(poly: Polynomial, d: int) -> Polynomial:
    """
    Compress_d : round(2^d / q · x) mod 2^d  for each coefficient x.

    Lossy compression from Z_q to Z_{2^d}.
    """
    two_d = 1 << d
    coeffs = []
    for c in poly.coeffs:
        # (2^d * c + q//2) // q   gives the correct rounding
        compressed = ((two_d * c) + (Q // 2)) // Q
        coeffs.append(compressed % two_d)
    return Polynomial(coeffs)


def decompress(poly: Polynomial, d: int) -> Polynomial:
    """
    Decompress_d : round(q / 2^d · y)  for each coefficient y.

    Approximate inverse of compress.
    """
    two_d = 1 << d
    coeffs = []
    for c in poly.coeffs:
        decompressed = ((Q * c) + (two_d // 2)) // two_d
        coeffs.append(decompressed % Q)
    return Polynomial(coeffs)


# ══════════════════════════════════════════════════════════════════════════════
# Sampling routines  (FIPS 203 Algorithms 8 & 9)
# ══════════════════════════════════════════════════════════════════════════════

def sample_ntt(xof_bytes: bytes) -> Polynomial:
    """
    SampleNTT : Parse a byte stream into a polynomial in NTT domain
    via rejection sampling  (FIPS 203 Algorithm 8).

    Reads 3 bytes at a time, extracting two 12-bit candidates.
    Keeps candidates < q until 256 coefficients are collected.
    """
    coeffs: List[int] = []
    i = 0
    while len(coeffs) < N:
        b0 = xof_bytes[i]
        b1 = xof_bytes[i + 1]
        b2 = xof_bytes[i + 2]
        i += 3

        d1 = b0 + 256 * (b1 % 16)          # lower 12 bits
        d2 = (b1 >> 4) + 16 * b2            # upper 12 bits

        if d1 < Q:
            coeffs.append(d1)
        if d2 < Q and len(coeffs) < N:
            coeffs.append(d2)

    return Polynomial(coeffs)


def sample_poly_cbd(prf_bytes: bytes, eta: int) -> Polynomial:
    """
    SamplePolyCBD_η : Centered Binomial Distribution sampling.
    (FIPS 203 Algorithm 9)

    Each coefficient is (sum of η random bits) − (sum of η random bits),
    giving values in [-η, η].

    Input: 64·η bytes of pseudorandom data.
    Output: Polynomial with coefficients in [0, q)  (negative values wrapped mod q).
    """
    # Convert to a flat bit array
    bits = []
    for byte_val in prf_bytes:
        for bit_idx in range(8):
            bits.append((byte_val >> bit_idx) & 1)

    coeffs = []
    for i in range(N):
        a = sum(bits[2 * i * eta + j] for j in range(eta))
        b = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        coeffs.append((a - b) % Q)

    return Polynomial(coeffs)


# ══════════════════════════════════════════════════════════════════════════════
# Vector encode / decode helpers
# ══════════════════════════════════════════════════════════════════════════════

def encode_poly_vector(vec: List[Polynomial], d: int) -> bytes:
    """Encode a vector of polynomials, concatenating their byte encodings."""
    return b"".join(byte_encode(p, d) for p in vec)


def decode_poly_vector(data: bytes, k: int, d: int) -> List[Polynomial]:
    """Decode k polynomials from concatenated byte data, each with d-bit coefficients."""
    chunk = 32 * d
    return [byte_decode(data[i * chunk:(i + 1) * chunk], d) for i in range(k)]
