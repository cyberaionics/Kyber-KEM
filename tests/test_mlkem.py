"""Tests for ML-KEM key encapsulation mechanism."""

import os
import pytest
from kyber.params import KYBER_512, KYBER_768, KYBER_1024
from kyber.mlkem import KeyGen, Encaps, Decaps


class TestMLKEM:
    """End-to-end KEM tests: keygen → encaps → decaps."""

    def _kem_roundtrip(self, params):
        """Full KEM roundtrip: keys must agree on shared secret."""
        ek, dk = KeyGen(params)
        K_enc, c = Encaps(ek, params)
        K_dec = Decaps(dk, c, params)
        return K_enc, K_dec

    def test_roundtrip_512(self):
        K_enc, K_dec = self._kem_roundtrip(KYBER_512)
        assert K_enc == K_dec

    def test_roundtrip_768(self):
        K_enc, K_dec = self._kem_roundtrip(KYBER_768)
        assert K_enc == K_dec

    def test_roundtrip_1024(self):
        K_enc, K_dec = self._kem_roundtrip(KYBER_1024)
        assert K_enc == K_dec

    def test_shared_secret_is_32_bytes(self):
        ek, dk = KeyGen(KYBER_512)
        K, c = Encaps(ek, KYBER_512)
        assert len(K) == 32

    def test_different_keys_different_secrets(self):
        """Two independent sessions should produce different shared secrets."""
        ek, dk = KeyGen(KYBER_512)

        K1, c1 = Encaps(ek, KYBER_512)
        K2, c2 = Encaps(ek, KYBER_512)

        # Overwhelmingly likely to differ (random m)
        assert K1 != K2 or c1 != c2

    def test_implicit_rejection(self):
        """Tampered ciphertext should NOT recover the original shared secret."""
        ek, dk = KeyGen(KYBER_512)
        K_enc, c = Encaps(ek, KYBER_512)

        # Tamper with the ciphertext
        c_tampered = bytearray(c)
        c_tampered[0] ^= 0xFF
        c_tampered = bytes(c_tampered)

        K_dec = Decaps(dk, c_tampered, KYBER_512)

        # Should get a pseudorandom rejection value, not the real key
        assert K_dec != K_enc
        assert len(K_dec) == 32  # Still returns 32 bytes

    def test_key_sizes_512(self):
        ek, dk = KeyGen(KYBER_512)
        assert len(ek) == 384 * 2 + 32       # 800 bytes
        assert len(dk) == 384 * 2 + 800 + 32 + 32  # 1632 bytes
