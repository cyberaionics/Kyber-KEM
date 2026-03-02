"""Tests for K-PKE inner encryption scheme."""

import os
import pytest
from kyber.params import KYBER_512, KYBER_768, KYBER_1024
from kyber.kpke import kpke_keygen, kpke_encrypt, kpke_decrypt


class TestKPKE:
    """K-PKE encrypt → decrypt roundtrip tests."""

    def _roundtrip(self, params):
        """Helper: generate keys, encrypt a random message, decrypt it."""
        d = os.urandom(32)
        ek, dk = kpke_keygen(d, params)

        m = os.urandom(32)
        r = os.urandom(32)

        c = kpke_encrypt(ek, m, r, params)
        m_dec = kpke_decrypt(dk, c, params)
        return m, m_dec

    def test_roundtrip_512(self):
        m, m_dec = self._roundtrip(KYBER_512)
        assert m == m_dec

    def test_roundtrip_768(self):
        m, m_dec = self._roundtrip(KYBER_768)
        assert m == m_dec

    def test_roundtrip_1024(self):
        m, m_dec = self._roundtrip(KYBER_1024)
        assert m == m_dec

    def test_deterministic_encryption(self):
        """Same (ek, m, r) should produce the same ciphertext."""
        d = os.urandom(32)
        ek, dk = kpke_keygen(d, KYBER_512)
        m = os.urandom(32)
        r = os.urandom(32)

        c1 = kpke_encrypt(ek, m, r, KYBER_512)
        c2 = kpke_encrypt(ek, m, r, KYBER_512)
        assert c1 == c2

    def test_different_messages_different_ciphertexts(self):
        d = os.urandom(32)
        ek, dk = kpke_keygen(d, KYBER_512)
        r = os.urandom(32)

        c1 = kpke_encrypt(ek, b"\x00" * 32, r, KYBER_512)
        c2 = kpke_encrypt(ek, b"\xff" * 32, r, KYBER_512)
        assert c1 != c2
